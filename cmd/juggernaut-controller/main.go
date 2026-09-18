// Command juggernaut-controller reconciles juggernaut.yaml into ServerType
// objects and Session objects into isolated session pods, and runs the idle reaper.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/controller"
	"github.com/cchulo/project-juggernaut/internal/netpol"
	"github.com/cchulo/project-juggernaut/internal/session"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_CONFIG", "/etc/juggernaut/juggernaut.yaml"), "path to juggernaut.yaml")
	wrapperImage := flag.String("wrapper-image", envOr("JUGGERNAUT_WRAPPER_IMAGE", ""), "image providing /juggernaut-wrapper for server images that lack it")
	metricsAddr := flag.String("metrics-bind-address", ":9091", "metrics listener")
	probeAddr := flag.String("health-probe-bind-address", ":8081", "probe listener")
	leaderElect := flag.Bool("leader-elect", false, "enable leader election")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log.Info("juggernaut-controller starting", "version", version.Version)

	if err := run(ctrl.SetupSignalHandler(), log, *cfgPath, *wrapperImage, *metricsAddr, *probeAddr, *leaderElect); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, cfgPath, wrapperImage, metricsAddr, probeAddr string, leaderElect bool) error {
	store, err := config.NewStore(cfgPath, log)
	if err != nil {
		return err
	}
	cfg := store.Get().Config
	ns := cfg.Network.SessionsNamespace

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := jugv1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "juggernaut-controller.juggernaut.io",
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)

	table, err := redisTable(cfg, log)
	if err != nil {
		return err
	}

	opts := controller.PodOptions{WrapperImage: wrapperImage}
	if cfg.Network.EgressEnforcer == config.EgressProxy && cfg.Network.Proxy != nil {
		opts.EgressProxy = cfg.Network.Proxy.Address
	}
	rec := &controller.SessionReconciler{Client: mgr.GetClient(), Namespace: ns, Options: opts}
	if cfg.Network.EgressEnforcer != config.EgressNone || !cfg.Network.AllowInsecure {
		iso := &controller.Isolation{
			Client:          mgr.GetClient(),
			Options:         netpol.DefaultOptions(cfg.Network),
			Log:             log,
			SystemNamespace: "juggernaut-system",
			CiliumAvailable: ciliumInstalled(mgr),
		}
		rec.Isolation = iso
		if err := mgr.Add(runnable(func(ctx context.Context) error {
			return iso.EnsureNamespaceDefaultDeny(ctx, ns)
		})); err != nil {
			return err
		}
	} else {
		log.Warn("network isolation disabled (egressEnforcer none + allowInsecure); session pods are NOT isolated")
	}
	if err := rec.SetupWithManager(mgr); err != nil {
		return err
	}

	syncer := &controller.ConfigSyncer{Client: mgr.GetClient(), Namespace: ns, Log: log}
	store.OnReload(func(l *config.Loaded) {
		if err := syncer.Sync(context.Background(), l); err != nil {
			log.Error("servertype sync failed", "err", err)
		}
	})
	if err := mgr.Add(runnable(func(ctx context.Context) error {
		// Initial sync once the cache is warm, then keep watching the file.
		if err := syncer.Sync(ctx, store.Get()); err != nil {
			log.Error("initial servertype sync failed", "err", err)
		}
		return store.Watch(ctx)
	})); err != nil {
		return err
	}
	reaper := &controller.Reaper{Client: mgr.GetClient(), Table: table, Namespace: ns, Interval: 30 * time.Second, Log: log}
	if err := mgr.Add(runnable(reaper.Run)); err != nil {
		return err
	}
	return mgr.Start(ctx)
}

func redisTable(cfg *config.Config, log *slog.Logger) (session.Table, error) {
	if cfg.Gateway.Redis == nil {
		log.Warn("no redis configured; reaper will treat every pod as idle from creation")
		return session.NewMemory(), nil
	}
	pw, err := cfg.Gateway.Redis.PasswordRef.Resolve()
	if err != nil && cfg.Gateway.Redis.PasswordRef.IsSet() {
		return nil, err
	}
	c := redis.NewClient(&redis.Options{Addr: cfg.Gateway.Redis.Address, Password: pw, DB: cfg.Gateway.Redis.DB})
	return session.NewRedis(c, cfg.Gateway.Redis.KeyPrefix, cfg.Gateway.MaxSessionAge.Or(12*time.Hour), nil), nil
}

// ciliumInstalled reports whether the CiliumNetworkPolicy CRD is served.
func ciliumInstalled(mgr ctrl.Manager) bool {
	gvk := netpol.CiliumNetworkPolicyGVK
	_, err := mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

type runnable func(context.Context) error

func (r runnable) Start(ctx context.Context) error { return r(ctx) }

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
