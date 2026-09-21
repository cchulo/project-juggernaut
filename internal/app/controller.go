package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/controller"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// ControllerOptions are the flags of juggernaut-controller.
type ControllerOptions struct {
	WrapperImage string
	MetricsAddr  string
	ProbeAddr    string
	LeaderElect  bool
}

// ControllerFromConfig builds the manager, the reconcilers and the reaper with
// the egress and routing adapters the configuration selects.
func ControllerFromConfig(ctx context.Context, store *config.Store, secrets core.Secrets, log *slog.Logger, o ControllerOptions) (ctrl.Manager, error) {
	cfg := store.Get().Config
	ns := cfg.Network.SessionsNamespace
	scheme, err := Scheme()
	if err != nil {
		return nil, err
	}
	rc := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(rc, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: o.MetricsAddr},
		HealthProbeBindAddress: o.ProbeAddr,
		LeaderElection:         o.LeaderElect,
		LeaderElectionID:       "juggernaut-controller.juggernaut.io",
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
	})
	if err != nil {
		return nil, fmt.Errorf("manager: %w", err)
	}
	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)

	hasKind := func(gvk schema.GroupVersionKind) bool {
		_, err := mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
		return err == nil
	}
	base := &core.Context{Config: store, Secrets: secrets, Log: log, Kube: KubeAccessFrom(rc, mgr.GetClient(), hasKind)}

	// Routing table: the reaper reads activity from the same store the gateway writes.
	var table contracts.RoutingTable
	if cfg.Gateway.Routing.Type == "memory" {
		log.Warn("gateway.routing.type is memory; the reaper cannot see gateway activity and treats every pod as idle from creation")
	}
	table, err = registry.Routing.Build(cfg.Gateway.Routing.Type, registry.WithOptions(base, cfg.Gateway.Routing.Options))
	if err != nil {
		return nil, fmt.Errorf("routing adapter: %w", err)
	}

	// Egress enforcer: none only with allowInsecure (validated by config).
	egress, err := registry.Egress.Build(string(cfg.Network.EgressEnforcer), base)
	if err != nil {
		return nil, fmt.Errorf("egress adapter: %w", err)
	}
	podEnv, disableDNS := egress.PodEnv()
	rec := &controller.SessionReconciler{
		Client: mgr.GetClient(), Namespace: ns, Egress: egress,
		Options: controller.PodOptions{WrapperImage: o.WrapperImage, Env: podEnv, DisableDNS: disableDNS},
	}
	if err := rec.SetupWithManager(mgr); err != nil {
		return nil, err
	}
	if err := mgr.Add(runnable(rec.EnsureNamespaceObjects)); err != nil {
		return nil, err
	}

	syncer := &controller.ConfigSyncer{Client: mgr.GetClient(), Namespace: ns, Log: log}
	store.OnReload(func(l *config.Loaded) {
		if err := syncer.Sync(context.Background(), l); err != nil {
			log.Error("servertype sync failed", "err", err)
		}
	})
	if err := mgr.Add(runnable(func(ctx context.Context) error {
		if err := syncer.Sync(ctx, store.Get()); err != nil {
			log.Error("initial servertype sync failed", "err", err)
		}
		return store.Watch(ctx)
	})); err != nil {
		return nil, err
	}
	reaper := &controller.Reaper{Client: mgr.GetClient(), Table: table, Namespace: ns, Interval: 30 * time.Second, Log: log}
	if err := mgr.Add(runnable(reaper.Run)); err != nil {
		return nil, err
	}
	_ = ctx
	return mgr, nil
}

type runnable func(context.Context) error

func (r runnable) Start(ctx context.Context) error { return r(ctx) }
