// Command juggernaut-gateway is the OAuth-protected MCP gateway.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/admin"
	"github.com/cchulo/project-juggernaut/internal/audit"
	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/broker"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/gateway"
	"github.com/cchulo/project-juggernaut/internal/router"
	"github.com/cchulo/project-juggernaut/internal/runtime"
	"github.com/cchulo/project-juggernaut/internal/runtime/kube"
	"github.com/cchulo/project-juggernaut/internal/runtime/local"
	"github.com/cchulo/project-juggernaut/internal/session"
	"github.com/cchulo/project-juggernaut/internal/telemetry"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_CONFIG", "/etc/juggernaut/juggernaut.yaml"), "path to juggernaut.yaml")
	stateDir := flag.String("state-dir", envOr("JUGGERNAUT_STATE_DIR", "/var/lib/juggernaut"), "state directory for the local runtime")
	logLevel := flag.String("log-level", envOr("JUGGERNAUT_LOG_LEVEL", "info"), "debug|info|warn|error")
	flag.Parse()

	log := newLogger(*logLevel)
	log.Info("juggernaut-gateway starting", "version", version.Version, "config", *cfgPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *cfgPath, *stateDir); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, cfgPath, stateDir string) error {
	store, err := config.NewStore(cfgPath, log)
	if err != nil {
		return err
	}
	cfg := store.Get().Config
	if cfg.Network.EgressEnforcer == config.EgressNone {
		log.Warn("network.egressEnforcer is none: session pods have unrestricted egress. Laptop use only.")
	}

	verifier, err := auth.NewVerifier(ctx, cfg.Identity, nil)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	br, err := broker.New(cfg.Identity, (*config.SecretRef).Resolve)
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}

	var backend runtime.Backend
	var table session.Table = session.NewMemory()
	switch cfg.Gateway.Runtime.Kind {
	case config.RuntimeLocal:
		backend, err = local.New(*cfg.Gateway.Runtime.Local, stateDir, log)
		if err != nil {
			return err
		}
	case config.RuntimeKube:
		backend, table, err = kubeRuntime(ctx, cfg, log)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown runtime kind %q", cfg.Gateway.Runtime.Kind)
	}

	srv := gateway.New(gateway.Deps{
		Store: store, Verifier: verifier, Broker: br, Table: table, Backend: backend, Log: log,
	})
	if err := wireHooks(ctx, srv, cfg, store, verifier, br, table, log); err != nil {
		return err
	}
	go func() {
		if err := store.Watch(ctx); err != nil {
			log.Error("config watch stopped", "err", err)
		}
	}()
	return srv.Run(ctx)
}

// wireHooks attaches the milestone-3 features: router, audit, metrics,
// tracing, introspection and the admin listener.
func wireHooks(ctx context.Context, srv *gateway.Server, cfg *config.Config, store *config.Store,
	verifier *auth.Verifier, br broker.Broker, table session.Table, log *slog.Logger) error {
	metrics := telemetry.New("juggernaut")
	srv.Hooks.MetricsHandler = metrics.Handler()
	srv.Hooks.OnAuthFailure = func(reason string) { metrics.AuthFailures.WithLabelValues(reason).Inc() }

	shutdownTracing, err := telemetry.SetupTracing(ctx, cfg.Gateway.Telemetry, log)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	go func() { <-ctx.Done(); _ = shutdownTracing(context.Background()) }()

	auditLog, err := audit.New(cfg.Gateway.Audit, log)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	outcome := func(isErr bool, err error) string {
		switch {
		case err != nil:
			return "error"
		case isErr:
			return "tool_error"
		}
		return "ok"
	}
	srv.Hooks.OnToolCall = func(ev gateway.CallEvent) {
		o := outcome(ev.Status >= 400, ev.Err)
		metrics.ToolCalls.WithLabelValues(ev.ServerType, o).Inc()
		metrics.ToolCallSeconds.WithLabelValues(ev.ServerType).Observe(ev.Duration.Seconds())
		auditLog.Write(audit.Record{Kind: "adapter_request", Subject: ev.Subject, ServerType: ev.ServerType, Pod: ev.PodName,
			SessionID: ev.SessionID, DurationMS: ev.Duration.Milliseconds(), Outcome: o, Error: errString(ev.Err),
			Extra: map[string]any{"method": ev.Method, "status": ev.Status}})
	}

	if cfg.Identity.Introspection.Enabled {
		srv.Hooks.Introspector = auth.NewIntrospector(cfg.Identity, (*config.SecretRef).Resolve)
	}

	rt := router.New(store, br, srv.Manager(), table, log)
	rt.OnCall = func(ev router.CallEvent) {
		o := outcome(ev.IsError, ev.Err)
		metrics.ToolCalls.WithLabelValues(ev.ServerType, o).Inc()
		metrics.ToolCallSeconds.WithLabelValues(ev.ServerType).Observe(ev.Duration.Seconds())
		auditLog.Write(audit.Record{Kind: "tool_call", Subject: ev.Subject, ServerType: ev.ServerType, Pod: ev.PodName,
			SessionID: ev.SessionID, Tool: ev.Tool, Upstream: ev.Upstream, Arguments: ev.Arguments,
			DurationMS: ev.Duration.Milliseconds(), Outcome: o, Error: errString(ev.Err), Lazy: ev.Lazy})
	}
	srv.Hooks.RouterHandler = rt.Handler()

	if cfg.Identity.KeycloakAdmin != nil {
		dir, err := admin.NewKeycloak(cfg.Identity, (*config.SecretRef).Resolve)
		if err != nil {
			return fmt.Errorf("admin: %w", err)
		}
		adm := &admin.Server{Store: store, Verifier: verifier, Dir: dir, Sessions: srv.Manager(), Log: log}
		adm.OnAction = func(actor, action, target string) {
			auditLog.Write(audit.Record{Kind: "admin_action", Subject: actor, Outcome: "ok", Extra: map[string]any{"action": action, "target": target}})
		}
		srv.Hooks.AdminHandler = adm.Handler()
	} else {
		log.Info("identity.keycloakAdmin not configured; admin UI disabled")
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// kubeRuntime wires the Kubernetes backend and the Redis routing table.
func kubeRuntime(ctx context.Context, cfg *config.Config, log *slog.Logger) (runtime.Backend, session.Table, error) {
	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}
	if err := jugv1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}
	rc, err := ctrl.GetConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("kubeconfig: %w", err)
	}
	cl, err := client.New(rc, client.Options{Scheme: scheme})
	if err != nil {
		return nil, nil, err
	}
	backend, err := kube.New(rc, cl, cfg.Network.SessionsNamespace)
	if err != nil {
		return nil, nil, err
	}

	pw, err := cfg.Gateway.Redis.PasswordRef.Resolve()
	if err != nil && cfg.Gateway.Redis.PasswordRef.IsSet() {
		return nil, nil, err
	}
	rdb := redis.NewClient(&redis.Options{Addr: cfg.Gateway.Redis.Address, Password: pw, DB: cfg.Gateway.Redis.DB})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, nil, fmt.Errorf("redis %s: %w", cfg.Gateway.Redis.Address, err)
	}
	var cipher session.Cipher
	if kek := os.Getenv("JUGGERNAUT_KEK"); kek != "" {
		key, err := base64.StdEncoding.DecodeString(kek)
		if err != nil || len(key) != 32 {
			return nil, nil, fmt.Errorf("JUGGERNAUT_KEK must be base64 of 32 bytes")
		}
		if cipher, err = session.NewAESGCM(key); err != nil {
			return nil, nil, err
		}
	} else {
		log.Warn("JUGGERNAUT_KEK not set: pod tokens are stored in Redis unencrypted")
	}
	table := session.NewRedis(rdb, cfg.Gateway.Redis.KeyPrefix, cfg.Gateway.MaxSessionAge.Or(12*time.Hour), cipher)
	return backend, table, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
