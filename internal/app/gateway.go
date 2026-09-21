package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/cchulo/project-juggernaut/internal/admin"
	"github.com/cchulo/project-juggernaut/internal/audit"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/gateway"
	"github.com/cchulo/project-juggernaut/internal/mcpproxy"
	"github.com/cchulo/project-juggernaut/internal/router"
	"github.com/cchulo/project-juggernaut/internal/telemetry"
)

// Gateway is a fully wired gateway and the resources it owns.
type Gateway struct {
	Server *gateway.Server
	Store  *config.Store
	close  []func() error
}

// Close releases adapters that hold resources.
func (g *Gateway) Close() error {
	var first error
	for i := len(g.close) - 1; i >= 0; i-- {
		if err := g.close[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Run starts config watching and the listeners.
func (g *Gateway) Run(ctx context.Context) error {
	go func() {
		if err := g.Store.Watch(ctx); err != nil {
			g.Server.Log.Error("config watch stopped", "err", err)
		}
	}()
	return g.Server.Run(ctx)
}

// GatewayFromConfig builds every adapter the configuration selects and wires
// the gateway. Selectors and their registries:
//
//	identity.type            registry.Identity
//	authorization.type       registry.Policy
//	identity.broker.mode     registry.Broker
//	gateway.runtime.kind     registry.Provision
//	gateway.routing.type     registry.Routing
//	gateway.audit.sink       registry.Audit
//	identity.keycloakAdmin   registry.Directory ("keycloak" when set)
func GatewayFromConfig(ctx context.Context, store *config.Store, secrets core.Secrets, log *slog.Logger) (*Gateway, error) {
	cfg := store.Get().Config
	base := &core.Context{Config: store, Secrets: secrets, Log: log}
	if cfg.Gateway.Runtime.Kind == config.RuntimeKube {
		k, err := NewKubeAccess()
		if err != nil {
			return nil, err
		}
		base.Kube = k
	}
	build := func(kind string, err error) error {
		if err != nil {
			return fmt.Errorf("%s adapter: %w", kind, err)
		}
		return nil
	}

	identity, err := registry.Identity.Build(cfg.Identity.Type, registry.WithOptions(base, cfg.Identity.Options))
	if err := build("identity", err); err != nil {
		return nil, err
	}
	policy, err := registry.Policy.Build(cfg.Authorization.Type, registry.WithOptions(base, cfg.Authorization.Options))
	if err := build("policy", err); err != nil {
		return nil, err
	}
	broker, err := registry.Broker.Build(string(cfg.Identity.Broker.Mode), registry.WithOptions(base, cfg.Identity.Broker.Options))
	if err := build("broker", err); err != nil {
		return nil, err
	}
	provisioner, err := registry.Provision.Build(string(cfg.Gateway.Runtime.Kind), base)
	if err := build("provision", err); err != nil {
		return nil, err
	}
	table, err := registry.Routing.Build(cfg.Gateway.Routing.Type, registry.WithOptions(base, cfg.Gateway.Routing.Options))
	if err := build("routing", err); err != nil {
		return nil, err
	}
	sink, err := registry.Audit.Build(cfg.Gateway.Audit.Sink, registry.WithOptions(base, cfg.Gateway.Audit.Options))
	if err := build("audit", err); err != nil {
		return nil, err
	}
	secretStore, err := registry.Secrets.Build(cfg.Gateway.UserSecrets.Store.Type, registry.WithOptions(base, cfg.Gateway.UserSecrets.Store.Options))
	if err := build("secrets", err); err != nil {
		return nil, err
	}
	var podTLS *mcpproxy.PodTLS
	if cfg.Network.PodAuth == "mtls" {
		m := cfg.Network.MTLS
		podTLS, err = mcpproxy.LoadPodTLS(m.CertFile, m.KeyFile, m.CAFile, m.TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("podAuth mtls: %w", err)
		}
	}

	srv := gateway.New(gateway.Deps{Store: store, Identity: identity, Policy: policy, Broker: broker,
		Table: table, Provisioner: provisioner, SecretStore: secretStore, Log: log, PodTLS: podTLS})
	g := &Gateway{Server: srv, Store: store}
	g.close = append(g.close, sink.Close)

	// Observability.
	metrics := telemetry.New("juggernaut")
	srv.Hooks.MetricsHandler = metrics.Handler()
	srv.Hooks.OnAuthFailure = func(reason string) { metrics.AuthFailures.WithLabelValues(reason).Inc() }
	shutdownTracing, err := telemetry.SetupTracing(ctx, cfg.Gateway.Telemetry, log)
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}
	g.close = append(g.close, func() error { return shutdownTracing(context.Background()) })

	auditLog := audit.New(cfg.Gateway.Audit, sink)
	srv.Hooks.OnRequest = func(ev gateway.RequestEvent) {
		o := outcome(ev.Status >= 400, ev.Err)
		metrics.ToolCalls.WithLabelValues(ev.ServerType, o).Inc()
		metrics.ToolCallSeconds.WithLabelValues(ev.ServerType).Observe(ev.Duration.Seconds())
		auditLog.Write(contracts.AuditRecord{Kind: "adapter_request", Subject: ev.Subject, ServerType: ev.ServerType, Pod: ev.PodName,
			SessionID: ev.SessionID, DurationMS: ev.Duration.Milliseconds(), Outcome: o, Error: errString(ev.Err),
			Extra: map[string]any{"method": ev.Method, "status": ev.Status}})
	}

	// Aggregated /mcp router.
	rt := router.New(store, identity, policy, broker, srv.Manager(), table, log)
	rt.PodTLS = podTLS
	rt.Secrets = func(ctx context.Context, hdr http.Header, p *core.Principal, s *config.Server) (http.Header, func(), error) {
		res, err := srv.ResolveUserSecrets(ctx, hdr, p, s)
		if err != nil {
			return nil, nil, err
		}
		return res.Headers(store.Get().Config.Gateway.UserSecrets), func() { core.ZeroMap(res.Plain) }, nil
	}
	rt.OnCall = func(ev router.CallEvent) {
		o := outcome(ev.IsError, ev.Err)
		metrics.ToolCalls.WithLabelValues(ev.ServerType, o).Inc()
		metrics.ToolCallSeconds.WithLabelValues(ev.ServerType).Observe(ev.Duration.Seconds())
		auditLog.Write(contracts.AuditRecord{Kind: "tool_call", Subject: ev.Subject, ServerType: ev.ServerType, Pod: ev.PodName,
			SessionID: ev.SessionID, Tool: ev.Tool, Upstream: ev.Upstream, Arguments: ev.Arguments,
			DurationMS: ev.Duration.Milliseconds(), Outcome: o, Error: errString(ev.Err), Lazy: ev.Lazy})
	}
	srv.Hooks.RouterHandler = rt.Handler()
	srv.Hooks.OnAdminAction = func(actor, action, target string) {
		auditLog.Write(contracts.AuditRecord{Kind: "admin_action", Subject: actor, Outcome: "ok",
			Extra: map[string]any{"action": action, "target": target}})
	}

	// Admin listener, only when a directory is configured.
	if cfg.Identity.KeycloakAdmin != nil {
		dir, err := registry.Directory.Build("keycloak", base)
		if err := build("directory", err); err != nil {
			return nil, err
		}
		adm := &admin.Server{Store: store, Identity: identity, Dir: dir, Sessions: srv.Manager(), Log: log}
		adm.OnAction = func(actor, action, target string) {
			auditLog.Write(contracts.AuditRecord{Kind: "admin_action", Subject: actor, Outcome: "ok",
				Extra: map[string]any{"action": action, "target": target}})
		}
		srv.Hooks.AdminHandler = adm.Handler()
	} else {
		log.Info("identity.keycloakAdmin not configured; admin UI disabled")
	}
	return g, nil
}

func outcome(isErr bool, err error) string {
	switch {
	case err != nil:
		return "error"
	case isErr:
		return "tool_error"
	}
	return "ok"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
