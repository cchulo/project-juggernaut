// Package gateway wires the HTTP surface of juggernaut-gateway: the OAuth
// protected data plane (/mcp, /adapters/{name}/mcp), the read-mostly control
// plane (/adapters, /tools, /sessions, /users), discovery and probes.
//
// It depends only on contracts; the composition root in internal/app decides
// which adapters satisfy them.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/mcpproxy"
)

// Deps are the collaborators the gateway needs, all contracts.
type Deps struct {
	Store       *config.Store
	Identity    contracts.IdentityProvider
	Policy      contracts.AccessPolicy
	Broker      contracts.TokenBroker
	Table       contracts.RoutingTable
	Provisioner contracts.Provisioner
	Log         *slog.Logger
}

// Server is the gateway HTTP server set.
type Server struct {
	Deps
	proxy    *mcpproxy.Proxy
	sessions *Manager
	// Hooks let optional features plug in without touching the core (router, audit, metrics, admin).
	Hooks Hooks
}

// Hooks are optional extension points.
type Hooks struct {
	// RouterHandler serves POST/GET/DELETE /mcp (the aggregator). Nil → 501.
	RouterHandler http.Handler
	// OnRequest is invoked after each forwarded adapter request for audit/metrics.
	OnRequest func(ev RequestEvent)
	// OnAuthFailure feeds the auth-failure metric.
	OnAuthFailure func(reason string)
	// AdminHandler is mounted on the admin listener. Nil → 404.
	AdminHandler http.Handler
	// MetricsHandler is mounted at /metrics on the metrics listener.
	MetricsHandler http.Handler
}

// RequestEvent is the audit record of one forwarded adapter request.
type RequestEvent struct {
	Subject    string
	ServerType string
	PodName    string
	SessionID  string
	Method     string
	Status     int
	Duration   time.Duration
	Err        error
}

// New builds the server.
func New(d Deps) *Server {
	cfg := d.Store.Get().Config
	s := &Server{Deps: d, proxy: mcpproxy.New(cfg.Gateway.MaxBodyBytes)}
	s.sessions = NewManager(d.Store, d.Policy, d.Table, d.Provisioner, d.Broker, d.Log)
	return s
}

// Manager exposes the session manager (a contracts.SessionManager) to other components.
func (s *Server) Manager() *Manager { return s.sessions }

// Router builds the data + control plane mux.
func (s *Server) Router() http.Handler {
	cfg := s.Store.Get().Config
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.RequestID, middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", s.readyz)
	r.Get("/.well-known/oauth-protected-resource", s.prm)

	authn := &Authn{Identity: s.Identity, Log: s.Log, RequiredScope: cfg.Identity.Scopes.MCP, OnFailure: s.Hooks.OnAuthFailure}
	r.Group(func(r chi.Router) {
		r.Use(authn.Wrap)
		// Data plane.
		r.HandleFunc("/mcp", s.routerOr501)
		r.Post("/adapters/{name}/mcp", s.adapterMCP)
		r.Get("/adapters/{name}/mcp", s.adapterMCP)
		r.Delete("/adapters/{name}/mcp", s.adapterMCP)
		// Control plane (read-mostly).
		r.Get("/adapters", s.listAdapters)
		r.Get("/adapters/{name}", s.getAdapter)
		r.Get("/adapters/{name}/status", s.adapterStatus)
		r.Get("/adapters/{name}/logs", s.adapterLogs)
		r.Get("/tools", s.listTools)
		r.Get("/tools/{name}", s.getTool)
		r.Get("/sessions", s.listSessions)
		r.Get("/sessions/{id}", s.getSession)
		r.Delete("/sessions/{id}", s.deleteSession)
		r.Get("/users/{sub}/sessions", s.userSessions)
		r.Delete("/users/{sub}/sessions", s.deleteUserSessions)
	})
	return r
}

func (s *Server) prm(w http.ResponseWriter, _ *http.Request) {
	doc := s.Identity.ProtectedResourceMetadata()
	if doc == nil {
		http.Error(w, "not applicable for this identity provider", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *Server) routerOr501(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.RouterHandler != nil {
		s.Hooks.RouterHandler.ServeHTTP(w, r)
		return
	}
	writeJSONRPCError(w, http.StatusNotImplemented, -32601, "the aggregated /mcp router is not enabled; use /adapters/{name}/mcp")
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if _, _, _, err := s.Table.CountPods(r.Context(), "", ""); err != nil {
		http.Error(w, "routing table unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Run serves all listeners until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	cfg := s.Store.Get().Config
	data := &http.Server{Addr: cfg.Gateway.Listeners.Data.Address, Handler: s.Router(), ReadHeaderTimeout: 15 * time.Second}
	admin := &http.Server{Addr: cfg.Gateway.Listeners.Admin.Address, Handler: s.adminMux(), ReadHeaderTimeout: 15 * time.Second}
	metrics := &http.Server{Addr: cfg.Gateway.Listeners.Metrics.Address, Handler: s.metricsMux(), ReadHeaderTimeout: 15 * time.Second}

	errc := make(chan error, 3)
	serve := func(name string, srv *http.Server, l config.Listener) {
		s.Log.Info("listening", "listener", name, "addr", srv.Addr, "tls", l.TLS != nil)
		var err error
		if l.TLS != nil {
			err = srv.ListenAndServeTLS(l.TLS.CertFile, l.TLS.KeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}
	go serve("data", data, cfg.Gateway.Listeners.Data)
	go serve("admin", admin, cfg.Gateway.Listeners.Admin)
	go serve("metrics", metrics, cfg.Gateway.Listeners.Metrics)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = data.Shutdown(shutdown)
	_ = admin.Shutdown(shutdown)
	_ = metrics.Shutdown(shutdown)
	return nil
}

// adminMux is a separate http.Server: the admin UI is never reachable from the data listener.
func (s *Server) adminMux() http.Handler {
	mux := http.NewServeMux()
	if s.Hooks.AdminHandler != nil {
		mux.Handle("/admin/", s.Hooks.AdminHandler)
		mux.Handle("/admin", s.Hooks.AdminHandler)
	} else {
		mux.HandleFunc("/admin/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "admin UI not enabled (identity.keycloakAdmin is not configured)", http.StatusNotFound)
		})
	}
	return mux
}

func (s *Server) metricsMux() http.Handler {
	mux := http.NewServeMux()
	if s.Hooks.MetricsHandler != nil {
		mux.Handle("/metrics", s.Hooks.MetricsHandler)
	}
	return mux
}
