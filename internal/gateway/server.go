// Package gateway wires the HTTP surface of juggernaut-gateway: the OAuth
// protected data plane (/mcp, /adapters/{name}/mcp), the read-mostly control
// plane (/adapters, /tools, /sessions, /users), discovery and probes.
package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/broker"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/mcpproxy"
	"github.com/cchulo/project-juggernaut/internal/runtime"
	"github.com/cchulo/project-juggernaut/internal/session"
)

// Deps are the collaborators the gateway needs.
type Deps struct {
	Store    *config.Store
	Verifier *auth.Verifier
	Broker   broker.Broker
	Table    session.Table
	Backend  runtime.Backend
	Log      *slog.Logger
}

// Server is the gateway HTTP server set.
type Server struct {
	Deps
	proxy    *mcpproxy.Proxy
	sessions *Manager
	// Hooks let later milestones plug in without touching the core (router, audit, metrics).
	Hooks Hooks
}

// Hooks are optional extension points.
type Hooks struct {
	// RouterHandler serves POST/GET/DELETE /mcp (the aggregator). Nil → 501.
	RouterHandler http.Handler
	// OnToolCall is invoked after each forwarded request for audit/metrics.
	OnToolCall func(ev CallEvent)
	// OnAuthFailure feeds the auth-failure metric.
	OnAuthFailure func(reason string)
	// AdminHandler is mounted on the admin listener. Nil → 404.
	AdminHandler http.Handler
	// MetricsHandler is mounted at /metrics on the metrics listener.
	MetricsHandler http.Handler
}

// CallEvent is the audit record of one forwarded request.
type CallEvent struct {
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
	s.sessions = NewManager(d.Store, d.Table, d.Backend, d.Broker, d.Log)
	return s
}

// Manager exposes the session manager for other listeners (admin).
func (s *Server) Manager() *Manager { return s.sessions }

// Router builds the data + control plane mux.
func (s *Server) Router() http.Handler {
	cfg := s.Store.Get().Config
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.RequestID, middleware.Recoverer)
	r.Use(middleware.Timeout(0)) // streams may live for hours; per-route timeouts apply instead

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", s.readyz)
	r.Method(http.MethodGet, auth.PRMPath, auth.PRMHandler(s.Store))

	mcpAuth := &auth.Middleware{Verifier: s.Verifier, Store: s.Store, Log: s.Log,
		RequiredScope: cfg.Identity.Scopes.MCP, OnAuthFailure: s.Hooks.OnAuthFailure}

	r.Group(func(r chi.Router) {
		r.Use(mcpAuth.Wrap)
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

func (s *Server) routerOr501(w http.ResponseWriter, r *http.Request) {
	if s.Hooks.RouterHandler != nil {
		s.Hooks.RouterHandler.ServeHTTP(w, r)
		return
	}
	writeJSONRPCError(w, http.StatusNotImplemented, -32601,
		"the aggregated /mcp router ships in milestone 3; use /adapters/{name}/mcp")
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
			http.Error(w, "admin UI ships in milestone 3", http.StatusNotFound)
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
