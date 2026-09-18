package wrapper

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Header names shared with the gateway (mirrors internal/mcpproxy).
const (
	HeaderPodToken = "X-Juggernaut-Pod-Token"
	HeaderSubject  = "X-Juggernaut-Subject"
)

// Server is the wrapper's HTTP surface: a Streamable HTTP MCP server on the
// data port that proxies to the child, and readiness/health on a second port.
type Server struct {
	cfg      *Config
	log      *slog.Logger
	child    *Child
	redactor *Redactor
	podToken []byte

	httpMode *httpMode

	mu    sync.RWMutex
	tools []*mcp.Tool
	ready bool
}

// NewServer loads the pod token and prepares the proxy server.
func NewServer(cfg *Config, log *slog.Logger) (*Server, error) {
	tok, err := os.ReadFile(cfg.PodTokenFile)
	if err != nil {
		return nil, fmt.Errorf("pod token: %w", err)
	}
	tok = []byte(strings.TrimSpace(string(tok)))
	if len(tok) < 16 {
		return nil, fmt.Errorf("pod token too short")
	}
	r := NewRedactor(cfg.LogRedaction)
	r.Add(string(tok))
	s := &Server{cfg: cfg, log: log, redactor: r, child: NewChild(cfg, log, r), podToken: tok}
	if cfg.Transport != "stdio" {
		hm, err := newHTTPMode(cfg, log, r)
		if err != nil {
			return nil, err
		}
		s.httpMode = hm
	}
	return s, nil
}

// Run serves until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	data := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.ListenPort),
		Handler:           s.requirePodToken(s.mcpHandler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	probes := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.ReadinessPort),
		Handler:           s.probeMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 2)
	go func() { errc <- data.ListenAndServe() }()
	go func() { errc <- probes.ListenAndServe() }()
	s.setReady(true)
	s.log.Info("wrapper listening", "data", data.Addr, "probes", probes.Addr, "server", s.cfg.ServerName, "tokenMode", s.cfg.Token.Mode)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = data.Shutdown(shutdown)
	_ = probes.Shutdown(shutdown)
	s.child.Close()
	if s.httpMode != nil {
		s.httpMode.stop()
	}
	return nil
}

func (s *Server) setReady(v bool) { s.mu.Lock(); s.ready = v; s.mu.Unlock() }

func (s *Server) probeMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		ready := s.ready
		s.mu.RUnlock()
		state := map[string]any{"ready": ready, "child": "not-started"}
		if s.child.Running() || (s.httpMode != nil && s.httpMode.running()) {
			state["child"] = "running"
		}
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.child.Healthy() {
			http.Error(w, "child restart budget exhausted", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// requirePodToken rejects anything that is not the gateway.
func (s *Server) requirePodToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get(HeaderPodToken))
		if len(got) != len(s.podToken) || subtle.ConstantTimeCompare(got, s.podToken) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mcpHandler serves Streamable HTTP. For stdio servers the SDK server proxies
// tools/resources/prompts to the child; for HTTP servers the wrapper reverse
// proxies to the local port (milestone 0 only supports stdio; HTTP is TODO).
func (s *Server) mcpHandler() http.Handler {
	if s.httpMode != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := s.httpMode.ensureStarted(r.Context(), ""); err != nil {
				s.log.Error("http child", "err", err)
				http.Error(w, "upstream server not available", http.StatusBadGateway)
				return
			}
			s.httpMode.proxy.ServeHTTP(w, r)
		})
	}
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.serverFor(r)
	}, &mcp.StreamableHTTPOptions{
		Logger:                     s.log,
		DisableLocalhostProtection: true, // the gateway connects by pod IP with its own Host header
		MaxRequestBodyBytes:        4 << 20,
	})
}

// serverFor builds an MCP server whose handlers forward to the child. Each HTTP
// session gets its own *mcp.Server (cheap) but they share the single child.
func (s *Server) serverFor(r *http.Request) *mcp.Server {
	token, exp := s.userTokenFrom(r)
	srv := mcp.NewServer(&mcp.Implementation{Name: "juggernaut/" + s.cfg.ServerName, Version: "0.1"}, &mcp.ServerOptions{
		Logger: s.log,
	})
	ctx := r.Context()
	sess, err := s.child.Session(context.WithoutCancel(ctx), token, exp)
	if err != nil {
		s.log.Error("child unavailable", "err", err)
		return srv // initialize succeeds with no tools; tools/list is empty
	}
	s.mirror(ctx, srv, sess)
	return srv
}

// userTokenFrom extracts the per-user token the gateway injected (env/file modes).
func (s *Server) userTokenFrom(r *http.Request) (string, time.Time) {
	if s.cfg.Token.Mode != "env" && s.cfg.Token.Mode != "file" {
		return "", time.Time{}
	}
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), time.Time{}
	}
	return "", time.Time{}
}

// mirror registers the child's tools, resources and prompts on srv, forwarding calls.
func (s *Server) mirror(ctx context.Context, srv *mcp.Server, sess *mcp.ClientSession) {
	if tools, err := sess.ListTools(ctx, &mcp.ListToolsParams{}); err == nil {
		for _, t := range tools.Tools {
			t := t
			srv.AddTool(t, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				s.child.Begin()
				defer s.child.End()
				return sess.CallTool(ctx, &mcp.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments, Meta: req.Params.Meta})
			})
		}
	} else {
		s.log.Warn("tools/list failed", "err", err)
	}
	if res, err := sess.ListResources(ctx, &mcp.ListResourcesParams{}); err == nil {
		for _, r := range res.Resources {
			r := r
			srv.AddResource(r, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return sess.ReadResource(ctx, &mcp.ReadResourceParams{URI: req.Params.URI})
			})
		}
	}
	if pr, err := sess.ListPrompts(ctx, &mcp.ListPromptsParams{}); err == nil {
		for _, p := range pr.Prompts {
			p := p
			srv.AddPrompt(p, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return sess.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: req.Params.Arguments})
			})
		}
	}
}
