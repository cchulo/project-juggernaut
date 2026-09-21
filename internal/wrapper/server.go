package wrapper

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cchulo/project-juggernaut/internal/core"
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
	// podKey is the per-incarnation X25519 key clients seal secrets to (tier B).
	podKey *core.PodKeyPair

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
	kp, err := core.NewPodKeyPair()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, redactor: r, child: NewChild(cfg, log, r), podToken: tok, podKey: kp}
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
	dataMux := http.NewServeMux()
	dataMux.Handle("/mcp", s.mcpHandler())
	dataMux.HandleFunc("/session-key", s.sessionKey)
	data := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.ListenPort),
		Handler:           s.requirePodToken(dataMux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if s.cfg.TLS != nil {
		tc, err := s.serverTLS()
		if err != nil {
			return err
		}
		data.TLSConfig = tc
	}
	probes := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.ReadinessPort),
		Handler:           s.probeMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 2)
	go func() {
		if s.cfg.TLS != nil {
			errc <- data.ListenAndServeTLS("", "")
			return
		}
		errc <- data.ListenAndServe()
	}()
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

// sessionKey publishes the pod's ephemeral public key (tier-B sealing).
func (s *Server) sessionKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"publicKey": base64.RawURLEncoding.EncodeToString(s.podKey.Public[:]),
		"algorithm": "x25519-nacl-box",
	})
}

// userSecretsFrom reads the gateway-forwarded secrets: plaintext items by
// header, then a sealed blob only this pod's key can open.
func (s *Server) userSecretsFrom(h http.Header) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range s.cfg.UserSecrets {
		if v := h.Get(s.cfg.SecretHeaderPrefix + it.Name); v != "" {
			out[it.Name] = v
		}
	}
	if blob := h.Get(s.cfg.SealedHeader); blob != "" {
		raw, err := base64.RawURLEncoding.DecodeString(blob)
		if err != nil {
			return nil, fmt.Errorf("sealed secrets: bad encoding")
		}
		vals, err := s.podKey.OpenFromClient(raw)
		if err != nil {
			return nil, err
		}
		for _, it := range s.cfg.UserSecrets {
			if v, ok := vals[it.Name]; ok {
				out[it.Name] = v
			}
		}
		core.ZeroMap(vals)
	}
	return out, nil
}

// serverTLS builds the mutual-TLS listener config: the pod presents its own
// certificate and accepts only the gateway's SPIFFE identity.
func (s *Server) serverTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("pod certificate: %w", err)
	}
	caPEM, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("client CA: no certificates")
	}
	want := s.cfg.TLS.GatewayURI
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			if len(chains) == 0 || len(chains[0]) == 0 {
				return fmt.Errorf("no verified client chain")
			}
			for _, u := range chains[0][0].URIs {
				if u.String() == want {
					return nil
				}
			}
			return fmt.Errorf("client certificate is not the gateway (%s)", want)
		},
	}, nil
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

// serverFor is the SDK's getServer callback. The SDK invokes it on every
// request (it needs the server's protocol versions before it looks the
// session up), so it must be cheap and must never restart the child: a
// request that already carries a session id gets a bare server, and only a
// session-creating request (initialize) builds the mirrored server. Tool
// handlers resolve the child per call from the call's own headers, so a
// credential rotation restarts the child without invalidating the session.
func (s *Server) serverFor(r *http.Request) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "juggernaut/" + s.cfg.ServerName, Version: "0.1"}, &mcp.ServerOptions{
		Logger: s.log,
	})
	if r.Header.Get("Mcp-Session-Id") != "" {
		return srv
	}
	ctx := r.Context()
	token, exp := s.userTokenFrom(r.Header)
	secrets, err := s.userSecretsFrom(r.Header)
	if err != nil {
		s.log.Error("user secrets", "err", err)
		return srv
	}
	defer core.ZeroMap(secrets)
	sess, err := s.child.Session(context.WithoutCancel(ctx), token, exp, secrets)
	if err != nil {
		s.log.Error("child unavailable", "err", err)
		return srv // initialize succeeds with no tools; tools/list is empty
	}
	s.mirror(ctx, srv, sess)
	return srv
}

// userTokenFrom extracts the per-user token the gateway injected (env/file modes).
func (s *Server) userTokenFrom(h http.Header) (string, time.Time) {
	if s.cfg.Token.Mode != "env" && s.cfg.Token.Mode != "file" {
		return "", time.Time{}
	}
	v := h.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:]), time.Time{}
	}
	return "", time.Time{}
}

// acquire resolves the child session for one forwarded request from that
// request's own headers (token and user secrets), holding it in flight until
// release is called. A rotation observed here restarts the child before the
// call when nothing else is in flight, or at the next idle boundary otherwise.
func (s *Server) acquire(ctx context.Context, h http.Header) (*mcp.ClientSession, func(), error) {
	token, exp := s.userTokenFrom(h)
	secrets, err := s.userSecretsFrom(h)
	if err != nil {
		return nil, nil, err
	}
	defer core.ZeroMap(secrets)
	return s.child.Acquire(context.WithoutCancel(ctx), token, exp, secrets)
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}

// mirror registers the child's tools, resources and prompts on srv. The
// listings come from the child's cache (refreshed per child generation), and
// every handler re-resolves the child at call time.
func (s *Server) mirror(ctx context.Context, srv *mcp.Server, sess *mcp.ClientSession) {
	lists, err := s.child.Lists(ctx, sess)
	if err != nil {
		s.log.Warn("child listing failed", "err", err)
		return
	}
	for _, t := range lists.Tools {
		t := t
		srv.AddTool(t, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cs, release, err := s.acquire(ctx, headerOf(req.Extra))
			if err != nil {
				return errResult(err), nil
			}
			defer release()
			return cs.CallTool(ctx, &mcp.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments, Meta: req.Params.Meta})
		})
	}
	for _, r := range lists.Resources {
		r := r
		srv.AddResource(r, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			cs, release, err := s.acquire(ctx, headerOf(req.Extra))
			if err != nil {
				return nil, err
			}
			defer release()
			return cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: req.Params.URI})
		})
	}
	for _, p := range lists.Prompts {
		p := p
		srv.AddPrompt(p, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			cs, release, err := s.acquire(ctx, headerOf(req.Extra))
			if err != nil {
				return nil, err
			}
			defer release()
			return cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: req.Params.Arguments})
		})
	}
}

// headerOf returns the HTTP headers of the request carrying an MCP call.
func headerOf(extra *mcp.RequestExtra) http.Header {
	if extra == nil || extra.Header == nil {
		return http.Header{}
	}
	return extra.Header
}
