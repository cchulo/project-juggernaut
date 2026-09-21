package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/mcpproxy"
)

// adapterMCP is the per-server data plane: POST/GET/DELETE /adapters/{name}/mcp.
func (s *Server) adapterMCP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := core.PrincipalFrom(ctx)
	name := chi.URLParam(r, "name")
	start := time.Now()

	// DELETE ends the MCP session but keeps the pod (the reaper handles the pod).
	if r.Method == http.MethodDelete {
		id := r.Header.Get(mcpproxy.HeaderSessionID)
		ms, err := s.Table.GetSession(ctx, id)
		if err != nil || ms.Subject != p.Subject {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		_ = s.Table.DeleteSession(ctx, id)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Required user secrets are checked before a pod is spawned so a missing
	// credential is a clear error rather than a silent failure inside the server.
	if srvDecl := s.Store.Get().Config.Server(name); srvDecl != nil && srvDecl.UserSecrets != nil {
		if pre, err := s.ResolveUserSecrets(ctx, r.Header, p, srvDecl); err != nil {
			writeJSONRPCError(w, http.StatusUnprocessableEntity, -32001, err.Error())
			return
		} else {
			core.ZeroMap(pre.Plain)
		}
	}
	pod, srv, err := s.sessions.EnsurePod(ctx, p, name)
	if err != nil {
		s.writeEnsureError(w, err)
		return
	}

	// Resolve the gateway session id → upstream session id.
	clientSID := r.Header.Get(mcpproxy.HeaderSessionID)
	var ms *contracts.McpSession
	if clientSID != "" {
		ms, err = s.Table.GetSession(ctx, clientSID)
		if err != nil || ms.Subject != p.Subject || ms.PodName != pod.Name {
			// Expired, foreign, or from a previous pod incarnation: the spec says 404 and
			// the client re-initializes.
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
	}

	up := mcpproxy.Upstream{
		Endpoint:   pod.Endpoint,
		Path:       "/mcp",
		PodToken:   pod.PodToken,
		Subject:    p.Subject,
		ServerType: name,
	}
	if ms != nil {
		up.UpstreamSessionID = ms.UpstreamSessionID
	}
	if err := s.injectUserToken(r, p, srv, &up); err != nil {
		s.Log.Warn("token broker failed", "user", p.Username, "serverType", name, "err", err)
		writeJSONRPCError(w, http.StatusBadGateway, -32000, "could not obtain a downstream token: "+err.Error())
		return
	}
	secrets, err := s.ResolveUserSecrets(ctx, r.Header, p, srv)
	if err != nil {
		writeJSONRPCError(w, http.StatusUnprocessableEntity, -32001, err.Error())
		return
	}
	up.Extra = secrets.Headers(s.Store.Get().Config.Gateway.UserSecrets)
	defer core.ZeroMap(secrets.Plain)

	_, _ = s.Table.InFlight(ctx, pod.Name, +1)
	defer func() { _, _ = s.Table.InFlight(ctx, pod.Name, -1) }()
	_ = s.Table.Touch(ctx, pod.Name, time.Now())

	// On a fresh initialize we mint our own session id and learn the upstream's from the response.
	if ms == nil && r.Method == http.MethodPost {
		ms = &contracts.McpSession{
			ID: core.NewMcpSessionID(), Subject: p.Subject, ServerType: name, PodName: pod.Name,
			ProtocolVersion: r.Header.Get(mcpproxy.HeaderProtocolV), CreatedAt: time.Now(),
		}
		w.Header().Set(mcpproxy.HeaderSessionID, ms.ID)
	}
	res, err := s.proxy.Forward(ctx, w, r, up)
	if ms != nil && res != nil && res.UpstreamSessionID != "" && ms.UpstreamSessionID == "" {
		ms.UpstreamSessionID = res.UpstreamSessionID
		_ = s.Table.PutSession(ctx, ms)
	}
	if s.Hooks.OnRequest != nil {
		ev := RequestEvent{Subject: p.Subject, ServerType: name, PodName: pod.Name, Method: r.Method, Duration: time.Since(start), Err: err}
		if ms != nil {
			ev.SessionID = ms.ID
		}
		if res != nil {
			ev.Status = res.Status
		}
		s.Hooks.OnRequest(ev)
	}
	if err != nil {
		s.Log.Warn("upstream error", "pod", pod.Name, "err", err)
	}
}

// injectUserToken asks the broker for the downstream token according to the server's token mode.
func (s *Server) injectUserToken(r *http.Request, p *core.Principal, srv *config.Server, up *mcpproxy.Upstream) error {
	switch srv.Token.Mode {
	case config.TokenNone:
		return nil
	case config.TokenStatic:
		v, err := srv.Token.StaticRef.Resolve()
		if err != nil {
			return err
		}
		up.UserToken, up.TokenHeader, up.TokenScheme = v, srv.Token.Header, srv.Token.Scheme
		return nil
	}
	tok, err := s.Broker.TokenFor(r.Context(), p, srv, 60*time.Second)
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	up.UserToken = tok.Value
	// env/file modes: the wrapper takes the token from Authorization and never passes it as a header to the child.
	up.TokenHeader = "Authorization"
	up.TokenScheme = "Bearer"
	if srv.Token.Mode == config.TokenHeader {
		up.TokenHeader, up.TokenScheme = srv.Token.Header, srv.Token.Scheme
	}
	return nil
}

func (s *Server) writeEnsureError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnknownType):
		http.Error(w, "unknown adapter", http.StatusNotFound)
	case errors.Is(err, ErrNotGranted):
		http.Error(w, "adapter not granted to caller", http.StatusForbidden)
	case errors.Is(err, ErrCapReached):
		w.Header().Set("Retry-After", "30")
		http.Error(w, "pod cap reached", http.StatusTooManyRequests)
	case errors.Is(err, ErrColdStart):
		w.Header().Set("Retry-After", "10")
		writeJSONRPCError(w, http.StatusServiceUnavailable, -32000, "session pod starting; retry")
	default:
		writeJSONRPCError(w, http.StatusBadGateway, -32000, fmt.Sprintf("session pod unavailable: %v", err))
	}
}

func writeJSONRPCError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": nil,
		"error": map[string]any{"code": code, "message": msg},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
