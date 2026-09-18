package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Middleware validates the bearer token on every data-plane and control-plane
// request and challenges per the MCP authorization spec when it is missing or invalid.
type Middleware struct {
	Verifier *Verifier
	Store    *config.Store
	Log      *slog.Logger
	// RequiredScope, when non-empty, must be present in the token (e.g. juggernaut:mcp).
	RequiredScope string
	// OnAuthFailure is called for metrics; may be nil.
	OnAuthFailure func(reason string)
	// Introspector, when set, detects revocation before expiry.
	Introspector *Introspector
}

// Wrap returns the protected handler.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := m.Store.Get().Config
		raw, ok := bearer(r)
		if !ok {
			m.challenge(w, cfg, "", "")
			m.fail("missing")
			return
		}
		p, err := m.Verifier.Verify(r.Context(), raw)
		if err != nil {
			m.Log.Debug("token rejected", "err", err)
			m.challenge(w, cfg, "invalid_token", "token validation failed")
			m.fail("invalid")
			return
		}
		if m.Introspector != nil {
			active, ierr := m.Introspector.Active(r.Context(), p)
			if ierr != nil {
				m.Log.Warn("introspection failed; accepting token until expiry", "err", ierr)
			}
			if !active {
				m.challenge(w, cfg, "invalid_token", "token revoked")
				m.fail("revoked")
				return
			}
		}
		if m.RequiredScope != "" && !p.HasScope(m.RequiredScope) {
			m.challenge(w, cfg, "insufficient_scope", "scope "+m.RequiredScope+" required")
			w.WriteHeader(http.StatusForbidden)
			m.fail("scope")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

func (m *Middleware) fail(reason string) {
	if m.OnAuthFailure != nil {
		m.OnAuthFailure(reason)
	}
}

// challenge writes the WWW-Authenticate header. For insufficient_scope the
// caller sets 403 afterwards; every other case is 401.
func (m *Middleware) challenge(w http.ResponseWriter, cfg *config.Config, errCode, desc string) {
	parts := []string{fmt.Sprintf(`resource_metadata=%q`, PRMURL(cfg))}
	if errCode != "" {
		parts = append(parts, fmt.Sprintf(`error=%q`, errCode))
	}
	if desc != "" {
		parts = append(parts, fmt.Sprintf(`error_description=%q`, desc))
	}
	if m.RequiredScope != "" {
		parts = append(parts, fmt.Sprintf(`scope=%q`, m.RequiredScope))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
	if errCode != "insufficient_scope" {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}
