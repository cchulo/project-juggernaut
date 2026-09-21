package gateway

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// Authn resolves the caller through the IdentityProvider and challenges per the
// MCP authorization spec when the token is missing, invalid or lacks a scope.
type Authn struct {
	Identity      contracts.IdentityProvider
	Log           *slog.Logger
	RequiredScope string
	OnFailure     func(reason string)
}

// Wrap returns the protected handler.
func (a *Authn) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := contracts.RequestInfoFrom(r)
		_, hasBearer := req.Bearer()
		p, err := a.Identity.Resolve(r.Context(), req)
		if err != nil {
			a.Log.Debug("identity rejected", "err", err)
			if !hasBearer {
				a.reject(w, contracts.ChallengeMissing, "", http.StatusUnauthorized, "missing")
				return
			}
			reason := "invalid"
			if !errors.Is(err, contracts.ErrUnauthenticated) {
				reason = "error"
			}
			a.reject(w, contracts.ChallengeInvalidToken, "token validation failed", http.StatusUnauthorized, reason)
			return
		}
		if a.RequiredScope != "" && !p.HasScope(a.RequiredScope) {
			a.reject(w, contracts.ChallengeInsufficientScope, "scope "+a.RequiredScope+" required", http.StatusForbidden, "scope")
			return
		}
		next.ServeHTTP(w, r.WithContext(core.WithPrincipal(r.Context(), p)))
	})
}

func (a *Authn) reject(w http.ResponseWriter, reason contracts.ChallengeReason, desc string, status int, metric string) {
	w.Header().Set("WWW-Authenticate", a.Identity.Challenge(reason, desc, a.RequiredScope))
	w.WriteHeader(status)
	if a.OnFailure != nil {
		a.OnFailure(metric)
	}
}
