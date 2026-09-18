// Package auth makes the gateway an OAuth 2.0 protected resource per the MCP
// authorization specification (2025-06-18): it validates bearer tokens issued by
// an external OIDC provider, serves protected-resource metadata, and challenges
// unauthenticated requests with 401 + WWW-Authenticate so clients can drive the
// standard discovery-and-login flow.
package auth

import (
	"context"
	"time"
)

// Principal is the validated identity of a caller.
type Principal struct {
	Subject  string
	Username string
	Groups   []string
	Scopes   []string
	Issuer   string
	Expiry   time.Time
	// RawToken is the validated bearer token. It is needed by the token broker
	// (subject_token for RFC 8693) and must never be logged or forwarded upstream.
	RawToken string
	// TokenHash is a stable, non-reversible identifier for RawToken used as a cache key.
	TokenHash string
}

// HasScope reports whether the token carries the scope.
func (p *Principal) HasScope(s string) bool {
	for _, x := range p.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// InGroup reports group membership.
func (p *Principal) InGroup(g string) bool {
	for _, x := range p.Groups {
		if x == g {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// WithPrincipal stores the principal in the context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PrincipalFrom returns the principal stored by the middleware, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
