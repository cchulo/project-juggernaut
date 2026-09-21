package contracts

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// RequestInfo is the slice of an HTTP request identity needs.
type RequestInfo struct {
	Header     http.Header
	Method     string
	Path       string
	RemoteAddr string
}

// RequestInfoFrom extracts the slice from a request.
func RequestInfoFrom(r *http.Request) RequestInfo {
	return RequestInfo{Header: r.Header, Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr}
}

// Bearer returns the bearer token, if any.
func (r RequestInfo) Bearer() (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}

// ErrUnauthenticated is wrapped by every identity failure so the middleware can
// answer 401 uniformly; the wrapped message says why.
var ErrUnauthenticated = errors.New("unauthenticated")

// ChallengeReason selects the OAuth error code in WWW-Authenticate.
type ChallengeReason string

const (
	ChallengeMissing           ChallengeReason = ""
	ChallengeInvalidToken      ChallengeReason = "invalid_token"
	ChallengeInsufficientScope ChallengeReason = "insufficient_scope"
)

// ProtectedResourceMetadata is the RFC 9728 document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// IdentityProvider turns a request into a Principal. The gateway is always the
// OAuth 2.0 resource server; the adapter decides how a request proves who it
// is (a JWT against the issuer's JWKS, introspection, ...).
type IdentityProvider interface {
	// Resolve returns the Principal or an error wrapping ErrUnauthenticated.
	Resolve(ctx context.Context, req RequestInfo) (*core.Principal, error)
	// Challenge returns the WWW-Authenticate value for a 401/403.
	Challenge(reason ChallengeReason, description, requiredScope string) string
	// ProtectedResourceMetadata is served at /.well-known/oauth-protected-resource; nil when not applicable.
	ProtectedResourceMetadata() *ProtectedResourceMetadata
}
