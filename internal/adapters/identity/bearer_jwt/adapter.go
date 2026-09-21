// Package bearer_jwt is the identity adapter for OAuth 2.0 / OIDC access tokens
// as JWTs, validated locally against the issuer's JWKS. Any IdP that publishes
// OIDC discovery works (Keycloak, Entra ID, Okta, Dex). It also serves the RFC
// 9728 protected-resource metadata and builds the WWW-Authenticate challenge.
//
// Options: jwks_url (override discovery), skip_audience_check (never in production).
package bearer_jwt

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "bearer_jwt"

func init() { registry.Identity.Register(Type, New) }

// Adapter validates bearer JWTs.
type Adapter struct {
	ctx      *core.Context
	mu       sync.RWMutex
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// New performs OIDC discovery (or uses jwksURL directly).
func New(ctx *core.Context) (contracts.IdentityProvider, error) {
	a := &Adapter{ctx: ctx, client: &http.Client{Timeout: 10 * time.Second}}
	if err := a.init(context.Background()); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Adapter) identity() config.Identity { return a.ctx.Cfg().Identity }

func (a *Adapter) init(ctx context.Context) error {
	id := a.identity()
	ctx = oidc.ClientContext(ctx, a.client)
	oc := &oidc.Config{
		ClientID: id.Audience,
		// Audience is checked in Resolve so either the audience or the resource URL is accepted.
		SkipClientIDCheck: true,
	}
	jwksURL := a.ctx.Options.String("jwks_url", id.JWKSURL)
	var v *oidc.IDTokenVerifier
	if jwksURL != "" {
		v = oidc.NewVerifier(id.Issuer, oidc.NewRemoteKeySet(ctx, jwksURL), oc)
	} else {
		p, err := oidc.NewProvider(ctx, id.Issuer)
		if err != nil {
			return fmt.Errorf("oidc discovery for %s: %w", id.Issuer, err)
		}
		v = p.VerifierContext(ctx, oc)
	}
	a.mu.Lock()
	a.verifier = v
	a.mu.Unlock()
	return nil
}

// Resolve validates the bearer token and extracts the principal.
func (a *Adapter) Resolve(ctx context.Context, req contracts.RequestInfo) (*core.Principal, error) {
	raw, ok := req.Bearer()
	if !ok {
		return nil, fmt.Errorf("%w: no bearer token", contracts.ErrUnauthenticated)
	}
	return a.Verify(ctx, raw)
}

// Verify validates a raw token. Exported for adapters that wrap this one.
func (a *Adapter) Verify(ctx context.Context, raw string) (*core.Principal, error) {
	a.mu.RLock()
	ver := a.verifier
	a.mu.RUnlock()
	id := a.identity()
	tok, err := ver.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", contracts.ErrUnauthenticated, err)
	}
	if !a.ctx.Options.Bool("skip_audience_check", false) && !containsAudience(tok.Audience, id.Audience) {
		return nil, fmt.Errorf("%w: audience %v does not include %q", contracts.ErrUnauthenticated, tok.Audience, id.Audience)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", contracts.ErrUnauthenticated, err)
	}
	sum := sha256.Sum256([]byte(raw))
	p := &core.Principal{
		Subject:   tok.Subject,
		Issuer:    tok.Issuer,
		Expiry:    tok.Expiry,
		RawToken:  raw,
		TokenHash: base64.RawURLEncoding.EncodeToString(sum[:16]),
		Username:  stringClaim(claims, id.UsernameClaim),
		Groups:    stringSliceClaim(claims, id.GroupsClaim),
		Scopes:    strings.Fields(stringClaim(claims, "scope")),
	}
	// Keycloak nests realm roles; treat them as groups so role-based mapping works.
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		p.Groups = append(p.Groups, stringSliceClaim(ra, "roles")...)
	}
	for i, g := range p.Groups {
		p.Groups[i] = strings.TrimPrefix(g, "/") // Keycloak group paths are "/name"
	}
	return p, nil
}

// Challenge builds the WWW-Authenticate value pointing MCP clients at the metadata.
func (a *Adapter) Challenge(reason contracts.ChallengeReason, desc, requiredScope string) string {
	parts := []string{fmt.Sprintf(`resource_metadata=%q`, PRMURL(a.ctx.Cfg()))}
	if reason != contracts.ChallengeMissing {
		parts = append(parts, fmt.Sprintf(`error=%q`, string(reason)))
	}
	if desc != "" {
		parts = append(parts, fmt.Sprintf(`error_description=%q`, desc))
	}
	if requiredScope != "" {
		parts = append(parts, fmt.Sprintf(`scope=%q`, requiredScope))
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// ProtectedResourceMetadata serves the RFC 9728 document.
func (a *Adapter) ProtectedResourceMetadata() *contracts.ProtectedResourceMetadata {
	c := a.ctx.Cfg()
	return &contracts.ProtectedResourceMetadata{
		Resource:               strings.TrimRight(c.Gateway.PublicURL, "/") + "/mcp",
		AuthorizationServers:   []string{c.Identity.Issuer},
		ScopesSupported:        []string{c.Identity.Scopes.MCP, c.Identity.Scopes.Admin},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Juggernaut MCP Gateway",
		ResourceDocumentation:  "https://github.com/cchulo/project-juggernaut",
	}
}

// PRMPath is the well-known path.
const PRMPath = "/.well-known/oauth-protected-resource"

// PRMURL returns the absolute metadata URL.
func PRMURL(c *config.Config) string { return strings.TrimRight(c.Gateway.PublicURL, "/") + PRMPath }

func containsAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

func stringClaim(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func stringSliceClaim(m map[string]any, k string) []string {
	raw, ok := m[k].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
