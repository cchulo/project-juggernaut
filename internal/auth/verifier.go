package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Verifier validates JWT access tokens against the configured issuer's JWKS.
// It is pluggable across IdPs: anything that publishes OIDC discovery works.
type Verifier struct {
	mu       sync.RWMutex
	cfg      config.Identity
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// NewVerifier performs OIDC discovery (or uses jwksURL directly) and returns a verifier.
func NewVerifier(ctx context.Context, cfg config.Identity, client *http.Client) (*Verifier, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	v := &Verifier{cfg: cfg, client: client}
	if err := v.init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) init(ctx context.Context) error {
	ctx = oidc.ClientContext(ctx, v.client)
	oc := &oidc.Config{
		ClientID: v.cfg.Audience,
		// Some IdPs (Keycloak with the audience mapper) put the audience in
		// "aud"; the resource indicator may also arrive there. Audience is
		// checked below so we can accept either the audience or the gateway URL.
		SkipClientIDCheck: true,
	}
	var ks oidc.KeySet
	if v.cfg.JWKSURL != "" {
		ks = oidc.NewRemoteKeySet(ctx, v.cfg.JWKSURL)
	} else {
		p, err := oidc.NewProvider(ctx, v.cfg.Issuer)
		if err != nil {
			return fmt.Errorf("oidc discovery for %s: %w", v.cfg.Issuer, err)
		}
		v.mu.Lock()
		v.verifier = p.VerifierContext(ctx, oc)
		v.mu.Unlock()
		return nil
	}
	v.mu.Lock()
	v.verifier = oidc.NewVerifier(v.cfg.Issuer, ks, oc)
	v.mu.Unlock()
	return nil
}

// ErrInvalidToken is returned for any signature, issuer, audience, expiry or scope failure.
var ErrInvalidToken = errors.New("invalid token")

// Verify validates a raw bearer token and extracts the principal.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Principal, error) {
	v.mu.RLock()
	ver := v.verifier
	v.mu.RUnlock()
	tok, err := ver.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !containsAudience(tok.Audience, v.cfg.Audience) {
		return nil, fmt.Errorf("%w: audience %v does not include %q", ErrInvalidToken, tok.Audience, v.cfg.Audience)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrInvalidToken, err)
	}
	sum := sha256.Sum256([]byte(raw))
	p := &Principal{
		Subject:   tok.Subject,
		Issuer:    tok.Issuer,
		Expiry:    tok.Expiry,
		RawToken:  raw,
		TokenHash: base64.RawURLEncoding.EncodeToString(sum[:16]),
		Username:  stringClaim(claims, v.cfg.UsernameClaim),
		Groups:    stringSliceClaim(claims, v.cfg.GroupsClaim),
		Scopes:    strings.Fields(stringClaim(claims, "scope")),
	}
	// Keycloak nests realm roles; treat them as groups too so role-based mapping works.
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		p.Groups = append(p.Groups, stringSliceClaim(ra, "roles")...)
	}
	for i, g := range p.Groups {
		p.Groups[i] = strings.TrimPrefix(g, "/") // Keycloak group paths are "/name"
	}
	return p, nil
}

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
