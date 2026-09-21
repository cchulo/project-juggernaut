// Package static is identity.type static: identity.tokens maps bearer strings
// to principals. Tokens never expire and cannot be revoked except by editing
// the file. Tests and demos only, never production.
package static

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/cchulo/project-juggernaut/internal/adapters/identity/claims"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "static"

// Issuer is recorded on principals so logs show where they came from.
const Issuer = "static"

func init() { registry.Identity.Register(Type, New) }

// Adapter matches bearer tokens against the configured map.
type Adapter struct{ ctx *core.Context }

// New builds the adapter and warns about the mode.
func New(ctx *core.Context) (contracts.IdentityProvider, error) {
	ctx.Log.Warn("identity.type is static: tokens come from the config file and never expire; tests and demos only")
	return &Adapter{ctx: ctx}, nil
}

// Resolve looks the bearer up in identity.tokens with a constant-time compare.
func (a *Adapter) Resolve(_ context.Context, req contracts.RequestInfo) (*core.Principal, error) {
	tok, ok := req.Bearer()
	if !ok {
		return nil, fmt.Errorf("%w: missing bearer token", contracts.ErrUnauthenticated)
	}
	cfg := a.ctx.Cfg()
	for candidate, seed := range cfg.Identity.Tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(tok)) == 1 {
			return claims.FromSeed(cfg, seed, Issuer), nil
		}
	}
	return nil, fmt.Errorf("%w: unknown bearer token", contracts.ErrUnauthenticated)
}

// Challenge is a bare Bearer.
func (a *Adapter) Challenge(contracts.ChallengeReason, string, string) string { return "Bearer" }

// ProtectedResourceMetadata is absent: there is no authorization server.
func (a *Adapter) ProtectedResourceMetadata() *contracts.ProtectedResourceMetadata { return nil }
