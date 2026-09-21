// Package none is identity.type none: one person on their own machine. Every
// request is the configured `identity.principal`.
//
// The adapter refuses anything that is not a loopback request unless the
// process runs on a trusted network ($JUGGERNAUT_TRUSTED_NETWORK=1, set by the
// compose file where the peer is the Docker bridge; never set it by hand on a
// port other machines can reach). identity.allowRemote is the explicit LAN
// option: every request, loopback included, must then carry the bearer named
// by identity.staticTokenEnv (default JUGGERNAUT_TOKEN); an empty secret is a
// 401, not an open door.
//
// There is no authorization server, so the protected-resource metadata is
// absent (404) and the challenge is a bare "Bearer".
package none

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/adapters/identity/claims"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "none"

// TrustedNetworkEnv is set by the provisioner on the gateway workload.
const TrustedNetworkEnv = "JUGGERNAUT_TRUSTED_NETWORK"

func init() { registry.Identity.Register(Type, New) }

// Adapter resolves every request to the fixed principal.
type Adapter struct{ ctx *core.Context }

// New builds the adapter and warns about the mode.
func New(ctx *core.Context) (contracts.IdentityProvider, error) {
	ctx.Log.Warn("identity.type is none: every request is the configured principal; loopback only unless allowRemote")
	return &Adapter{ctx: ctx}, nil
}

// Resolve applies the loopback / trusted-network / static-token rules.
func (a *Adapter) Resolve(_ context.Context, req contracts.RequestInfo) (*core.Principal, error) {
	cfg := a.ctx.Cfg()
	id := cfg.Identity
	if id.AllowRemote {
		expected, _ := a.ctx.Secrets.Env(id.StaticTokenEnv)
		if expected == "" {
			return nil, fmt.Errorf("%w: identity.allowRemote is set but %s is empty", contracts.ErrUnauthenticated, id.StaticTokenEnv)
		}
		got, _ := req.Bearer()
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			return nil, fmt.Errorf("%w: missing or invalid bearer token", contracts.ErrUnauthenticated)
		}
	} else if !IsLoopback(req.RemoteAddr) && !a.trustedNetwork() {
		return nil, fmt.Errorf("%w: identity.type none accepts loopback requests only (set identity.allowRemote to change that)", contracts.ErrUnauthenticated)
	}
	return claims.FromSeed(cfg, *id.Principal, ""), nil
}

func (a *Adapter) trustedNetwork() bool {
	v, _ := a.ctx.Secrets.Env(TrustedNetworkEnv)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// IsLoopback reports whether a host:port remote address is local.
func IsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Challenge is a bare Bearer: there is nothing to discover.
func (a *Adapter) Challenge(contracts.ChallengeReason, string, string) string { return "Bearer" }

// ProtectedResourceMetadata is absent in this mode.
func (a *Adapter) ProtectedResourceMetadata() *contracts.ProtectedResourceMetadata { return nil }
