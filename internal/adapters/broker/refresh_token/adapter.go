// Package refresh_token is the plugin point for IdPs without token exchange
// (e.g. Dex): the gateway would hold per-user refresh tokens obtained through
// its own consent flow and mint short-lived access tokens from them. It is
// deliberately not implemented in the reference design (docs/DESIGN.md §3);
// registering it makes the configuration error explicit rather than silent.
package refresh_token

import (
	"context"
	"errors"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "refresh-token"

func init() { registry.Broker.Register(Type, New) }

// Adapter is a placeholder.
type Adapter struct{}

// New builds the adapter.
func New(*core.Context) (contracts.TokenBroker, error) { return &Adapter{}, nil }

// TokenFor is not implemented.
func (*Adapter) TokenFor(context.Context, *core.Principal, *config.Server, time.Duration) (*contracts.Token, error) {
	return nil, errors.New("refresh-token broker: not implemented")
}

// Revoke is not implemented.
func (*Adapter) Revoke(context.Context, string) error { return nil }
