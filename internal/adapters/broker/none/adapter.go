// Package none is the token broker for deployments where no server takes a
// per-user token (token modes none and static only).
package none

import (
	"context"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "none"

func init() { registry.Broker.Register(Type, New) }

// Adapter never mints tokens.
type Adapter struct{}

// New builds the adapter.
func New(*core.Context) (contracts.TokenBroker, error) { return Adapter{}, nil }

// TokenFor fails for token modes that need a user token.
func (Adapter) TokenFor(_ context.Context, _ *core.Principal, s *config.Server, _ time.Duration) (*contracts.Token, error) {
	if s.Token.Mode == config.TokenNone || s.Token.Mode == config.TokenStatic {
		return nil, nil
	}
	return nil, contracts.ErrNoToken
}

// Revoke is a no-op.
func (Adapter) Revoke(context.Context, string) error { return nil }
