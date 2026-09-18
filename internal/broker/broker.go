// Package broker mints the per-user downstream token a session pod receives.
// The reference implementation is RFC 8693 token exchange; alternatives plug in
// behind the Broker interface. The client's own access token is never forwarded.
package broker

import (
	"context"
	"errors"
	"time"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/config"
)

// Token is a downstream token and its expiry.
type Token struct {
	Value  string
	Expiry time.Time
	// Type is "Bearer" for exchanged tokens.
	Type string
}

// ErrNoToken is returned by the none broker when a server needs a user token.
var ErrNoToken = errors.New("no token broker configured")

// Broker exchanges a validated principal for a token scoped to one server type.
type Broker interface {
	// TokenFor returns a token for the server type, minting one if the cache
	// has none with at least minRemaining validity left.
	TokenFor(ctx context.Context, p *auth.Principal, s *config.Server, minRemaining time.Duration) (*Token, error)
	// Revoke drops every cached token for a subject (revocation / disable).
	Revoke(ctx context.Context, subject string) error
}

// New picks the broker from configuration.
func New(cfg config.Identity, secretResolver func(*config.SecretRef) (string, error)) (Broker, error) {
	switch cfg.Broker.Mode {
	case config.BrokerExchange:
		return NewExchange(cfg, secretResolver)
	case config.BrokerRefreshToken:
		return &RefreshToken{}, nil
	default:
		return None{}, nil
	}
}

// None is the broker for deployments where servers take no user token.
type None struct{}

// TokenFor always fails for token modes that need a user token.
func (None) TokenFor(_ context.Context, _ *auth.Principal, s *config.Server, _ time.Duration) (*Token, error) {
	if s.Token.Mode == config.TokenNone || s.Token.Mode == config.TokenStatic {
		return nil, nil
	}
	return nil, ErrNoToken
}

// Revoke is a no-op.
func (None) Revoke(context.Context, string) error { return nil }

// RefreshToken is the plugin point for IdPs without token exchange (e.g. Dex):
// the gateway would hold per-user refresh tokens obtained through its own
// consent flow. Deliberately not implemented in the reference design (see
// docs/DESIGN.md §3).
type RefreshToken struct{}

// TokenFor is not implemented.
func (*RefreshToken) TokenFor(context.Context, *auth.Principal, *config.Server, time.Duration) (*Token, error) {
	return nil, errors.New("refresh-token broker: not implemented")
}

// Revoke is not implemented.
func (*RefreshToken) Revoke(context.Context, string) error { return nil }
