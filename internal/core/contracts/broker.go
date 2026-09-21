package contracts

import (
	"context"
	"errors"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// Token is a downstream per-user token and its expiry.
type Token struct {
	Value  string
	Expiry time.Time
	Type   string // "Bearer"
}

// ErrNoToken is returned when a server needs a user token but the broker cannot mint one.
var ErrNoToken = errors.New("no token broker configured")

// TokenBroker mints the per-user token a session pod receives for one server
// type. The client's own access token is never forwarded; the reference
// adapter is RFC 8693 token exchange.
type TokenBroker interface {
	// TokenFor returns a token for the server type with at least minRemaining
	// validity, minting one if needed. nil, nil means the server takes no user token.
	TokenFor(ctx context.Context, p *core.Principal, s *config.Server, minRemaining time.Duration) (*Token, error)
	// Revoke drops cached tokens for a subject.
	Revoke(ctx context.Context, subject string) error
}
