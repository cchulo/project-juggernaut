package contracts

import (
	"context"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// UserSecretStore keeps users' sealed third-party credentials. It only ever
// sees ciphertext (core.SealedEntry); it cannot open what it stores.
type UserSecretStore interface {
	Put(ctx context.Context, subject, adapter string, e *core.SealedEntry) error
	// Get returns ErrNotFound when the user has no entry for the adapter.
	Get(ctx context.Context, subject, adapter string) (*core.SealedEntry, error)
	// List returns the adapters the user has entries for.
	List(ctx context.Context, subject string) ([]string, error)
	Delete(ctx context.Context, subject, adapter string) error
	DeleteAll(ctx context.Context, subject string) error
}
