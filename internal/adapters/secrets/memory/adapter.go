// Package memory is the in-process UserSecretStore: development and tests.
package memory

import (
	"context"
	"sync"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "memory"

func init() { registry.Secrets.Register(Type, New) }

// Store keeps sealed entries in a map.
type Store struct {
	mu sync.RWMutex
	m  map[string]map[string]*core.SealedEntry // subject → adapter → entry
}

// New builds an empty store.
func New(*core.Context) (contracts.UserSecretStore, error) { return NewStore(), nil }

// NewStore builds an empty store.
func NewStore() *Store { return &Store{m: map[string]map[string]*core.SealedEntry{}} }

func (s *Store) Put(_ context.Context, subject, adapter string, e *core.SealedEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[subject] == nil {
		s.m[subject] = map[string]*core.SealedEntry{}
	}
	cp := *e
	s.m[subject][adapter] = &cp
	return nil
}

func (s *Store) Get(_ context.Context, subject, adapter string) (*core.SealedEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[subject][adapter]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	cp := *e
	return &cp, nil
}

func (s *Store) List(_ context.Context, subject string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for a := range s.m[subject] {
		out = append(out, a)
	}
	return out, nil
}

func (s *Store) Delete(_ context.Context, subject, adapter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m[subject], adapter)
	return nil
}

func (s *Store) DeleteAll(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, subject)
	return nil
}

var _ contracts.UserSecretStore = (*Store)(nil)
