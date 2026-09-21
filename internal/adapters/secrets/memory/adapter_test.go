package memory

import (
	"errors"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	contracttest.UserSecretStore(t, NewStore())
}

func TestIsolationBetweenSubjects(t *testing.T) {
	s := NewStore()
	_ = s.Put(t.Context(), "alice", "jira", &core.SealedEntry{Version: 1, Names: []string{"X"}})
	if _, err := s.Get(t.Context(), "bob", "jira"); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatal("bob must not see alice's entry")
	}
}
