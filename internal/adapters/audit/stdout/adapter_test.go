package stdout

import (
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	s, _ := New(nil)
	contracttest.AuditSink(t, s)
}
