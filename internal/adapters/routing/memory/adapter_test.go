package memory

import (
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) { contracttest.RoutingTable(t, NewMemory()) }
