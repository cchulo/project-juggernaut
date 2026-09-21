package none

import (
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	b, _ := New(nil)
	contracttest.TokenBroker(t, b, &core.Principal{Subject: "u"})
}
