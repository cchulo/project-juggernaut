package local

import (
	"log/slog"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	b, err := NewBackend(config.LocalRuntime{Mode: "process", WrapperBinary: "juggernaut-wrapper", Network: "juggernaut", PortRange: "39000-39010"}, t.TempDir(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	contracttest.Provisioner(t, b)
}
