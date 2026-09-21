//go:build integration

package integration

import (
	"os/exec"
	"testing"
)

// TestDockerProvisioner runs only with `go test -tags integration` and a
// working docker daemon plus the images from `make images`. It is the
// environment-dependent counterpart of local_test.go.
func TestDockerProvisioner(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker not available")
	}
	t.Skip("TODO: exercise runtime.local mode docker with ghcr.io/cchulo/example-stdio-server:dev once images are built locally")
}
