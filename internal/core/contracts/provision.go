package contracts

import (
	"context"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// SpawnSpec is everything a provisioner needs to start one session pod.
type SpawnSpec struct {
	Key        core.PodKey
	Server     *config.Server
	Network    config.Network
	ConfigHash string
	// PodToken is the per-pod shared secret the wrapper must require.
	PodToken string
}

// PodStatus is a provisioner's view of a session pod.
type PodStatus struct {
	Name     string
	Phase    Phase
	Endpoint string
	Message  string
	Started  time.Time
}

// Provisioner creates, inspects and destroys session pods. It keeps cerebro's
// ensure / release / status / touch shape: the gateway asks for a pod for
// (user, server type) and the provisioner owns naming, placement and cleanup.
type Provisioner interface {
	// Ensure starts the pod if needed and returns immediately with its status.
	Ensure(ctx context.Context, spec SpawnSpec) (*PodStatus, error)
	// Status reports the current phase; ErrNotFound when the pod does not exist.
	Status(ctx context.Context, key core.PodKey) (*PodStatus, error)
	// Release terminates the pod. It is idempotent.
	Release(ctx context.Context, key core.PodKey) error
	// List returns every session pod the provisioner knows about.
	List(ctx context.Context) ([]PodStatus, error)
	// Logs returns the last tailLines of the wrapper/server logs, tokens redacted.
	Logs(ctx context.Context, key core.PodKey, tailLines int) (string, error)
}
