// Package runtime abstracts where session pods run. Milestone 0 ships the local
// backend (docker containers or plain processes on the operator's machine);
// milestone 1 adds the Kubernetes backend driven by the controller. This keeps
// cerebro's provisioner contract (ensure / release / touch / endpoint).
package runtime

import (
	"context"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/session"
)

// SpawnSpec is everything a backend needs to start one session pod.
type SpawnSpec struct {
	Key        session.PodKey
	Server     *config.Server
	Network    config.Network
	ConfigHash string
	// PodToken is the per-pod shared secret the wrapper must require.
	PodToken string
}

// Status is a backend's view of a session pod.
type Status struct {
	Name     string
	Phase    session.Phase
	Endpoint string
	Message  string
	Started  time.Time
}

// Backend creates, inspects and destroys session pods.
type Backend interface {
	// Ensure starts the pod if needed and returns immediately with its status.
	Ensure(ctx context.Context, spec SpawnSpec) (*Status, error)
	// Status reports the current phase; ErrNotFound when the pod does not exist.
	Status(ctx context.Context, key session.PodKey) (*Status, error)
	// Release terminates the pod. It is idempotent.
	Release(ctx context.Context, key session.PodKey) error
	// List returns every session pod the backend knows about.
	List(ctx context.Context) ([]Status, error)
	// Logs returns the last tailLines of the wrapper/server logs.
	Logs(ctx context.Context, key session.PodKey, tailLines int) (string, error)
}

// ErrNotFound is returned when a pod does not exist.
var ErrNotFound = session.ErrNotFound
