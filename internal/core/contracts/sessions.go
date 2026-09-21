package contracts

import (
	"context"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// SessionView is the API shape of a session pod, shared by the control plane and the admin listener.
type SessionView struct {
	ID           string `json:"id"`
	Adapter      string `json:"adapter"`
	User         string `json:"user"`
	Phase        string `json:"phase"`
	PodName      string `json:"podName"`
	CreatedAt    string `json:"createdAt"`
	LastActiveAt string `json:"lastActiveAt,omitempty"`
	InFlight     int    `json:"inFlight"`
}

// SessionManager owns the (user, server type) → pod mapping: it is the gateway's
// core use case, implemented once and consumed by the data plane, the router
// and the admin listener through this interface.
type SessionManager interface {
	// EnsurePod returns a Ready pod for (principal, server type), holding for up
	// to the cold-start budget when it has to be created.
	EnsurePod(ctx context.Context, p *core.Principal, serverType string) (*Pod, *config.Server, error)
	// Release terminates one pod and purges its sessions.
	Release(ctx context.Context, key core.PodKey) error
	// ReleaseAll terminates every pod of a subject (revocation / admin disable).
	ReleaseAll(ctx context.Context, subject string) error
	// SessionsFor lists a subject's pods.
	SessionsFor(ctx context.Context, subject string) ([]SessionView, error)
}
