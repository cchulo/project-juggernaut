package session

import (
	"context"
	"errors"
	"time"
)

// Phase is the lifecycle state of a session pod (docs/DESIGN.md §4).
type Phase string

const (
	PhasePending     Phase = "Pending"
	PhaseStarting    Phase = "Starting"
	PhaseReady       Phase = "Ready"
	PhaseIdle        Phase = "Idle"
	PhaseTerminating Phase = "Terminating"
	PhaseFailed      Phase = "Failed"
	PhaseGone        Phase = "Gone"
)

// Pod is the routing-table view of a session pod.
type Pod struct {
	Key       PodKey
	Name      string
	Endpoint  string // http://ip:port (wrapper data port)
	Phase     Phase
	CreatedAt time.Time
	// ConfigHash is the config version the pod was rendered from.
	ConfigHash string
	// PodToken is the shared secret the gateway presents to the wrapper. Held
	// in memory only; never serialized to logs or the API.
	PodToken string `json:"-"`
}

// McpSession is one client session bound to exactly one pod.
type McpSession struct {
	ID                string
	Subject           string
	ServerType        string // empty for aggregated /mcp sessions
	PodName           string
	UpstreamSessionID string
	ClientName        string
	ProtocolVersion   string
	Lazy              bool
	CreatedAt         time.Time
}

// ErrNotFound is returned for unknown ids.
var ErrNotFound = errors.New("not found")

// Table is the routing table. The memory implementation serves milestone 0 and
// fronts Redis from milestone 1 on.
type Table interface {
	GetPod(ctx context.Context, key PodKey) (*Pod, error)
	PutPod(ctx context.Context, p *Pod) error
	DeletePod(ctx context.Context, key PodKey) error
	ListPods(ctx context.Context, subject string) ([]*Pod, error)
	CountPods(ctx context.Context, subject, serverType string) (perUser int, perType int, total int, err error)

	GetSession(ctx context.Context, id string) (*McpSession, error)
	PutSession(ctx context.Context, s *McpSession) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsForPod(ctx context.Context, podName string) error

	Touch(ctx context.Context, podName string, at time.Time) error
	LastActive(ctx context.Context, podName string) (time.Time, error)
	InFlight(ctx context.Context, podName string, delta int) (int, error)
}
