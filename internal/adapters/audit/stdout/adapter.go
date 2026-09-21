// Package stdout writes audit records as JSON lines to standard output, one per
// line, for the cluster's log pipeline to collect.
package stdout

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "stdout"

func init() {
	registry.Audit.Register(Type, New)
	// "otlp" records are emitted as OTel log records by the telemetry package in a
	// follow-up; until then they go to stdout so nothing is lost.
	registry.Audit.Register("otlp", New)
}

// Sink writes to stdout.
type Sink struct{ mu sync.Mutex }

// New builds the sink.
func New(*core.Context) (contracts.AuditSink, error) { return &Sink{}, nil }

// Write emits one line.
func (s *Sink) Write(r contracts.AuditRecord) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = os.Stdout.Write(append(b, '\n'))
}

// Close is a no-op.
func (s *Sink) Close() error { return nil }
