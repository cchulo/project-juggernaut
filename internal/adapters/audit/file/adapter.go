// Package file appends audit records as JSON lines to gateway.audit.file.
package file

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "file"

func init() { registry.Audit.Register(Type, New) }

// Sink appends to a file.
type Sink struct {
	mu sync.Mutex
	f  *os.File
}

// New opens gateway.audit.file (option "path" overrides).
func New(ctx *core.Context) (contracts.AuditSink, error) {
	path := ctx.Options.String("path", ctx.Cfg().Gateway.Audit.File)
	if path == "" {
		return nil, fmt.Errorf("audit sink file requires gateway.audit.file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Sink{f: f}, nil
}

// Write appends one line.
func (s *Sink) Write(r contracts.AuditRecord) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.f.Write(append(b, '\n'))
}

// Close closes the file.
func (s *Sink) Close() error { return s.f.Close() }
