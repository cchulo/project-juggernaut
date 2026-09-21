package contracts

import (
	"encoding/json"
	"time"
)

// AuditRecord is the audit event schema (stable; consumers may index it).
type AuditRecord struct {
	Time       time.Time       `json:"time"`
	Kind       string          `json:"kind"` // tool_call | adapter_request | session_create | session_terminate | auth_failure | admin_action
	Subject    string          `json:"subject,omitempty"`
	ServerType string          `json:"serverType,omitempty"`
	Pod        string          `json:"pod,omitempty"`
	SessionID  string          `json:"sessionId,omitempty"`
	Tool       string          `json:"tool,omitempty"`
	Upstream   string          `json:"upstreamTool,omitempty"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
	DurationMS int64           `json:"durationMs,omitempty"`
	Outcome    string          `json:"outcome"` // ok | tool_error | error
	Error      string          `json:"error,omitempty"`
	Lazy       bool            `json:"lazy,omitempty"`
	Extra      map[string]any  `json:"extra,omitempty"`
}

// AuditSink receives records. Redaction happens before Write is called, so a
// sink only has to persist.
type AuditSink interface {
	Write(r AuditRecord)
	Close() error
}
