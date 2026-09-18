// Package audit writes one structured record per tool call: who, which server
// type and pod, which tool, redacted arguments, duration and outcome. Records
// never contain tokens; argument values whose key matches a redaction pattern
// are replaced before the record is written.
package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Record is the audit event schema (stable; consumers may index it).
type Record struct {
	Time       time.Time       `json:"time"`
	Kind       string          `json:"kind"` // tool_call | session_create | session_terminate | auth_failure | admin_action
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

// Logger writes records to a sink.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	closer   io.Closer
	redact   []string
	fallback *slog.Logger
}

// New opens the configured sink.
func New(cfg config.Audit, fallback *slog.Logger) (*Logger, error) {
	l := &Logger{fallback: fallback}
	for _, r := range cfg.RedactArguments {
		l.redact = append(l.redact, strings.ToLower(r))
	}
	if len(l.redact) == 0 {
		l.redact = []string{"password", "token", "secret", "authorization", "api_key", "apikey"}
	}
	switch cfg.Sink {
	case "file":
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		l.w, l.closer = f, f
	case "otlp":
		// Emitted as OTel log records by the telemetry package; stdout as well so nothing is lost.
		l.w = os.Stdout
	default:
		l.w = os.Stdout
	}
	return l, nil
}

// Write emits a record.
func (l *Logger) Write(r Record) {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	r.Arguments = l.Redact(r.Arguments)
	b, err := json.Marshal(r)
	if err != nil {
		l.fallback.Error("audit marshal", "err", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

// Redact replaces values of sensitive keys anywhere in a JSON document.
func (l *Logger) Redact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return json.RawMessage(`"[unparseable]"`)
	}
	v = l.redactValue(v)
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	if len(b) > 8192 {
		b = append(b[:8192], []byte(`..."`)...)
	}
	return b
}

func (l *Logger) redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if l.sensitive(k) {
				t[k] = "[REDACTED]"
				continue
			}
			t[k] = l.redactValue(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = l.redactValue(t[i])
		}
		return t
	case string:
		if strings.HasPrefix(strings.ToLower(t), "bearer ") || (len(t) > 40 && strings.Count(t, ".") == 2) {
			return "[REDACTED]"
		}
		return t
	}
	return v
}

func (l *Logger) sensitive(key string) bool {
	k := strings.ToLower(key)
	for _, r := range l.redact {
		if strings.Contains(k, r) {
			return true
		}
	}
	return false
}

// Close releases the sink.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}
