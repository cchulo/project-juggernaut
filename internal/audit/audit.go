// Package audit is the redaction layer between the gateway and an AuditSink:
// every record passes through Logger.Write, which strips sensitive argument
// values before the sink ever sees them. Sinks (stdout, file) are adapters.
package audit

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// Record is the audit event schema.
type Record = contracts.AuditRecord

// Logger redacts and forwards to a sink.
type Logger struct {
	sink   contracts.AuditSink
	redact []string
}

// New wraps a sink with the configured redaction keys.
func New(cfg config.Audit, sink contracts.AuditSink) *Logger {
	l := &Logger{sink: sink}
	for _, r := range cfg.RedactArguments {
		l.redact = append(l.redact, strings.ToLower(r))
	}
	if len(l.redact) == 0 {
		l.redact = []string{"password", "token", "secret", "authorization", "api_key", "apikey"}
	}
	return l
}

// Write redacts and emits a record.
func (l *Logger) Write(r Record) {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	r.Arguments = l.Redact(r.Arguments)
	l.sink.Write(r)
}

// Close releases the sink.
func (l *Logger) Close() error { return l.sink.Close() }

// Redact replaces values of sensitive keys anywhere in a JSON document, and
// any string that looks like a bearer token or JWT.
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
