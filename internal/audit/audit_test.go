package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

type capture struct{ last contracts.AuditRecord }

func (c *capture) Write(r contracts.AuditRecord) { c.last = r }
func (c *capture) Close() error                  { return nil }

func TestRedact(t *testing.T) {
	sink := &capture{}
	l := New(config.Audit{}, sink)
	in := json.RawMessage(`{"issue":"JIRA-1","api_token":"abc","nested":{"Authorization":"Bearer x"},"list":["Bearer y","ok"]}`)
	l.Write(Record{Kind: "tool_call", Arguments: in})
	out := string(sink.last.Arguments)
	if strings.Contains(out, "abc") || strings.Contains(out, "Bearer x") || strings.Contains(out, "Bearer y") {
		t.Fatalf("secrets leaked: %s", out)
	}
	if !strings.Contains(out, "JIRA-1") || !strings.Contains(out, `"ok"`) {
		t.Fatalf("non-secret values must survive: %s", out)
	}
	if sink.last.Time.IsZero() {
		t.Fatal("time must be stamped")
	}
}
