package audit

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
)

func TestRedact(t *testing.T) {
	l, _ := New(config.Audit{Sink: "stdout"}, slog.Default())
	in := json.RawMessage(`{"issue":"JIRA-1","api_token":"abc","nested":{"Authorization":"Bearer x"},"list":["Bearer y","ok"]}`)
	out := string(l.Redact(in))
	if strings.Contains(out, "abc") || strings.Contains(out, "Bearer x") || strings.Contains(out, "Bearer y") {
		t.Fatalf("secrets leaked: %s", out)
	}
	if !strings.Contains(out, "JIRA-1") || !strings.Contains(out, `"ok"`) {
		t.Fatalf("non-secret values must survive: %s", out)
	}
}
