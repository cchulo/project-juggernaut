package telemetry

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
)

func TestMetricsExposition(t *testing.T) {
	m := New("juggernaut")
	m.AuthFailures.WithLabelValues("invalid").Inc()
	m.ToolCalls.WithLabelValues("jira", "ok").Add(2)
	m.PodsActive.WithLabelValues("jira", "Ready").Set(3)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{`juggernaut_auth_failures_total{reason="invalid"} 1`, `juggernaut_tool_calls_total{outcome="ok",server_type="jira"} 2`, `juggernaut_pods_active{phase="Ready",server_type="jira"} 3`, "juggernaut_config_reload_errors_total"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestTracingDisabledWithoutEndpoint(t *testing.T) {
	shutdown, err := SetupTracing(context.Background(), config.Telemetry{}, slog.Default())
	if err != nil || shutdown == nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
