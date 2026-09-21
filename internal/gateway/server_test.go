package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	brokernone "github.com/cchulo/project-juggernaut/internal/adapters/broker/none"
	"github.com/cchulo/project-juggernaut/internal/adapters/identity/static"
	"github.com/cchulo/project-juggernaut/internal/adapters/policy/groups"
	"github.com/cchulo/project-juggernaut/internal/adapters/routing/memory"
	secretsmem "github.com/cchulo/project-juggernaut/internal/adapters/secrets/memory"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
	"github.com/cchulo/project-juggernaut/internal/testutil"
)

func newTestServer(t *testing.T) (*httptest.Server, *testutil.FakeProvisioner) {
	t.Helper()
	ctx := contracttest.Context(t, contracttest.LaptopConfig, nil, nil)
	id, _ := static.New(ctx)
	pol, _ := groups.New(ctx)
	br, _ := brokernone.New(ctx)
	prov := testutil.NewFakeProvisioner()
	s := New(Deps{Store: ctx.Config, Identity: id, Policy: pol, Broker: br, Table: memory.NewMemory(), Provisioner: prov,
		SecretStore: secretsmem.NewStore(), Log: slog.Default()})
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return ts, prov
}

func get(t *testing.T, ts *httptest.Server, path, token string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

func TestChallengeAndScope(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := get(t, ts, "/adapters", "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("missing token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp, _ = get(t, ts, "/adapters", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token: %d", resp.StatusCode)
	}
	// ci-token carries only juggernaut:mcp → allowed on the data/control plane.
	resp, _ = get(t, ts, "/adapters", "ci-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ci token: %d", resp.StatusCode)
	}
	// /healthz needs nothing; the PRM is 404 for static identity.
	if resp, _ := get(t, ts, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Fatal("healthz")
	}
	if resp, _ := get(t, ts, "/.well-known/oauth-protected-resource", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("static identity has no PRM, got %d", resp.StatusCode)
	}
}

func TestControlPlaneIsScopedToGrants(t *testing.T) {
	ts, prov := newTestServer(t)
	resp, body := get(t, ts, "/adapters", "alice-token")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"name":"jira"`) || strings.Contains(body, `"name":"github"`) {
		t.Fatalf("alice (engineering) sees jira only: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, ts, "/adapters/github", "alice-token"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ungranted adapter must be 404, got %d", resp.StatusCode)
	}
	resp, body = get(t, ts, "/tools", "alice-token")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "jira__search_issues") || strings.Contains(body, "jira__create") {
		t.Fatalf("tool exposure on /tools: %s", body)
	}
	// Admin-only endpoints.
	if resp, _ := get(t, ts, "/users/bob/sessions", "alice-token"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin reading another user's sessions must be 403, got %d", resp.StatusCode)
	}
	// Sessions of the caller only, after a pod exists.
	prov.ReadyAfter = 0
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/adapters/jira/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer alice-token")
	req.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req)
	resp2.Body.Close() // upstream is a dead endpoint; we only care that a pod was ensured
	resp, body = get(t, ts, "/sessions", "alice-token")
	var views []map[string]any
	_ = json.Unmarshal([]byte(body), &views)
	if resp.StatusCode != http.StatusOK || len(views) != 1 || views[0]["adapter"] != "jira" {
		t.Fatalf("sessions: %d %s", resp.StatusCode, body)
	}
	if resp, body := get(t, ts, "/sessions", "ci-token"); resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Fatalf("another subject must see no sessions: %s", body)
	}
	if resp, _ := get(t, ts, "/adapters/jira/logs", "alice-token"); resp.StatusCode != http.StatusOK {
		t.Fatalf("own logs: %d", resp.StatusCode)
	}
	if resp, _ := get(t, ts, "/adapters/jira/logs?user=alice", "ci-token"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other user's logs without admin must be 403, got %d", resp.StatusCode)
	}
}

func TestMeSecretsAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	// jira does not declare userSecrets → 404.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/me/secrets/jira", strings.NewReader(`{"version":1,"salt":"AA==","wrappedDek":"AA==","nonce":"AA==","ciphertext":"AA==","names":["X"]}`))
	req.Header.Set("Authorization", "Bearer alice-token")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("put for adapter without userSecrets: %d", resp.StatusCode)
	}
	if resp, body := get(t, ts, "/me/secrets", "alice-token"); resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Fatalf("empty list: %d %s", resp.StatusCode, body)
	}
}
