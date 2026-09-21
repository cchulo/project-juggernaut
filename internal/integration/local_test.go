// Package integration runs the real binaries together: the gateway in-process
// (static identity, local provisioner in process mode), the juggernaut-wrapper
// binary, and a real stdio MCP server, driven through the MCP SDK client.
// No Docker, Kubernetes or identity provider is needed. Docker and cluster
// variants live behind build tags (see docker_test.go).
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	_ "github.com/cchulo/project-juggernaut/internal/adapters/all"
	"github.com/cchulo/project-juggernaut/internal/app"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/testutil"
)

type stack struct {
	url     string
	gateway *app.Gateway
	cancel  context.CancelFunc
}

func startStack(t *testing.T) *stack {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test builds binaries; skipped with -short")
	}
	wrapper := testutil.BuildBinary(t, "./cmd/juggernaut-wrapper")
	server := testutil.BuildBinary(t, "./internal/testutil/stdioserver")
	dataPort, adminPort, metricsPort := testutil.FreePort(t), testutil.FreePort(t), testutil.FreePort(t)
	state := t.TempDir()
	if d := os.Getenv("JUGGERNAUT_TEST_STATE"); d != "" {
		state = d
	}
	cfg := fmt.Sprintf(`
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity:
  type: static
  tokens:
    alice-token: { subject: alice, groups: [engineering], scopes: [juggernaut:mcp] }
    bob-token:   { subject: bob,   groups: [support],     scopes: [juggernaut:mcp] }
    cursor-token: { subject: carol, groups: [engineering, lazy], scopes: [juggernaut:mcp] }
  broker: { mode: none }
gateway:
  publicURL: http://127.0.0.1:%d
  listeners:
    data:    { address: "127.0.0.1:%d" }
    admin:   { address: "127.0.0.1:%d" }
    metrics: { address: "127.0.0.1:%d" }
  runtime:
    kind: local
    local: { mode: process, wrapperBinary: %q, portRange: "%d-%d" }
  coldStartBudget: 30s
  tools: { lazyForGroups: [lazy] }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - name: echo
    image: local/stdioserver:test
    transport: stdio
    command: [%q]
    token: { mode: none }
    userSecrets:
      sources: [header]
      items:
        - { name: TEST_API_TOKEN, env: TEST_API_TOKEN, required: true }
    tools:
      expose: { mode: deny, names: [secret_tool] }
      rename: { echo: say }
authorization:
  groups:
    - { name: engineering, serverTypes: [echo] }
    - { name: support, serverTypes: [] }
    - { name: lazy, serverTypes: [echo] }
`, dataPort, dataPort, adminPort, metricsPort, wrapper, dataPort+1000, dataPort+1100, server)
	// support has no server types: fix the empty list the schema rejects by granting nothing via a dummy.
	cfg = strings.Replace(cfg, "- { name: support, serverTypes: [] }", "", 1)
	path := filepath.Join(state, "juggernaut.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JUGGERNAUT_STATE_DIR", state)
	store, err := config.NewStore(path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	level := slog.LevelWarn
	if os.Getenv("JUGGERNAUT_TEST_DEBUG") != "" {
		level = slog.LevelDebug
		t.Logf("state dir: %s", state)
	}
	gw, err := app.GatewayFromConfig(ctx, store, core.EnvSecrets{}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { _ = gw.Run(ctx) }()
	s := &stack{url: fmt.Sprintf("http://127.0.0.1:%d", dataPort), gateway: gw, cancel: cancel}
	testutil.WaitFor(t, 10*time.Second, func() bool {
		resp, err := http.Get(s.url + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	}, "gateway readiness")
	t.Cleanup(func() {
		// Release pods (kills wrapper processes) before stopping the gateway.
		_ = gw.Server.Manager().ReleaseAll(context.Background(), "alice")
		_ = gw.Server.Manager().ReleaseAll(context.Background(), "carol")
		cancel()
		_ = gw.Close()
	})
	return s
}

// headerTransport adds fixed headers to every request the SDK client makes.
type headerTransport struct{ h http.Header }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, vv := range h.h {
		r.Header[k] = vv
	}
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, url string, headers map[string]string) *mcp.ClientSession {
	t.Helper()
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "integration-test", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: headerTransport{h}}}, nil)
	if err != nil {
		t.Fatalf("connect %s: %v", url, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func text(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestPerAdapterEndpointEndToEnd(t *testing.T) {
	s := startStack(t)
	// Unauthenticated: 401 with a Bearer challenge.
	resp, err := http.Post(s.url+"/adapters/echo/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("unauthenticated: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	// Missing required user secret: rejected before any pod is spawned.
	req, _ := http.NewRequest(http.MethodPost, s.url+"/adapters/echo/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer alice-token")
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	body, _ := readAll(resp)
	if resp.StatusCode != 422 || !strings.Contains(body, "TEST_API_TOKEN") {
		t.Fatalf("missing secret must be 422 naming it: %d %s", resp.StatusCode, body)
	}
	if views, _ := s.gateway.Server.Manager().SessionsFor(context.Background(), "alice"); len(views) != 0 {
		t.Fatal("no pod may be spawned before required secrets are present")
	}

	// Real MCP session through the wrapper to the stdio server, secret injected into the child.
	cs := connect(t, s.url+"/adapters/echo/mcp", map[string]string{"Authorization": "Bearer alice-token", "X-Juggernaut-Secret-TEST_API_TOKEN": "alice-secret"})
	tools, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	if !names["echo"] || !names["env"] {
		t.Fatalf("tools via wrapper: %v", names)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "env", Arguments: map[string]any{"names": []string{"TEST_API_TOKEN"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := text(res); got != "TEST_API_TOKEN=alice-secret" {
		t.Fatalf("secret must reach the child environment: %q", got)
	}
	res, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "whoenv"})
	if strings.Contains(text(res), "JUGGERNAUT_") {
		t.Fatalf("wrapper environment must not leak into the child: %s", text(res))
	}

	// Session pod is visible on the control plane, and only to its owner.
	views, _ := s.gateway.Server.Manager().SessionsFor(context.Background(), "alice")
	if len(views) != 1 || views[0].Adapter != "echo" || views[0].Phase != "Ready" {
		t.Fatalf("sessions: %+v", views)
	}
	if views, _ := s.gateway.Server.Manager().SessionsFor(context.Background(), "bob"); len(views) != 0 {
		t.Fatal("bob must see no sessions")
	}
	// Bob is not granted echo.
	req, _ = http.NewRequest(http.MethodPost, s.url+"/adapters/echo/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer bob-token")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("ungranted adapter must be 403, got %d", resp.StatusCode)
	}
	// Reusing alice's gateway session id as bob: 404, never routed.
	req, _ = http.NewRequest(http.MethodPost, s.url+"/adapters/echo/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer bob-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", cs.ID())
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 && resp.StatusCode != 404 {
		t.Fatalf("foreign session id must not be routed: %d", resp.StatusCode)
	}
}

func TestRouterEagerLazyAndWhoami(t *testing.T) {
	s := startStack(t)
	eager := connect(t, s.url+"/mcp", map[string]string{"Authorization": "Bearer alice-token", "X-Juggernaut-Secret-TEST_API_TOKEN": "a"})
	tools, err := eager.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	if !names["whoami"] || !names["echo__say"] || !names["echo__env"] || names["echo__secret_tool"] || names["echo__echo"] {
		t.Fatalf("eager tool surface (rename, deny): %v", names)
	}
	res, err := eager.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo__say", Arguments: map[string]any{"text": "hello"}})
	if err != nil || text(res) != "hello" {
		t.Fatalf("routed call: %q %v", text(res), err)
	}
	res, _ = eager.CallTool(context.Background(), &mcp.CallToolParams{Name: "whoami"})
	var who map[string]any
	_ = json.Unmarshal([]byte(text(res)), &who)
	if who["subject"] != "alice" || who["lazyTools"] != false {
		t.Fatalf("whoami: %s", text(res))
	}

	lazy := connect(t, s.url+"/mcp", map[string]string{"Authorization": "Bearer cursor-token", "X-Juggernaut-Secret-TEST_API_TOKEN": "c"})
	tools, _ = lazy.ListTools(context.Background(), &mcp.ListToolsParams{})
	names = map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	if !names["search_tools"] || !names["describe_tool"] || !names["execute"] || names["echo__say"] {
		t.Fatalf("lazy tool surface: %v", names)
	}
	res, err = lazy.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_tools", Arguments: map[string]any{"query": "say"}})
	if err != nil || !strings.Contains(text(res), "echo__say") || strings.Contains(text(res), "secret_tool") {
		t.Fatalf("search_tools: %q %v", text(res), err)
	}
	res, err = lazy.CallTool(context.Background(), &mcp.CallToolParams{Name: "execute", Arguments: map[string]any{"name": "echo__say", "arguments": map[string]any{"text": "via-execute"}}})
	if err != nil || text(res) != "via-execute" {
		t.Fatalf("execute: %q %v", text(res), err)
	}
	res, _ = lazy.CallTool(context.Background(), &mcp.CallToolParams{Name: "execute", Arguments: map[string]any{"name": "echo__secret_tool"}})
	if !res.IsError {
		t.Fatal("execute must refuse a hidden tool")
	}
	// Two users, two pods.
	a, _ := s.gateway.Server.Manager().SessionsFor(context.Background(), "alice")
	c, _ := s.gateway.Server.Manager().SessionsFor(context.Background(), "carol")
	if len(a) != 1 || len(c) != 1 || a[0].PodName == c[0].PodName {
		t.Fatalf("one pod per user: %+v %+v", a, c)
	}
}

func readAll(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String(), nil
		}
	}
}
