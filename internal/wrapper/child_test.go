package wrapper

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/testutil"
)

// secretHeaderTransport adds the gateway-style secret header to every request.
type secretHeaderTransport struct{ h http.Header }

func (t secretHeaderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, vv := range t.h {
		r.Header[k] = vv
	}
	return http.DefaultTransport.RoundTrip(r)
}

func newStdioWrapper(t *testing.T) *Server {
	t.Helper()
	bin := testutil.BuildBinary(t, "./internal/testutil/stdioserver")
	dir := t.TempDir()
	tok := filepath.Join(dir, "pod-token")
	_ = os.WriteFile(tok, []byte("0123456789abcdef0123456789abcdef"), 0o600)
	cfg := &Config{ServerName: "echo", Transport: config.TransportStdio, Command: []string{bin},
		PodTokenFile: tok, Token: config.Token{Mode: "none"}, StartupTimeout: 10 * time.Second,
		UserSecrets:        []config.UserSecretItem{{Name: "TEST_API_TOKEN", Env: "TEST_API_TOKEN"}},
		SecretHeaderPrefix: "X-Juggernaut-Secret-", SealedHeader: "X-Juggernaut-Sealed-Secrets"}
	s, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.child.Close)
	return s
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	if res.IsError {
		t.Fatalf("%s returned an error: %s", name, sb.String())
	}
	return sb.String()
}

// The MCP SDK asks the handler for a server on every HTTP request. A call that
// carries a rotated secret must restart the child and still be served on the
// same MCP session, and the session set up without any secret must keep
// working after that restart (the bug the end-to-end test first exposed).
func TestChildRestartsOnSecretRotationWithoutBreakingSession(t *testing.T) {
	s := newStdioWrapper(t)
	srv := httptest.NewServer(s.requirePodToken(s.mcpHandler()))
	defer srv.Close()

	hdr := http.Header{}
	hdr.Set(HeaderPodToken, "0123456789abcdef0123456789abcdef")
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: secretHeaderTransport{hdr}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if got := callText(t, cs, "env", map[string]any{"names": []string{"TEST_API_TOKEN"}}); got != "TEST_API_TOKEN=" {
		t.Fatalf("child started without a secret, got %q", got)
	}
	gen1 := s.child.generation

	// Same MCP session, but the next call brings a secret: child restarts.
	hdr.Set("X-Juggernaut-Secret-TEST_API_TOKEN", "tok-1")
	if got := callText(t, cs, "env", map[string]any{"names": []string{"TEST_API_TOKEN"}}); got != "TEST_API_TOKEN=tok-1" {
		t.Fatalf("secret must reach the restarted child, got %q", got)
	}
	if s.child.generation <= gen1 {
		t.Fatalf("expected a restart, generation %d -> %d", gen1, s.child.generation)
	}
	gen2 := s.child.generation

	// Unchanged secret: no restart, and the same value is visible.
	if got := callText(t, cs, "echo", map[string]any{"text": "still here"}); got != "still here" {
		t.Fatalf("echo after restart: %q", got)
	}
	if s.child.generation != gen2 {
		t.Fatalf("unchanged secret must not restart the child (%d -> %d)", gen2, s.child.generation)
	}

	// Rotation again restarts; a rotation-restart is not a crash and must not
	// eat the crash budget.
	hdr.Set("X-Juggernaut-Secret-TEST_API_TOKEN", "tok-2")
	if got := callText(t, cs, "env", map[string]any{"names": []string{"TEST_API_TOKEN"}}); got != "TEST_API_TOKEN=tok-2" {
		t.Fatalf("rotated secret: %q", got)
	}
	if !s.child.Healthy() || len(s.child.restarts) != 0 {
		t.Fatalf("rotation restarts must not count as crashes: restarts=%d", len(s.child.restarts))
	}
}

// Lists are cached per child generation, so session setup does not round-trip
// to the child for every new HTTP session.
func TestChildListsCachedPerGeneration(t *testing.T) {
	s := newStdioWrapper(t)
	ctx := context.Background()
	sess, err := s.child.Session(ctx, "", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := s.child.Lists(ctx, sess)
	if err != nil || len(l1.Tools) == 0 {
		t.Fatalf("lists: %v %+v", err, l1)
	}
	l2, _ := s.child.Lists(ctx, sess)
	if l1 != l2 {
		t.Fatal("same generation must return the cached listing")
	}
	sess2, _, err := s.child.Acquire(ctx, "", time.Time{}, map[string]string{"TEST_API_TOKEN": "x"})
	if err != nil {
		t.Fatal(err)
	}
	l3, err := s.child.Lists(ctx, sess2)
	if err != nil || l3 == l1 {
		t.Fatalf("a new generation must refresh the listing: %v", err)
	}
}
