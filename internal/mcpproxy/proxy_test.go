package mcpproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForwardRewritesHeaders(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set(HeaderSessionID, "upstream-123")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	p := New(1<<20, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/adapters/jira/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("Cookie", "a=b")
	req.Header.Set("X-Juggernaut-Secret-EVIL", "injected")
	req.Header.Set("X-Juggernaut-Pod-Token", "spoofed")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(HeaderSessionID, "jg_client")
	res, err := p.Forward(context.Background(), rec, req, Upstream{
		Endpoint: up.URL, Path: "/mcp", PodToken: "pod-secret", Subject: "alice", ServerType: "jira",
		UpstreamSessionID: "up-1", UserToken: "dt", TokenHeader: "Authorization", TokenScheme: "Bearer",
		Extra: http.Header{"X-Juggernaut-Secret-JIRA_API_TOKEN": {"abc"}},
	})
	if err != nil || res.Status != 200 || res.UpstreamSessionID != "upstream-123" {
		t.Fatalf("forward: %+v %v", res, err)
	}
	if seen.Get("Authorization") != "Bearer dt" {
		t.Fatalf("downstream token must replace the client token: %q", seen.Get("Authorization"))
	}
	if seen.Get("Cookie") != "" || seen.Get("X-Juggernaut-Secret-EVIL") != "" {
		t.Fatal("cookies and undeclared client X-Juggernaut headers must be stripped")
	}
	if seen.Get(HeaderPodToken) != "pod-secret" || seen.Get(HeaderSubject) != "alice" || seen.Get(HeaderSessionID) != "up-1" {
		t.Fatalf("pod headers: %v", seen)
	}
	if seen.Get("X-Juggernaut-Secret-JIRA_API_TOKEN") != "abc" || seen.Get("Accept") != "application/json" {
		t.Fatalf("extra and ordinary headers: %v", seen)
	}
	if rec.Header().Get(HeaderSessionID) != "" {
		t.Fatal("the upstream session id must not leak to the client")
	}
}

// The gateway-issued session id reaches the client only when the upstream
// started a session; a stateless call (server/discover) must not leave the
// client holding an id the gateway cannot resolve.
func TestForwardSessionIDOnlyWhenUpstreamStartsOne(t *testing.T) {
	withSession := true
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withSession {
			w.Header().Set(HeaderSessionID, "upstream-123")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer up.Close()
	p := New(1<<20, nil)
	for _, tc := range []struct {
		upstreamSession bool
		want            string
	}{{true, "jg_new"}, {false, ""}} {
		withSession = tc.upstreamSession
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/adapters/jira/mcp", strings.NewReader("{}"))
		res, err := p.Forward(context.Background(), rec, req, Upstream{Endpoint: up.URL, Path: "/mcp", NewSessionID: "jg_new"})
		if err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get(HeaderSessionID); got != tc.want {
			t.Fatalf("upstream session=%v: client sees %q, want %q (res %+v)", tc.upstreamSession, got, tc.want, res)
		}
	}
}

func TestForwardStreamsSSE(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "event: message\ndata: {\"a\":1}\n\n")
		_, _ = io.WriteString(w, "event: message\ndata: {\"a\":2}\n\n")
	}))
	defer up.Close()
	p := New(1<<20, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/adapters/jira/mcp", nil)
	if _, err := p.Forward(context.Background(), rec, req, Upstream{Endpoint: up.URL, Path: "/mcp", PodToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" || strings.Count(rec.Body.String(), "data:") != 2 {
		t.Fatalf("sse passthrough: %q", rec.Body.String())
	}
}
