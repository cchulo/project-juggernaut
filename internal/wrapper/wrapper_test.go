package wrapper

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

func TestRedactor(t *testing.T) {
	r := NewRedactor(true)
	r.Add("s3cret-value")
	line := r.Scrub("token=s3cret-value Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789")
	if strings.Contains(line, "s3cret-value") || strings.Contains(line, "abcdefghijklmnop") {
		t.Fatalf("redaction failed: %s", line)
	}
	var buf bytes.Buffer
	r.Pipe(strings.NewReader("child says s3cret-value\n"), slog.New(slog.NewTextHandler(&buf, nil)))
	if strings.Contains(buf.String(), "s3cret-value") || !strings.Contains(buf.String(), "[REDACTED]") {
		t.Fatalf("pipe redaction: %s", buf.String())
	}
	off := NewRedactor(false)
	off.Add("x")
	if off.Scrub("x") != "x" {
		t.Fatal("disabled redactor must pass through")
	}
}

func TestFingerprintAndChildEnv(t *testing.T) {
	a := fingerprint(map[string]string{"A": "1", "B": "2"})
	if a != fingerprint(map[string]string{"B": "2", "A": "1"}) || a == fingerprint(map[string]string{"A": "1", "B": "3"}) || fingerprint(nil) != "" {
		t.Fatal("fingerprint must be order-independent and value-sensitive")
	}
	cfg := &Config{Env: map[string]string{"JIRA_URL": "https://x"}, Token: config.Token{Mode: "env", Env: "JIRA_OAUTH_TOKEN"}}
	env := childEnv(cfg, "tok")
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "JIRA_OAUTH_TOKEN=tok") || !strings.Contains(joined, "JIRA_URL=https://x") || !strings.Contains(joined, "HOME=/tmp") {
		t.Fatalf("child env: %v", env)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "JUGGERNAUT_") {
			t.Fatalf("wrapper env must not leak into the child: %s", kv)
		}
	}
}

func newWrapper(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "pod-token")
	_ = os.WriteFile(tok, []byte("0123456789abcdef0123456789abcdef"), 0o600)
	cfg := &Config{ServerName: "t", Transport: config.TransportStdio, Command: []string{"/bin/true"}, ListenPort: 0, ReadinessPort: 0,
		PodTokenFile: tok, Token: config.Token{Mode: "none"}, StartupTimeout: time.Second,
		UserSecrets:        []config.UserSecretItem{{Name: "JIRA_API_TOKEN", Env: "JIRA_API_TOKEN"}},
		SecretHeaderPrefix: "X-Juggernaut-Secret-", SealedHeader: "X-Juggernaut-Sealed-Secrets"}
	s, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPodTokenGate(t *testing.T) {
	s := newWrapper(t)
	h := s.requirePodToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for _, tok := range []string{"", "wrong", "0123456789abcdef0123456789abcde"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set(HeaderPodToken, tok)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("token %q must be refused, got %d", tok, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(HeaderPodToken, "0123456789abcdef0123456789abcdef")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("the right token must pass")
	}
}

func TestUserSecretsPlainAndSealed(t *testing.T) {
	s := newWrapper(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("X-Juggernaut-Secret-JIRA_API_TOKEN", "plain")
	req.Header.Set("X-Juggernaut-Secret-UNDECLARED", "nope")
	got, err := s.userSecretsFrom(req.Header)
	if err != nil || got["JIRA_API_TOKEN"] != "plain" || len(got) != 1 {
		t.Fatalf("plain: %v %v", got, err)
	}
	// Sealed to this pod's key wins; sealed to another pod's key is refused.
	rec := httptest.NewRecorder()
	s.sessionKey(rec, req)
	var body struct{ PublicKey string }
	_ = jsonUnmarshal(rec.Body.Bytes(), &body)
	pubRaw, _ := base64.RawURLEncoding.DecodeString(body.PublicKey)
	var pub [32]byte
	copy(pub[:], pubRaw)
	blob, _ := core.SealToPod(&pub, map[string]string{"JIRA_API_TOKEN": "sealed", "OTHER": "dropped"})
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("X-Juggernaut-Sealed-Secrets", base64.RawURLEncoding.EncodeToString(blob))
	got, err = s.userSecretsFrom(req2.Header)
	if err != nil || got["JIRA_API_TOKEN"] != "sealed" || len(got) != 1 {
		t.Fatalf("sealed: %v %v", got, err)
	}
	other, _ := core.NewPodKeyPair()
	blob2, _ := core.SealToPod(other.Public, map[string]string{"JIRA_API_TOKEN": "x"})
	req3 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req3.Header.Set("X-Juggernaut-Sealed-Secrets", base64.RawURLEncoding.EncodeToString(blob2))
	if _, err := s.userSecretsFrom(req3.Header); err == nil {
		t.Fatal("a blob sealed to another pod must be refused")
	}
}

func TestHTTPModeDirectorMapsSecretsAndStripsInternalHeaders(t *testing.T) {
	cfg := &Config{Transport: config.TransportStreamableHTTP, HTTPPort: 8081, HTTPPath: "/mcp",
		Token:              config.Token{Mode: "header", Header: "X-Api-Key", Scheme: ""},
		UserSecrets:        []config.UserSecretItem{{Name: "JIRA_API_TOKEN", Header: "X-Jira-Token"}},
		SecretHeaderPrefix: "X-Juggernaut-Secret-"}
	hm, err := newHTTPMode(cfg, slog.Default(), NewRedactor(true))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://pod:9000/mcp", nil)
	req.Header.Set("Authorization", "Bearer downstream")
	req.Header.Set(HeaderPodToken, "pod")
	req.Header.Set("X-Juggernaut-Secret-JIRA_API_TOKEN", "jt")
	req.Header.Set("X-Juggernaut-Subject", "alice")
	hm.proxy.Director(req)
	if req.URL.Host != "127.0.0.1:8081" || req.URL.Path != "/mcp" {
		t.Fatalf("director target: %s", req.URL)
	}
	if req.Header.Get("X-Api-Key") != "downstream" || req.Header.Get("Authorization") != "" {
		t.Fatalf("token header mapping: %v", req.Header)
	}
	if req.Header.Get("X-Jira-Token") != "jt" {
		t.Fatalf("secret header mapping: %v", req.Header)
	}
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-juggernaut-") {
			t.Fatalf("internal header leaked to the server: %s", k)
		}
	}
}
