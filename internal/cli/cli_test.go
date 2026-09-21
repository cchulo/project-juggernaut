package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// fakeGateway implements /me/secrets and /adapters/{name}/session-key in memory.
type fakeGateway struct {
	entries map[string]*core.SealedEntry
	podKey  *core.PodKeyPair
	seen    http.Header
}

func newFakeGateway(t *testing.T) (*httptest.Server, *fakeGateway) {
	t.Helper()
	kp, _ := core.NewPodKeyPair()
	fg := &fakeGateway{entries: map[string]*core.SealedEntry{}, podKey: kp}
	mux := http.NewServeMux()
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer tok" }
	mux.HandleFunc("GET /me/secrets", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(401)
			return
		}
		var out []SecretEntry
		for a, e := range fg.entries {
			out = append(out, SecretEntry{Adapter: a, Entry: e})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("PUT /me/secrets/{adapter}", func(w http.ResponseWriter, r *http.Request) {
		var e core.SealedEntry
		_ = json.NewDecoder(r.Body).Decode(&e)
		fg.entries[r.PathValue("adapter")] = &e
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /adapters/{name}/session-key", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": base64.RawURLEncoding.EncodeToString(kp.Public[:]), "pod": "atlassian-1"})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) { fg.seen = r.Header.Clone(); w.WriteHeader(200) })
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, fg
}

func TestVaultInitSetRotate(t *testing.T) {
	t.Setenv("JUGGERNAUT_HOME", t.TempDir())
	v, err := InitVault("pass1", true)
	if err != nil || v.Key == "" {
		t.Fatalf("init: %v", err)
	}
	if _, err := InitVault("pass1", true); err == nil {
		t.Fatal("second init must refuse")
	}
	loaded, _ := LoadVault()
	key, err := loaded.UserKey("")
	if err != nil {
		t.Fatal(err)
	}
	ts, fg := newFakeGateway(t)
	g := &Gateway{URL: ts.URL, Token: "tok"}
	if err := SetSecrets(t.Context(), g, loaded, key, "alice", "atlassian", map[string]string{"JIRA_API_TOKEN": "a"}); err != nil {
		t.Fatal(err)
	}
	if err := SetSecrets(t.Context(), g, loaded, key, "alice", "atlassian", map[string]string{"JIRA_USERNAME": "u"}); err != nil {
		t.Fatal(err)
	}
	e := fg.entries["atlassian"]
	if len(e.Names) != 2 || strings.Contains(string(e.Ciphertext), "JIRA") {
		t.Fatalf("merged, sealed entry: %+v", e)
	}
	vals, err := core.OpenEntry(key, "alice", "atlassian", e)
	if err != nil || vals["JIRA_API_TOKEN"] != "a" || vals["JIRA_USERNAME"] != "u" {
		t.Fatalf("open merged: %v %v", vals, err)
	}
	if err := Rotate(t.Context(), g, loaded, key, "alice", "pass2", true); err != nil {
		t.Fatal(err)
	}
	if _, err := core.OpenEntry(key, "alice", "atlassian", fg.entries["atlassian"]); err == nil {
		t.Fatal("old key must not open rotated entries")
	}
	rotated, _ := LoadVault()
	newKey, _ := rotated.UserKey("")
	if _, err := core.OpenEntry(newKey, "alice", "atlassian", fg.entries["atlassian"]); err != nil {
		t.Fatalf("new key must open rotated entries: %v", err)
	}
}

func TestCompanionSealsToPodKey(t *testing.T) {
	t.Setenv("JUGGERNAUT_HOME", t.TempDir())
	v, _ := InitVault("p", true)
	key, _ := v.UserKey("")
	ts, fg := newFakeGateway(t)
	g := &Gateway{URL: ts.URL, Token: "tok"}
	if err := SetSecrets(t.Context(), g, v, key, "alice", "atlassian", map[string]string{"JIRA_API_TOKEN": "secret-a"}); err != nil {
		t.Fatal(err)
	}
	comp := NewCompanion(g, "alice", key, "X-Juggernaut-Sealed-Secrets-", nil)
	if err := comp.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(comp)
	defer local.Close()
	req, _ := http.NewRequest(http.MethodPost, local.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer attacker-supplied")
	req.Header.Set("X-Juggernaut-Secret-JIRA_API_TOKEN", "attacker-supplied")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if fg.seen.Get("Authorization") != "Bearer tok" || fg.seen.Get("X-Juggernaut-Secret-JIRA_API_TOKEN") != "" {
		t.Fatalf("companion must own credentials headers: %v", fg.seen)
	}
	blob := fg.seen.Get("X-Juggernaut-Sealed-Secrets-atlassian")
	if blob == "" || strings.Contains(blob, "secret-a") {
		t.Fatalf("sealed blob missing or plaintext: %q", blob)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(blob)
	vals, err := fg.podKey.OpenFromClient(raw)
	if err != nil || vals["JIRA_API_TOKEN"] != "secret-a" {
		t.Fatalf("pod must open the blob: %v %v", vals, err)
	}
}
