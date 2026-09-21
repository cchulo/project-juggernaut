package gateway

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	secretsmem "github.com/cchulo/project-juggernaut/internal/adapters/secrets/memory"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

const secretsConfig = `
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity: { type: static, tokens: { t: { subject: alice } }, broker: { mode: none } }
gateway: { publicURL: http://127.0.0.1:8080, runtime: { kind: local } }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - name: atlassian
    image: x/y:1
    transport: stdio
    command: ["/bin/a"]
    token: { mode: none }
    userSecrets:
      sources: [header, store, sealed]
      items:
        - { name: JIRA_API_TOKEN, env: JIRA_API_TOKEN, required: true }
        - { name: JIRA_USERNAME, env: JIRA_USERNAME }
authorization:
  groups: [{ name: everyone, serverTypes: [atlassian] }]
`

func newServer(t *testing.T) (*Server, *config.Server) {
	t.Helper()
	l, err := config.Parse([]byte(secretsConfig))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStoreFrom(l, slog.Default())
	s := &Server{Deps: Deps{Store: store, SecretStore: secretsmem.NewStore(), Log: slog.Default()}}
	return s, l.Config.Server("atlassian")
}

func TestHeaderSource(t *testing.T) {
	s, srv := newServer(t)
	p := &core.Principal{Subject: "alice"}
	h := http.Header{}
	h.Set("X-Juggernaut-Secret-JIRA_API_TOKEN", "abc")
	h.Set("X-Juggernaut-Secret-OTHER", "ignored")
	got, err := s.ResolveUserSecrets(t.Context(), h, p, srv)
	if err != nil || got.Plain["JIRA_API_TOKEN"] != "abc" || len(got.Plain) != 1 {
		t.Fatalf("header source: %+v %v", got, err)
	}
	out := got.Headers(s.Store.Get().Config.Gateway.UserSecrets)
	if out.Get("X-Juggernaut-Secret-JIRA_API_TOKEN") != "abc" || out.Get("X-Juggernaut-Secret-OTHER") != "" {
		t.Fatalf("forwarded headers: %v", out)
	}
}

func TestMissingRequiredIsAnError(t *testing.T) {
	s, srv := newServer(t)
	_, err := s.ResolveUserSecrets(t.Context(), http.Header{}, &core.Principal{Subject: "alice"}, srv)
	var missing *ErrMissingUserSecret
	if !errors.As(err, &missing) || missing.Name != "JIRA_API_TOKEN" {
		t.Fatalf("expected ErrMissingUserSecret for JIRA_API_TOKEN, got %v", err)
	}
}

func TestStoreSourceNeedsTheUsersKey(t *testing.T) {
	s, srv := newServer(t)
	salt := core.NewSalt()
	params := core.ArgonParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	key := core.DeriveUserKey("pw", salt, params)
	entry, _ := core.SealEntry(key, salt, params, "alice", "atlassian", map[string]string{"JIRA_API_TOKEN": "sealed-value"})
	_ = s.SecretStore.Put(t.Context(), "alice", "atlassian", entry)

	// Without the vault key header the store cannot be opened → required secret missing.
	if _, err := s.ResolveUserSecrets(t.Context(), http.Header{}, &core.Principal{Subject: "alice"}, srv); err == nil {
		t.Fatal("store source must not yield anything without the user's key")
	}
	// With the wrong key: still missing (and never a decrypt).
	wrong := http.Header{}
	wrong.Set("X-Juggernaut-Vault-Key", base64.RawURLEncoding.EncodeToString(core.DeriveUserKey("nope", salt, params)))
	if _, err := s.ResolveUserSecrets(t.Context(), wrong, &core.Principal{Subject: "alice"}, srv); err == nil {
		t.Fatal("wrong vault key must not open the entry")
	}
	// With the right key, for the right subject.
	right := http.Header{}
	right.Set("X-Juggernaut-Vault-Key", base64.RawURLEncoding.EncodeToString(key))
	got, err := s.ResolveUserSecrets(t.Context(), right, &core.Principal{Subject: "alice"}, srv)
	if err != nil || got.Plain["JIRA_API_TOKEN"] != "sealed-value" {
		t.Fatalf("store source: %+v %v", got, err)
	}
	// Bob with Alice's key still gets nothing: entries are per subject.
	if _, err := s.ResolveUserSecrets(t.Context(), right, &core.Principal{Subject: "bob"}, srv); err == nil {
		t.Fatal("another subject must not read alice's entry")
	}
}

func TestSealedSourcePassesThrough(t *testing.T) {
	s, srv := newServer(t)
	h := http.Header{}
	h.Set("X-Juggernaut-Sealed-Secrets-atlassian", "opaque-blob")
	got, err := s.ResolveUserSecrets(t.Context(), h, &core.Principal{Subject: "alice"}, srv)
	if err != nil || got.Sealed != "opaque-blob" {
		t.Fatalf("sealed source: %+v %v", got, err)
	}
	if out := got.Headers(s.Store.Get().Config.Gateway.UserSecrets); out.Get("X-Juggernaut-Sealed-Secrets") != "opaque-blob" {
		t.Fatalf("sealed header must be forwarded under the adapter-less name: %v", out)
	}
}
