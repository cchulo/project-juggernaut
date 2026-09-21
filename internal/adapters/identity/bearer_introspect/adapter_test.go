package bearer_introspect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/adapters/identity/bearer_jwt"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

// fakeJWT stands in for bearer_jwt so this test needs no issuer.
type fakeJWT struct{ contracts.IdentityProvider }

func (fakeJWT) Resolve(_ context.Context, req contracts.RequestInfo) (*core.Principal, error) {
	tok, _ := req.Bearer()
	return &core.Principal{Subject: "alice", Kind: "user", RawToken: tok, TokenHash: "h-" + tok}, nil
}
func (fakeJWT) Challenge(contracts.ChallengeReason, string, string) string { return "Bearer" }
func (fakeJWT) ProtectedResourceMetadata() *contracts.ProtectedResourceMetadata {
	return nil
}

func newAdapter(t *testing.T, endpoint string, opts map[string]any) *Adapter {
	t.Helper()
	cfg := strings.Replace(contracttest.LaptopConfig, "type: static", "type: bearer_introspect\n  issuer: https://idp/realms/x\n  audience: gw\n  introspection: { enabled: true, interval: 1h, endpoint: "+endpoint+", clientId: gw, clientSecretRef: { env: INTRO } }", 1)
	ctx := contracttest.Context(t, cfg, core.StaticSecrets{"INTRO": "s"}, opts)
	return &Adapter{IdentityProvider: fakeJWT{}, jwt: &bearer_jwt.Adapter{}, ctx: ctx, client: http.DefaultClient, seen: map[string]seen{}}
}

func req(tok string) contracts.RequestInfo {
	return contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer " + tok}}}
}

func TestRevokedTokenRejectedAndCached(t *testing.T) {
	var calls atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{"active": r.PostForm.Get("token") == "good"})
	}))
	defer idp.Close()
	a := newAdapter(t, idp.URL, nil)
	if _, err := a.Resolve(t.Context(), req("good")); err != nil {
		t.Fatalf("active token: %v", err)
	}
	if _, err := a.Resolve(t.Context(), req("good")); err != nil || calls.Load() != 1 {
		t.Fatalf("second check within the interval must be cached (calls=%d)", calls.Load())
	}
	if _, err := a.Resolve(t.Context(), req("revoked")); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked token must be rejected: %v", err)
	}
}

func TestFailsClosedByDefault(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	dead.Close() // unreachable
	a := newAdapter(t, dead.URL, nil)
	if _, err := a.Resolve(t.Context(), req("good")); err == nil {
		t.Fatal("unreachable introspection must reject by default")
	}
	open := newAdapter(t, dead.URL, map[string]any{"fail_open": true})
	if _, err := open.Resolve(t.Context(), req("good")); err != nil {
		t.Fatalf("fail_open must accept: %v", err)
	}
}
