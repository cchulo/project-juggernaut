package exchange

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestExchangeCachesAndBoundsExpiry(t *testing.T) {
	var calls atomic.Int32
	var lastForm map[string][]string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		lastForm = r.PostForm
		u, p, _ := r.BasicAuth()
		if u != "juggernaut-gateway" || p != "s3cret" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "dt-" + r.PostForm.Get("audience"), "token_type": "Bearer", "expires_in": 3600})
	}))
	defer idp.Close()
	cfg := strings.Replace(contracttest.LaptopConfig, "broker: { mode: none }",
		"broker: { mode: exchange, clientId: juggernaut-gateway, clientSecretRef: { env: BROKER_SECRET }, tokenEndpoint: "+idp.URL+" }", 1)
	cfg = strings.Replace(cfg, "type: static", "type: bearer_jwt\n  issuer: https://idp/realms/x\n  audience: gw", 1)
	ctx := contracttest.Context(t, cfg, core.StaticSecrets{"BROKER_SECRET": "s3cret"}, nil)
	b, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := &core.Principal{Subject: "alice", RawToken: "client-token", TokenHash: "h1", Expiry: time.Now().Add(10 * time.Minute)}
	srv := &config.Server{Name: "jira", Token: config.Token{Mode: config.TokenEnv, Audience: "jira-mcp", Scopes: []string{"read:jira"}}}

	tok, err := b.TokenFor(t.Context(), p, srv, time.Minute)
	if err != nil || tok.Value != "dt-jira-mcp" {
		t.Fatalf("exchange: %+v %v", tok, err)
	}
	if lastForm["grant_type"][0] != "urn:ietf:params:oauth:grant-type:token-exchange" || lastForm["subject_token"][0] != "client-token" || lastForm["scope"][0] != "read:jira" {
		t.Fatalf("exchange form: %v", lastForm)
	}
	if !tok.Expiry.Before(time.Now().Add(11 * time.Minute)) {
		t.Fatal("downstream token must not outlive the incoming token")
	}
	if _, err := b.TokenFor(t.Context(), p, srv, time.Minute); err != nil || calls.Load() != 1 {
		t.Fatalf("second call must hit the cache (calls=%d)", calls.Load())
	}
	other := &config.Server{Name: "github", Token: config.Token{Mode: config.TokenHeader, Audience: "github-mcp"}}
	if tok, _ := b.TokenFor(t.Context(), p, other, time.Minute); tok.Value != "dt-github-mcp" || calls.Load() != 2 {
		t.Fatal("a different server type needs its own exchange")
	}
	if tok, err := b.TokenFor(t.Context(), p, &config.Server{Name: "n", Token: config.Token{Mode: config.TokenNone}}, time.Minute); tok != nil || err != nil {
		t.Fatal("token mode none needs no exchange")
	}
	_ = b.Revoke(t.Context(), "alice")
	if _, err := b.TokenFor(t.Context(), p, srv, time.Minute); err != nil || calls.Load() != 3 {
		t.Fatal("revoke must drop the cache")
	}
	contracttest.TokenBroker(t, b, p)
}
