package bearer_jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

// issuer is a mocked OIDC issuer: discovery + JWKS, signing RS256 tokens.
type issuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": is.srv.URL, "jwks_uri": is.srv.URL + "/jwks", "authorization_endpoint": is.srv.URL + "/auth",
			"token_endpoint": is.srv.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: is.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"iss": is.srv.URL, "aud": "juggernaut-gateway", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	for k, v := range claims {
		base[k] = v
	}
	payload, _ := json.Marshal(base)
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := sig.CompactSerialize()
	return s
}

func TestContract(t *testing.T) {
	is := newIssuer(t)
	cfg := strings.Replace(contracttest.LaptopConfig, "identity:\n  type: static\n",
		"identity:\n  type: bearer_jwt\n  issuer: "+is.srv.URL+"\n  audience: juggernaut-gateway\n", 1)
	a, err := New(contracttest.Context(t, cfg, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	good := contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer " + is.token(t, map[string]any{
		"sub": "u1", "preferred_username": "alice", "groups": []string{"/engineering"}, "scope": "openid juggernaut:mcp",
		"realm_access": map[string]any{"roles": []string{"juggernaut-admin"}},
	})}}}
	bad := contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer " + is.token(t, map[string]any{"sub": "u1", "aud": "someone-else"})}}}
	contracttest.IdentityProvider(t, a, good, &bad)

	p, _ := a.Resolve(t.Context(), good)
	if p.Username != "alice" || !p.InGroup("engineering") || !p.InGroup("juggernaut-admin") || !p.HasScope("juggernaut:mcp") || p.Kind != "user" {
		t.Fatalf("claims mapping: %+v", p)
	}
	svc, err := a.Resolve(t.Context(), contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer " + is.token(t, map[string]any{"sub": "ci", "azp": "ci"})}}})
	if err != nil || svc.Kind != "service" {
		t.Fatalf("client-credentials token must be a service principal: %+v %v", svc, err)
	}
	md := a.ProtectedResourceMetadata()
	if md == nil || md.AuthorizationServers[0] != is.srv.URL || !strings.HasSuffix(md.Resource, "/mcp") {
		t.Fatalf("metadata: %+v", md)
	}
	if ch := a.Challenge(contracts.ChallengeInvalidToken, "x", "juggernaut:mcp"); !strings.Contains(ch, "resource_metadata=") || !strings.Contains(ch, `error="invalid_token"`) {
		t.Fatalf("challenge: %s", ch)
	}
}
