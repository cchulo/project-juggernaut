package none

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

const noneConfig = `
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity:
  type: none
  broker: { mode: none }
gateway: { publicURL: http://127.0.0.1:8080, runtime: { kind: local } }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - { name: a, image: example/a:1, transport: stdio, command: ["/bin/a"], token: { mode: none } }
authorization:
  groups: [{ name: everyone, serverTypes: [a] }]
`

func TestLoopbackOnly(t *testing.T) {
	a, err := New(contracttest.Context(t, noneConfig, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	good := contracts.RequestInfo{RemoteAddr: "127.0.0.1:5555"}
	bad := contracts.RequestInfo{RemoteAddr: "10.0.0.9:5555"}
	contracttest.IdentityProvider(t, a, good, &bad)
	p, _ := a.Resolve(t.Context(), good)
	if p.Subject != "local" || !p.InGroup("everyone") || !p.HasScope("juggernaut:mcp") {
		t.Fatalf("default principal wrong: %+v", p)
	}
}

func TestTrustedNetworkAcceptsAnyPeer(t *testing.T) {
	a, _ := New(contracttest.Context(t, noneConfig, core.StaticSecrets{TrustedNetworkEnv: "1"}, nil))
	if _, err := a.Resolve(t.Context(), contracts.RequestInfo{RemoteAddr: "10.0.0.9:1"}); err != nil {
		t.Fatalf("trusted network must accept non-loopback: %v", err)
	}
}

func TestAllowRemoteNeedsToken(t *testing.T) {
	cfg := strings.Replace(noneConfig, "type: none\n", "type: none\n  allowRemote: true\n", 1)
	a, _ := New(contracttest.Context(t, cfg, core.StaticSecrets{"JUGGERNAUT_TOKEN": "s3cret"}, nil))
	loopbackNoToken := contracts.RequestInfo{RemoteAddr: "127.0.0.1:1"}
	if _, err := a.Resolve(t.Context(), loopbackNoToken); err == nil {
		t.Fatal("allowRemote must require the token even on loopback")
	}
	withToken := contracts.RequestInfo{RemoteAddr: "10.0.0.9:1", Header: http.Header{"Authorization": {"Bearer s3cret"}}}
	if _, err := a.Resolve(t.Context(), withToken); err != nil {
		t.Fatalf("valid static token must be accepted: %v", err)
	}
	empty, _ := New(contracttest.Context(t, cfg, core.StaticSecrets{}, nil))
	if _, err := empty.Resolve(t.Context(), withToken); err == nil {
		t.Fatal("an empty secret must be a 401, not an open door")
	}
}
