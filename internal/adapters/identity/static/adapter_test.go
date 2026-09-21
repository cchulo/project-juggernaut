package static

import (
	"net/http"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	a, err := New(contracttest.Context(t, contracttest.LaptopConfig, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	good := contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer alice-token"}}, RemoteAddr: "10.0.0.9:1"}
	bad := contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer nope"}}, RemoteAddr: "10.0.0.9:1"}
	contracttest.IdentityProvider(t, a, good, &bad)

	p, _ := a.Resolve(t.Context(), contracts.RequestInfo{Header: http.Header{"Authorization": {"Bearer ci-token"}}})
	if p.Kind != "service" || len(p.Scopes) != 1 {
		t.Fatalf("seed kind/scopes not honoured: %+v", p)
	}
	if a.ProtectedResourceMetadata() != nil {
		t.Fatal("static must serve no protected-resource metadata")
	}
}
