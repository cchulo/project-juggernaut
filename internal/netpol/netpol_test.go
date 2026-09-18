package netpol

import (
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
)

func fixtures() (*jugv1.Session, *jugv1.ServerType) {
	sess := &jugv1.Session{ObjectMeta: metav1.ObjectMeta{Name: "jira-abcd1234", Namespace: "juggernaut-sessions"},
		Spec: jugv1.SessionSpec{ServerType: "jira", UserHash: "abcd1234"}}
	st := &jugv1.ServerType{ObjectMeta: metav1.ObjectMeta{Name: "jira"}, Spec: jugv1.ServerTypeSpec{
		WrapperPort: 9000, ReadinessPort: 9001,
		Egress: []jugv1.EgressRule{{Host: "api.atlassian.com", Ports: []int32{443}, Protocol: "TCP"}, {Host: "*.example.net", Ports: []int32{443, 8443}, Protocol: "TCP"}},
	}}
	return sess, st
}

func TestNetworkPolicyProxyModeOnlyReachesProxy(t *testing.T) {
	sess, st := fixtures()
	np := RenderNetworkPolicy(sess, st, DefaultOptions(config.Network{EgressEnforcer: config.EgressProxy, DenyCIDRs: []string{"169.254.169.254/32"}}))
	if len(np.Spec.Egress) != 1 || np.Spec.Egress[0].To[0].PodSelector.MatchLabels["app.kubernetes.io/name"] != "juggernaut-egress" {
		t.Fatalf("proxy mode must only allow egress to the proxy: %+v", np.Spec.Egress)
	}
	if np.Spec.Ingress[0].From[0].PodSelector.MatchLabels["app.kubernetes.io/name"] != "juggernaut-gateway" {
		t.Fatal("ingress must be restricted to the gateway")
	}
}

func TestNetworkPolicyCiliumModeDeniesMetadata(t *testing.T) {
	sess, st := fixtures()
	np := RenderNetworkPolicy(sess, st, DefaultOptions(config.Network{EgressEnforcer: config.EgressCilium, DenyCIDRs: []string{"169.254.169.254/32"}}))
	found := false
	for _, e := range np.Spec.Egress[1].To[0].IPBlock.Except {
		if e == "169.254.169.254/32" || e == "169.254.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatal("metadata endpoint must be excluded")
	}
}

func TestCiliumPolicyHasFQDNAndDNSRules(t *testing.T) {
	sess, st := fixtures()
	u := RenderCiliumPolicy(sess, st, DefaultOptions(config.Network{EgressEnforcer: config.EgressCilium}))
	spec := u.Object["spec"].(map[string]any)
	egress := spec["egress"].([]any)
	if len(egress) != 2 {
		t.Fatalf("expected DNS + FQDN rules, got %d", len(egress))
	}
	fq := egress[1].(map[string]any)["toFQDNs"].([]any)
	if len(fq) != 2 {
		t.Fatalf("expected 2 fqdn entries, got %v", fq)
	}
}

func TestAllowlist(t *testing.T) {
	sess, st := fixtures()
	a := &Allowlist{Entries: map[string]AllowEntry{"10.0.0.5": EntryFor(sess, st)}}
	src := net.ParseIP("10.0.0.5")
	if _, ok := a.Allows(src, "api.atlassian.com", 443); !ok {
		t.Fatal("exact host should be allowed")
	}
	if _, ok := a.Allows(src, "foo.example.net", 8443); !ok {
		t.Fatal("wildcard host should be allowed")
	}
	if _, ok := a.Allows(src, "a.b.example.net", 443); ok {
		t.Fatal("wildcard must match one label only")
	}
	if _, ok := a.Allows(src, "api.atlassian.com", 80); ok {
		t.Fatal("port not in allowlist")
	}
	if _, ok := a.Allows(net.ParseIP("10.0.0.6"), "api.atlassian.com", 443); ok {
		t.Fatal("unknown source pod must be denied")
	}
}
