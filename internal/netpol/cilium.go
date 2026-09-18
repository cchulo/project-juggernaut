package netpol

import (
	"strconv"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
)

// CiliumNetworkPolicyGVK is used with unstructured objects so Juggernaut does
// not depend on the Cilium Go API.
var CiliumNetworkPolicyGVK = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}

// RenderCiliumPolicy builds the FQDN-level policy: egress only to the declared
// hostnames on the declared ports, and DNS lookups only for those names (the
// Cilium DNS proxy enforces the latter, closing the DNS covert channel).
func RenderCiliumPolicy(sess *jugv1.Session, st *jugv1.ServerType, o Options) *unstructured.Unstructured {
	var dnsRules []any
	var fqdns []any
	for _, e := range st.Spec.Egress {
		if len(e.Host) > 2 && e.Host[:2] == "*." {
			dnsRules = append(dnsRules, map[string]any{"matchPattern": e.Host})
			fqdns = append(fqdns, map[string]any{"matchPattern": e.Host})
		} else {
			dnsRules = append(dnsRules, map[string]any{"matchName": e.Host})
			fqdns = append(fqdns, map[string]any{"matchName": e.Host})
		}
	}
	var toPorts []any
	seen := map[string]bool{}
	for _, e := range st.Spec.Egress {
		for _, p := range e.Ports {
			k := strconv.Itoa(int(p)) + e.Protocol
			if seen[k] {
				continue
			}
			seen[k] = true
			toPorts = append(toPorts, map[string]any{"port": strconv.Itoa(int(p)), "protocol": e.Protocol})
		}
	}
	dnsSelector := map[string]any{}
	for k, v := range o.DNSPodSelector {
		dnsSelector["k8s:"+k] = v
	}
	dnsSelector["k8s:io.kubernetes.pod.namespace"] = o.DNSNamespace
	gwSelector := map[string]any{"k8s:io.kubernetes.pod.namespace": o.SystemNamespace}
	for k, v := range o.GatewayPodSelector {
		gwSelector["k8s:"+k] = v
	}

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(CiliumNetworkPolicyGVK)
	u.SetName("session-" + sess.Name)
	u.SetNamespace(sess.Namespace)
	u.SetLabels(sessionLabels(sess))
	u.Object["spec"] = map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{jugv1.LabelSessionID: sess.Name}},
		"ingress": []any{map[string]any{
			"fromEndpoints": []any{map[string]any{"matchLabels": gwSelector}},
			"toPorts": []any{map[string]any{"ports": []any{
				map[string]any{"port": strconv.Itoa(int(st.Spec.WrapperPort)), "protocol": "TCP"},
				map[string]any{"port": strconv.Itoa(int(st.Spec.ReadinessPort)), "protocol": "TCP"},
			}}},
		}},
		"egress": []any{
			map[string]any{
				"toEndpoints": []any{map[string]any{"matchLabels": dnsSelector}},
				"toPorts": []any{map[string]any{
					"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}, map[string]any{"port": "53", "protocol": "TCP"}},
					"rules": map[string]any{"dns": dnsRules},
				}},
			},
			map[string]any{
				"toFQDNs": fqdns,
				"toPorts": []any{map[string]any{"ports": toPorts}},
			},
		},
	}
	return u
}
