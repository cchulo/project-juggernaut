// Package netpol renders the per-session network isolation objects:
//
//   - a vanilla NetworkPolicy (L3/L4 baseline every cluster gets),
//   - a CiliumNetworkPolicy with toFQDNs + DNS proxy rules (reference enforcer),
//   - the hostname allowlist consumed by juggernaut-egress (fallback enforcer).
//
// See docs/DESIGN.md §5 for the threat model these implement.
package netpol

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
)

// Options are the cluster-level inputs from juggernaut.yaml's network section.
type Options struct {
	Enforcer           config.EgressEnforcer
	SystemNamespace    string
	GatewayPodSelector map[string]string
	// EgressProxySelector selects juggernaut-egress pods (proxy mode).
	EgressProxySelector map[string]string
	EgressProxyPort     int32
	// DNSNamespace/DNSPodSelector locate the cluster resolver (cilium mode).
	DNSNamespace   string
	DNSPodSelector map[string]string
	// DenyCIDRs are never reachable even when a wider CIDR is allowed.
	DenyCIDRs []string
	// APIServerCIDR is added to DenyCIDRs when set.
	APIServerCIDR string
}

// DefaultOptions fills the usual kube-dns and namespace values.
func DefaultOptions(n config.Network) Options {
	o := Options{
		Enforcer:            n.EgressEnforcer,
		SystemNamespace:     "juggernaut-system",
		GatewayPodSelector:  n.GatewayPodSelector,
		EgressProxySelector: map[string]string{"app.kubernetes.io/name": "juggernaut-egress"},
		EgressProxyPort:     3128,
		DNSNamespace:        "kube-system",
		DNSPodSelector:      map[string]string{"k8s-app": "kube-dns"},
		DenyCIDRs:           append([]string{}, n.DenyCIDRs...),
		APIServerCIDR:       n.APIServerCIDR,
	}
	if len(o.GatewayPodSelector) == 0 {
		o.GatewayPodSelector = map[string]string{"app.kubernetes.io/name": "juggernaut-gateway"}
	}
	if len(o.DenyCIDRs) == 0 {
		o.DenyCIDRs = []string{"169.254.169.254/32", "169.254.0.0/16", "fd00::/8"}
	}
	if o.APIServerCIDR != "" {
		o.DenyCIDRs = append(o.DenyCIDRs, o.APIServerCIDR)
	}
	return o
}

func sessionLabels(sess *jugv1.Session) map[string]string {
	return map[string]string{
		jugv1.LabelSession:    "true",
		jugv1.LabelSessionID:  sess.Name,
		jugv1.LabelServerType: sess.Spec.ServerType,
		jugv1.LabelUserHash:   sess.Spec.UserHash,
		jugv1.LabelManagedBy:  jugv1.ManagedByValue,
	}
}

// RenderNetworkPolicy builds the baseline policy for one session pod.
//
// Ingress: only gateway pods, only the wrapper ports.
// Egress (cilium): DNS to the cluster resolver and TCP to the declared ports of
// 0.0.0.0/0 minus private, link-local and denied CIDRs; hostnames are enforced
// by the Cilium policy on top.
// Egress (proxy): only the egress proxy; no DNS at all.
func RenderNetworkPolicy(sess *jugv1.Session, st *jugv1.ServerType, o Options) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "session-" + sess.Name, Namespace: sess.Namespace, Labels: sessionLabels(sess)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{jugv1.LabelSessionID: sess.Name}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": o.SystemNamespace}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: o.GatewayPodSelector},
				}},
				Ports: []networkingv1.NetworkPolicyPort{
					{Protocol: &tcp, Port: ptrIntstr(st.Spec.WrapperPort)},
					{Protocol: &tcp, Port: ptrIntstr(st.Spec.ReadinessPort)},
				},
			}},
		},
	}
	switch o.Enforcer {
	case config.EgressProxy:
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": o.SystemNamespace}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: o.EgressProxySelector},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: ptrIntstr(o.EgressProxyPort)}},
		}}
	default:
		ports := uniquePorts(st)
		var portRules []networkingv1.NetworkPolicyPort
		for _, p := range ports {
			portRules = append(portRules, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: ptrIntstr(p)})
		}
		except := append([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"}, o.DenyCIDRs...)
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": o.DNSNamespace}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: o.DNSPodSelector},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: ptrIntstr(53)}, {Protocol: &tcp, Port: ptrIntstr(53)}},
			},
			{
				To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: dedupe(except)}}},
				Ports: portRules,
			},
		}
		if o.Enforcer == config.EgressNone {
			// Insecure mode still keeps metadata and the API server off limits.
			np.Spec.Egress[1].To[0].IPBlock.Except = dedupe(o.DenyCIDRs)
			np.Spec.Egress[1].Ports = nil
		}
	}
	return np
}

// RenderNamespaceDefaultDeny is applied once to the sessions namespace so a pod
// that somehow lacks its own policy still has no connectivity.
func RenderNamespaceDefaultDeny(namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny-all", Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func uniquePorts(st *jugv1.ServerType) []int32 {
	seen := map[int32]bool{}
	var out []int32
	for _, e := range st.Spec.Egress {
		for _, p := range e.Ports {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		out = []int32{443}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func ptrIntstr(p int32) *intstr.IntOrString {
	v := intstr.FromInt32(p)
	return &v
}

// Validate checks that the enforcer can actually isolate the given server type.
func Validate(st *jugv1.ServerType, o Options) error {
	if o.Enforcer != config.EgressNone && len(st.Spec.Egress) == 0 {
		return fmt.Errorf("server type %s declares no egress hosts", st.Name)
	}
	return nil
}
