// Package cilium is the reference egress enforcer: a baseline NetworkPolicy plus
// a CiliumNetworkPolicy with toFQDNs and DNS-proxy rules per session pod, so a
// pod can reach only its declared hostnames and cannot resolve anything else.
package cilium

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// Type is the registry name.
const Type = "cilium"

func init() { registry.Egress.Register(Type, New) }

// Adapter renders Cilium policies.
type Adapter struct{ opts netpol.Options }

// New refuses to start when the cluster does not serve CiliumNetworkPolicy.
func New(ctx *core.Context) (contracts.EgressEnforcer, error) {
	if ctx.Kube != nil && !ctx.Kube.HasKind(netpol.CiliumNetworkPolicyGVK) {
		return nil, fmt.Errorf("network.egressEnforcer is cilium but the CiliumNetworkPolicy CRD is not installed")
	}
	n := ctx.Cfg().Network
	n.EgressEnforcer = config.EgressCilium
	return &Adapter{opts: netpol.DefaultOptions(n)}, nil
}

func (a *Adapter) Validate(st *jugv1.ServerType) error { return netpol.Validate(st, a.opts) }

func (a *Adapter) Objects(sess *jugv1.Session, st *jugv1.ServerType) ([]client.Object, error) {
	return []client.Object{netpol.RenderNetworkPolicy(sess, st, a.opts), netpol.RenderCiliumPolicy(sess, st, a.opts)}, nil
}

func (a *Adapter) OnReady(context.Context, *jugv1.Session, *jugv1.ServerType, string) error {
	return nil
}
func (a *Adapter) OnCleanup(context.Context, *jugv1.Session) error { return nil }

func (a *Adapter) NamespaceObjects(namespace string) []client.Object {
	return []client.Object{netpol.RenderNamespaceDefaultDeny(namespace)}
}

func (a *Adapter) PodEnv() (map[string]string, bool) { return nil, false }
