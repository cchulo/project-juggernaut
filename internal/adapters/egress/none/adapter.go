// Package none disables hostname-level egress enforcement (laptops only; requires
// network.allowInsecure). Metadata and API-server CIDRs are still denied and the
// gateway is still the only allowed ingress.
package none

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// Type is the registry name.
const Type = "none"

func init() { registry.Egress.Register(Type, New) }

// Adapter renders only the minimal baseline.
type Adapter struct{ opts netpol.Options }

// New logs loudly.
func New(ctx *core.Context) (contracts.EgressEnforcer, error) {
	ctx.Log.Warn("network.egressEnforcer is none: session pods have unrestricted egress. Laptop use only.")
	n := ctx.Cfg().Network
	n.EgressEnforcer = config.EgressNone
	return &Adapter{opts: netpol.DefaultOptions(n)}, nil
}

func (a *Adapter) Validate(*jugv1.ServerType) error { return nil }

func (a *Adapter) Objects(sess *jugv1.Session, st *jugv1.ServerType) ([]client.Object, error) {
	return []client.Object{netpol.RenderNetworkPolicy(sess, st, a.opts)}, nil
}

func (a *Adapter) OnReady(context.Context, *jugv1.Session, *jugv1.ServerType, string) error {
	return nil
}
func (a *Adapter) OnCleanup(context.Context, *jugv1.Session) error { return nil }
func (a *Adapter) NamespaceObjects(string) []client.Object         { return nil }
func (a *Adapter) PodEnv() (map[string]string, bool)               { return nil, false }
