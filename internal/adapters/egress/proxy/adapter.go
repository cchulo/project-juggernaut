// Package proxy is the fallback egress enforcer for clusters without an
// FQDN-aware CNI: a NetworkPolicy lets the session pod reach only
// juggernaut-egress, the pod gets no resolver, and the proxy enforces the
// hostname allowlist this adapter publishes per pod IP in a ConfigMap.
//
// Options: allowlist_configmap (default juggernaut-egress-allowlist),
// system_namespace (default juggernaut-system).
package proxy

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// Type is the registry name.
const Type = "proxy"

func init() { registry.Egress.Register(Type, New) }

// Adapter renders proxy-mode policies and publishes allowlists.
type Adapter struct {
	opts      netpol.Options
	address   string
	cl        client.Client
	cmName    string
	namespace string
	mu        sync.Mutex
}

// New builds the adapter; publishing needs a Kubernetes client.
func New(ctx *core.Context) (contracts.EgressEnforcer, error) {
	n := ctx.Cfg().Network
	if n.Proxy == nil || n.Proxy.Address == "" {
		return nil, fmt.Errorf("network.proxy.address is required for egressEnforcer proxy")
	}
	n.EgressEnforcer = config.EgressProxy
	a := &Adapter{opts: netpol.DefaultOptions(n), address: n.Proxy.Address,
		cmName:    ctx.Options.String("allowlist_configmap", "juggernaut-egress-allowlist"),
		namespace: ctx.Options.String("system_namespace", "juggernaut-system")}
	if ctx.Kube != nil {
		a.cl = ctx.Kube.Client()
	}
	return a, nil
}

func (a *Adapter) Validate(st *jugv1.ServerType) error { return netpol.Validate(st, a.opts) }

func (a *Adapter) Objects(sess *jugv1.Session, st *jugv1.ServerType) ([]client.Object, error) {
	return []client.Object{netpol.RenderNetworkPolicy(sess, st, a.opts)}, nil
}

// OnReady publishes the pod's allowlist keyed by its IP.
func (a *Adapter) OnReady(ctx context.Context, sess *jugv1.Session, st *jugv1.ServerType, podIP string) error {
	return a.update(ctx, func(al *netpol.Allowlist) { al.Entries[podIP] = netpol.EntryFor(sess, st) })
}

// OnCleanup removes the pod's entry.
func (a *Adapter) OnCleanup(ctx context.Context, sess *jugv1.Session) error {
	return a.update(ctx, func(al *netpol.Allowlist) {
		for ip, e := range al.Entries {
			if e.Session == sess.Name {
				delete(al.Entries, ip)
			}
		}
	})
}

func (a *Adapter) update(ctx context.Context, mutate func(*netpol.Allowlist)) error {
	if a.cl == nil {
		return fmt.Errorf("egress proxy adapter: no Kubernetes client to publish the allowlist")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: a.cmName, Namespace: a.namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, a.cl, cm, func() error {
		al, err := netpol.ParseAllowlist([]byte(cm.Data["allowlist.json"]))
		if err != nil {
			al = &netpol.Allowlist{Entries: map[string]netpol.AllowEntry{}}
		}
		mutate(al)
		b, err := al.Marshal()
		if err != nil {
			return err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data["allowlist.json"] = string(b)
		return nil
	})
	return err
}

func (a *Adapter) NamespaceObjects(namespace string) []client.Object {
	return []client.Object{netpol.RenderNamespaceDefaultDeny(namespace)}
}

// PodEnv points the pod at the proxy and disables its resolver.
func (a *Adapter) PodEnv() (map[string]string, bool) {
	return map[string]string{
		"HTTPS_PROXY": "http://" + a.address,
		"HTTP_PROXY":  "http://" + a.address,
		"NO_PROXY":    "127.0.0.1,localhost",
	}, true
}
