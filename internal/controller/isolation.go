package controller

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// Isolation creates the per-session network objects and, in proxy mode,
// publishes the pod's allowlist to juggernaut-egress.
type Isolation struct {
	Client  client.Client
	Options netpol.Options
	Log     *slog.Logger
	// SystemNamespace hosts the allowlist ConfigMap for the egress proxy.
	SystemNamespace string
	// CiliumAvailable is probed at startup; without it cilium mode is refused.
	CiliumAvailable bool

	mu sync.Mutex
}

// AllowlistConfigMapName is the ConfigMap juggernaut-egress mounts.
const AllowlistConfigMapName = "juggernaut-egress-allowlist"

// Decorate is wired into SessionReconciler.Decorate: it runs before the pod is created.
func (iso *Isolation) Decorate(ctx context.Context, sess *jugv1.Session, st *jugv1.ServerType, owner client.Object, scheme schemeSetter) error {
	if err := netpol.Validate(st, iso.Options); err != nil {
		return err
	}
	np := netpol.RenderNetworkPolicy(sess, st, iso.Options)
	if err := iso.apply(ctx, np, owner, scheme); err != nil {
		return fmt.Errorf("networkpolicy: %w", err)
	}
	if iso.Options.Enforcer == config.EgressCilium {
		if !iso.CiliumAvailable {
			return fmt.Errorf("network.egressEnforcer is cilium but the CiliumNetworkPolicy CRD is not installed")
		}
		cnp := netpol.RenderCiliumPolicy(sess, st, iso.Options)
		if err := iso.apply(ctx, cnp, owner, scheme); err != nil {
			return fmt.Errorf("ciliumnetworkpolicy: %w", err)
		}
	}
	return nil
}

type schemeSetter interface {
	SetControllerReference(owner, object metav1.Object) error
}

func (iso *Isolation) apply(ctx context.Context, obj client.Object, owner client.Object, scheme schemeSetter) error {
	if err := scheme.SetControllerReference(owner, obj); err != nil {
		return err
	}
	switch o := obj.(type) {
	case *networkingv1.NetworkPolicy:
		existing := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: o.Name, Namespace: o.Namespace}}
		_, err := controllerutil.CreateOrUpdate(ctx, iso.Client, existing, func() error {
			existing.Labels = o.Labels
			existing.OwnerReferences = o.OwnerReferences
			existing.Spec = o.Spec
			return nil
		})
		return err
	case *unstructured.Unstructured:
		existing := &unstructured.Unstructured{}
		existing.SetGroupVersionKind(o.GroupVersionKind())
		existing.SetName(o.GetName())
		existing.SetNamespace(o.GetNamespace())
		err := iso.Client.Get(ctx, client.ObjectKeyFromObject(existing), existing)
		if apierrors.IsNotFound(err) {
			return iso.Client.Create(ctx, o)
		}
		if err != nil {
			return err
		}
		existing.Object["spec"] = o.Object["spec"]
		existing.SetLabels(o.GetLabels())
		existing.SetOwnerReferences(o.GetOwnerReferences())
		return iso.Client.Update(ctx, existing)
	}
	return fmt.Errorf("unsupported object %T", obj)
}

// OnReady publishes the pod's allowlist keyed by pod IP (proxy mode only).
func (iso *Isolation) OnReady(ctx context.Context, sess *jugv1.Session, st *jugv1.ServerType, podIP string) error {
	if iso.Options.Enforcer != config.EgressProxy {
		return nil
	}
	return iso.updateAllowlist(ctx, func(a *netpol.Allowlist) {
		a.Entries[podIP] = netpol.EntryFor(sess, st)
	})
}

// OnCleanup removes the pod's allowlist entry.
func (iso *Isolation) OnCleanup(ctx context.Context, sess *jugv1.Session) error {
	if iso.Options.Enforcer != config.EgressProxy {
		return nil
	}
	return iso.updateAllowlist(ctx, func(a *netpol.Allowlist) {
		for ip, e := range a.Entries {
			if e.Session == sess.Name {
				delete(a.Entries, ip)
			}
		}
	})
}

func (iso *Isolation) updateAllowlist(ctx context.Context, mutate func(*netpol.Allowlist)) error {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: AllowlistConfigMapName, Namespace: iso.SystemNamespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, iso.Client, cm, func() error {
		a, err := netpol.ParseAllowlist([]byte(cm.Data["allowlist.json"]))
		if err != nil {
			a = &netpol.Allowlist{Entries: map[string]netpol.AllowEntry{}}
		}
		mutate(a)
		b, err := a.Marshal()
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

// EnsureNamespaceDefaultDeny applies the namespace-wide default-deny once.
func (iso *Isolation) EnsureNamespaceDefaultDeny(ctx context.Context, namespace string) error {
	np := netpol.RenderNamespaceDefaultDeny(namespace)
	existing := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: np.Name, Namespace: np.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, iso.Client, existing, func() error {
		existing.Spec = np.Spec
		return nil
	})
	return err
}
