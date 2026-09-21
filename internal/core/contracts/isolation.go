package contracts

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
)

// EgressEnforcer decides what a session pod may reach and renders the objects
// that enforce it. The controller calls it around the pod lifecycle and never
// knows whether the mechanism is a CNI policy or an egress proxy.
type EgressEnforcer interface {
	// Validate rejects server types the enforcer cannot isolate (e.g. no egress hosts).
	Validate(st *jugv1.ServerType) error
	// Objects renders the per-session objects (NetworkPolicy, CiliumNetworkPolicy, ...)
	// to create before the pod. The caller sets owner references and applies them.
	Objects(sess *jugv1.Session, st *jugv1.ServerType) ([]client.Object, error)
	// OnReady runs once the pod has an IP (proxy mode publishes the allowlist here).
	OnReady(ctx context.Context, sess *jugv1.Session, st *jugv1.ServerType, podIP string) error
	// OnCleanup runs when the session terminates.
	OnCleanup(ctx context.Context, sess *jugv1.Session) error
	// NamespaceObjects renders namespace-wide objects applied once (default-deny).
	NamespaceObjects(namespace string) []client.Object
	// PodEnv returns environment the session pod needs (HTTPS_PROXY in proxy mode) and
	// whether the pod must run without a resolver.
	PodEnv() (env map[string]string, disableDNS bool)
}
