package core

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubeAccess is the Kubernetes connection adapters may use. It is set on the
// Context by the composition root only when the process runs against a
// cluster; laptop deployments leave it nil.
type KubeAccess interface {
	Client() client.Client
	RESTConfig() *rest.Config
	// HasKind reports whether the API server serves a group/version/kind (e.g. CiliumNetworkPolicy).
	HasKind(gvk schema.GroupVersionKind) bool
}
