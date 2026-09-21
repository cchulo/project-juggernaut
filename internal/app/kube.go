// Package app holds the composition roots: the only code that turns
// juggernaut.yaml selectors into concrete adapters through the registries and
// wires them into the gateway and controller. Everything else depends on
// contracts. This is the Go counterpart of cerebro's Gateway.from_config.
package app

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// Scheme registers the built-in and Juggernaut API types.
func Scheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := jugv1.AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

// kubeAccess is the core.KubeAccess implementation for a direct client.
type kubeAccess struct {
	cfg    *rest.Config
	cl     client.Client
	mapper func() (hasKind func(schema.GroupVersionKind) bool)
}

func (k *kubeAccess) Client() client.Client                    { return k.cl }
func (k *kubeAccess) RESTConfig() *rest.Config                 { return k.cfg }
func (k *kubeAccess) HasKind(gvk schema.GroupVersionKind) bool { return k.mapper()(gvk) }

// NewKubeAccess connects with the in-cluster config or kubeconfig.
func NewKubeAccess() (core.KubeAccess, error) {
	rc, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	scheme, err := Scheme()
	if err != nil {
		return nil, err
	}
	cl, err := client.New(rc, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	return &kubeAccess{cfg: rc, cl: cl, mapper: func() func(schema.GroupVersionKind) bool {
		m, err := apiutil.NewDynamicRESTMapper(rc, nil)
		if err != nil {
			return func(schema.GroupVersionKind) bool { return false }
		}
		return func(gvk schema.GroupVersionKind) bool {
			_, err := m.RESTMapping(gvk.GroupKind(), gvk.Version)
			return err == nil
		}
	}}, nil
}

// KubeAccessFrom wraps an existing client (the controller manager's).
func KubeAccessFrom(rc *rest.Config, cl client.Client, hasKind func(schema.GroupVersionKind) bool) core.KubeAccess {
	return &kubeAccess{cfg: rc, cl: cl, mapper: func() func(schema.GroupVersionKind) bool { return hasKind }}
}
