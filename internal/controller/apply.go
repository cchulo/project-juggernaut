package controller

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// applyObject creates or updates a rendered object, keeping its spec, labels
// and owner references in sync with what the enforcer rendered.
func applyObject(ctx context.Context, cl client.Client, obj client.Object) error {
	switch o := obj.(type) {
	case *networkingv1.NetworkPolicy:
		existing := &networkingv1.NetworkPolicy{}
		existing.Name, existing.Namespace = o.Name, o.Namespace
		_, err := controllerutil.CreateOrUpdate(ctx, cl, existing, func() error {
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
		err := cl.Get(ctx, client.ObjectKeyFromObject(existing), existing)
		if apierrors.IsNotFound(err) {
			return cl.Create(ctx, o)
		}
		if err != nil {
			return err
		}
		existing.Object["spec"] = o.Object["spec"]
		existing.SetLabels(o.GetLabels())
		existing.SetOwnerReferences(o.GetOwnerReferences())
		return cl.Update(ctx, existing)
	}
	return fmt.Errorf("unsupported isolation object %T", obj)
}
