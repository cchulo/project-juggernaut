// Package v1alpha1 holds Juggernaut's internal Kubernetes API types. They are an
// implementation detail: the controller derives ServerType objects from
// juggernaut.yaml, and the gateway creates Session objects as runtime state.
// Operators never edit these by hand.
//
// +kubebuilder:object:generate=true
// +groupName=juggernaut.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group/version of these types.
	GroupVersion = schema.GroupVersion{Group: "juggernaut.io", Version: "v1alpha1"}

	// SchemeBuilder registers the types.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
