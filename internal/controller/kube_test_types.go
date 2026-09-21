package controller

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// Aliases used by tests so the fake KubeAccess reads cleanly.
type (
	restConfig = rest.Config
	schemaGVK  = schema.GroupVersionKind
)
