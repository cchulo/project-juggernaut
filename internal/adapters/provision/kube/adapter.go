// Package kube is the Kubernetes provisioner: the gateway expresses "I need a
// pod for (user, server type)" as a Session object plus a per-pod Secret; the
// controller turns that into a Pod. The gateway itself needs no rights on Pods
// or Secrets beyond creating the one Secret, which keeps its RBAC small.
package kube

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "kube"

func init() { registry.Provision.Register(Type, New) }

// New builds the provisioner from the in-cluster (or kubeconfig) connection in the context.
func New(ctx *core.Context) (contracts.Provisioner, error) {
	if ctx.Kube == nil {
		return nil, fmt.Errorf("kube provisioner: no Kubernetes connection in context")
	}
	return NewBackend(ctx.Kube.RESTConfig(), ctx.Kube.Client(), ctx.Cfg().Network.SessionsNamespace)
}

// Backend implements contracts.Provisioner on top of Session objects.
type Backend struct {
	cl        client.Client
	clientset kubernetes.Interface
	namespace string
}

// NewBackend builds the backend for the sessions namespace.
func NewBackend(cfg *rest.Config, cl client.Client, namespace string) (*Backend, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Backend{cl: cl, clientset: cs, namespace: namespace}, nil
}

// Ensure creates the Session (and pod-token Secret) if missing.
func (b *Backend) Ensure(ctx context.Context, spec contracts.SpawnSpec) (*contracts.PodStatus, error) {
	name := spec.Key.Name()
	var existing jugv1.Session
	err := b.cl.Get(ctx, client.ObjectKey{Namespace: b.namespace, Name: name}, &existing)
	if err == nil {
		return statusOf(&existing), nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	labels := map[string]string{
		jugv1.LabelSession:    "true",
		jugv1.LabelSessionID:  name,
		jugv1.LabelServerType: spec.Key.ServerType,
		jugv1.LabelUserHash:   core.UserHash(spec.Key.Subject),
		jugv1.LabelConfigHash: spec.ConfigHash,
		jugv1.LabelManagedBy:  jugv1.ManagedByValue,
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-pod-token", Namespace: b.namespace, Labels: labels},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{"pod-token": spec.PodToken},
	}
	if err := b.cl.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create pod token secret: %w", err)
	}
	sess := &jugv1.Session{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: b.namespace, Labels: labels},
		Spec: jugv1.SessionSpec{
			Subject:            spec.Key.Subject,
			UserHash:           core.UserHash(spec.Key.Subject),
			ServerType:         spec.Key.ServerType,
			ConfigHash:         spec.ConfigHash,
			PodTokenSecretName: secret.Name,
		},
	}
	if err := b.cl.Create(ctx, sess); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &contracts.PodStatus{Name: name, Phase: contracts.PhasePending, Started: time.Now()}, nil
}

// Status reads the Session status the controller maintains.
func (b *Backend) Status(ctx context.Context, key core.PodKey) (*contracts.PodStatus, error) {
	var s jugv1.Session
	if err := b.cl.Get(ctx, client.ObjectKey{Namespace: b.namespace, Name: key.Name()}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, contracts.ErrNotFound
		}
		return nil, err
	}
	return statusOf(&s), nil
}

func statusOf(s *jugv1.Session) *contracts.PodStatus {
	st := &contracts.PodStatus{Name: s.Name, Phase: contracts.Phase(s.Status.Phase), Endpoint: s.Status.Endpoint, Message: s.Status.Message}
	if st.Phase == "" {
		st.Phase = contracts.PhasePending
	}
	if s.Status.StartedAt != nil {
		st.Started = s.Status.StartedAt.Time
	}
	return st
}

// Release deletes the Session; the controller's finalizer removes pod and secret.
func (b *Backend) Release(ctx context.Context, key core.PodKey) error {
	s := &jugv1.Session{ObjectMeta: metav1.ObjectMeta{Namespace: b.namespace, Name: key.Name()}}
	if err := b.cl.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// List returns every Session in the namespace.
func (b *Backend) List(ctx context.Context) ([]contracts.PodStatus, error) {
	var list jugv1.SessionList
	if err := b.cl.List(ctx, &list, client.InNamespace(b.namespace)); err != nil {
		return nil, err
	}
	out := make([]contracts.PodStatus, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, *statusOf(&list.Items[i]))
	}
	return out, nil
}

// Logs tails the wrapper container's logs with tokens redacted a second time.
func (b *Backend) Logs(ctx context.Context, key core.PodKey, tailLines int) (string, error) {
	tl := int64(tailLines)
	req := b.clientset.CoreV1().Pods(b.namespace).GetLogs(key.Name(), &corev1.PodLogOptions{Container: "wrapper", TailLines: &tl})
	rc, err := req.Stream(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", contracts.ErrNotFound
		}
		return "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(data), "Bearer ", "Bearer [REDACTED] "), nil
}

var _ contracts.Provisioner = (*Backend)(nil)
