package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
)

// SessionReconciler turns Session objects into pods and reports their phase.
type SessionReconciler struct {
	client.Client
	Namespace string
	Options   PodOptions
	// Decorate lets later milestones add objects (network policies) per session.
	Decorate func(ctx context.Context, sess *jugv1.Session, st *jugv1.ServerType) error
}

// SetupWithManager registers the reconciler.
func (r *SessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jugv1.Session{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}

// Reconcile implements the state machine Pending → Starting → Ready → Terminating → Gone.
func (r *SessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	var sess jugv1.Session
	if err := r.Get(ctx, req.NamespacedName, &sess); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion / termination.
	if !sess.DeletionTimestamp.IsZero() || sess.Spec.DesiredPhase == jugv1.PhaseTerminating {
		if sess.Status.Phase != jugv1.PhaseTerminating {
			sess.Status.Phase = jugv1.PhaseTerminating
			_ = r.Status().Update(ctx, &sess)
		}
		if err := r.cleanup(ctx, &sess); err != nil {
			return ctrl.Result{}, err
		}
		if sess.DeletionTimestamp.IsZero() {
			// Reaper-initiated: delete the object itself; the finalizer path runs next.
			return ctrl.Result{}, client.IgnoreNotFound(r.Delete(ctx, &sess))
		}
		if controllerutil.RemoveFinalizer(&sess, jugv1.FinalizerSession) {
			return ctrl.Result{}, r.Update(ctx, &sess)
		}
		return ctrl.Result{}, nil
	}
	if controllerutil.AddFinalizer(&sess, jugv1.FinalizerSession) {
		return ctrl.Result{}, r.Update(ctx, &sess)
	}

	var st jugv1.ServerType
	if err := r.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: sess.Spec.ServerType}, &st); err != nil {
		return r.fail(ctx, &sess, fmt.Sprintf("server type %s not found", sess.Spec.ServerType))
	}
	if err := r.ensureWrapperConfigMap(ctx, &st); err != nil {
		return ctrl.Result{}, err
	}
	if r.Decorate != nil {
		if err := r.Decorate(ctx, &sess, &st); err != nil {
			return ctrl.Result{}, err
		}
	}

	var pod corev1.Pod
	err := r.Get(ctx, client.ObjectKey{Namespace: sess.Namespace, Name: sess.Name}, &pod)
	switch {
	case apierrors.IsNotFound(err):
		if sess.Status.Phase == jugv1.PhaseReady || sess.Status.Phase == jugv1.PhaseIdle {
			// Pod vanished (evicted, node lost): the session is over.
			return r.fail(ctx, &sess, "pod disappeared")
		}
		newPod := BuildPod(&sess, &st, r.Options)
		if err := controllerutil.SetControllerReference(&sess, newPod, r.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, newPod); err != nil && !apierrors.IsAlreadyExists(err) {
			return r.fail(ctx, &sess, "create pod: "+err.Error())
		}
		now := metav1.Now()
		sess.Status.Phase = jugv1.PhaseStarting
		sess.Status.PodName = newPod.Name
		sess.Status.StartedAt = &now
		sess.Status.ExpiresAt = &metav1.Time{Time: now.Add(st.Spec.MaxSessionAge.Duration)}
		log.Info("session pod created", "pod", newPod.Name, "serverType", st.Name)
		return ctrl.Result{RequeueAfter: time.Second}, r.Status().Update(ctx, &sess)
	case err != nil:
		return ctrl.Result{}, err
	}

	// Map pod state to session phase.
	switch pod.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		return r.fail(ctx, &sess, "pod "+string(pod.Status.Phase)+": "+pod.Status.Message)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "ImagePullBackOff" || cs.State.Waiting.Reason == "ErrImagePull" || cs.State.Waiting.Reason == "CrashLoopBackOff") {
			return r.fail(ctx, &sess, cs.State.Waiting.Reason+": "+cs.State.Waiting.Message)
		}
	}
	ready := false
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if ready && pod.Status.PodIP != "" {
		if sess.Status.Phase != jugv1.PhaseReady {
			now := metav1.Now()
			sess.Status.Phase = jugv1.PhaseReady
			sess.Status.PodIP = pod.Status.PodIP
			sess.Status.Endpoint = fmt.Sprintf("http://%s:%d", pod.Status.PodIP, st.Spec.WrapperPort)
			sess.Status.ReadyAt = &now
			sess.Status.Message = ""
			log.Info("session ready", "pod", pod.Name, "endpoint", sess.Status.Endpoint)
			return ctrl.Result{}, r.Status().Update(ctx, &sess)
		}
		return ctrl.Result{}, nil
	}
	if sess.Status.Phase != jugv1.PhaseStarting {
		sess.Status.Phase = jugv1.PhaseStarting
		return ctrl.Result{RequeueAfter: time.Second}, r.Status().Update(ctx, &sess)
	}
	return ctrl.Result{RequeueAfter: time.Second}, nil
}

func (r *SessionReconciler) fail(ctx context.Context, sess *jugv1.Session, msg string) (ctrl.Result, error) {
	sess.Status.Phase = jugv1.PhaseFailed
	sess.Status.Message = msg
	ctrl.LoggerFrom(ctx).Info("session failed", "session", sess.Name, "reason", msg)
	return ctrl.Result{}, r.Status().Update(ctx, sess)
}

// cleanup deletes the pod and the per-pod secret. Network policies are owned
// by the Session via owner references and are garbage collected.
func (r *SessionReconciler) cleanup(ctx context.Context, sess *jugv1.Session) error {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: sess.Namespace, Name: sess.Name}}
	if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if sess.Spec.PodTokenSecretName != "" {
		sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: sess.Namespace, Name: sess.Spec.PodTokenSecretName}}
		if err := r.Delete(ctx, sec); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// ensureWrapperConfigMap publishes the rendered wrapper config for a server type.
func (r *SessionReconciler) ensureWrapperConfigMap(ctx context.Context, st *jugv1.ServerType) error {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: r.Namespace, Name: st.Name + "-wrapper"}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Labels = map[string]string{jugv1.LabelManagedBy: jugv1.ManagedByValue, jugv1.LabelServerType: st.Name}
		cm.Data = map[string]string{"wrapper.json": st.Spec.WrapperConfigJSON}
		return nil
	})
	return err
}
