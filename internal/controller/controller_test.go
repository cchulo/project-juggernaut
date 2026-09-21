package controller

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	egressnone "github.com/cchulo/project-juggernaut/internal/adapters/egress/none"
	egressproxy "github.com/cchulo/project-juggernaut/internal/adapters/egress/proxy"
	"github.com/cchulo/project-juggernaut/internal/adapters/routing/memory"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

const ns = "juggernaut-sessions"

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = jugv1.AddToScheme(s)
	return s
}

func kubeCfg(t *testing.T, extra string) *config.Loaded {
	t.Helper()
	doc := strings.Replace(contracttest.LaptopConfig, "runtime: { kind: local }", "runtime: { kind: kube }\n  redis: { address: \"r:6379\" }", 1)
	doc = strings.Replace(doc, "network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }",
		"network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false }"+extra+" }", 1)
	l, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func newReconciler(t *testing.T, cl client.Client, egress contracts.EgressEnforcer) *SessionReconciler {
	t.Helper()
	return &SessionReconciler{Client: cl, Namespace: ns, Egress: egress, Options: PodOptions{WrapperImage: "wrapper:test"}}
}

func seed(t *testing.T, l *config.Loaded) (*jugv1.ServerType, *jugv1.Session, *corev1.Secret) {
	t.Helper()
	st, err := RenderServerType(l, l.Config.Server("jira"), ns)
	if err != nil {
		t.Fatal(err)
	}
	sess := &jugv1.Session{ObjectMeta: metav1.ObjectMeta{Name: "jira-abcd1234", Namespace: ns},
		Spec: jugv1.SessionSpec{Subject: "alice", UserHash: "abcd1234", ServerType: "jira", ConfigHash: l.Hash, PodTokenSecretName: "jira-abcd1234-pod-token"}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: sess.Spec.PodTokenSecretName, Namespace: ns}, Data: map[string][]byte{"pod-token": []byte("tok")}}
	return st, sess, sec
}

func reconcile(t *testing.T, r *SessionReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return res
}

func TestRenderServerType(t *testing.T) {
	l := kubeCfg(t, "")
	st, err := RenderServerType(l, l.Config.Server("jira"), ns)
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.ConfigHash != l.Hash || st.Spec.WrapperPort != 9000 || st.Spec.TokenMode != "none" || !strings.Contains(st.Spec.WrapperConfigJSON, `"serverName":"jira"`) {
		t.Fatalf("servertype: %+v", st.Spec)
	}
	if st.Spec.Resources.Limits.Memory().String() != "512Mi" {
		t.Fatalf("resources: %v", st.Spec.Resources)
	}
}

func TestBuildPodIsRestricted(t *testing.T) {
	l := kubeCfg(t, "")
	st, sess, _ := seed(t, l)
	pod := BuildPod(sess, st, PodOptions{WrapperImage: "w:1", Env: map[string]string{"HTTPS_PROXY": "http://p:3128"}, DisableDNS: true})
	c := pod.Spec.Containers[0]
	sc := c.SecurityContext
	if *pod.Spec.AutomountServiceAccountToken || !*sc.RunAsNonRoot || !*sc.ReadOnlyRootFilesystem || *sc.AllowPrivilegeEscalation ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("security context not restricted: %+v", sc)
	}
	if pod.Spec.DNSPolicy != corev1.DNSNone || len(pod.Spec.InitContainers) != 1 || c.Command[0] != "/opt/juggernaut/juggernaut-wrapper" {
		t.Fatalf("proxy mode / wrapper install: dns=%s init=%d cmd=%v", pod.Spec.DNSPolicy, len(pod.Spec.InitContainers), c.Command)
	}
	found := false
	for _, e := range c.Env {
		if e.Name == "HTTPS_PROXY" {
			found = true
		}
	}
	if !found || pod.Labels[jugv1.LabelUserHash] != "abcd1234" || pod.Labels[jugv1.LabelSessionID] != sess.Name {
		t.Fatalf("env/labels: %v %v", c.Env, pod.Labels)
	}
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil && v.Secret.SecretName != sess.Spec.PodTokenSecretName {
			t.Fatalf("unexpected secret mount %s", v.Secret.SecretName)
		}
	}
}

func TestReconcileLifecycle(t *testing.T) {
	l := kubeCfg(t, "")
	st, sess, sec := seed(t, l)
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(st, sess, sec).WithStatusSubresource(&jugv1.Session{}).Build()
	egress, _ := egressnone.New(&core.Context{Config: config.NewStoreFrom(l, slog.Default()), Log: slog.Default()})
	r := newReconciler(t, cl, egress)

	reconcile(t, r, sess.Name) // adds finalizer
	reconcile(t, r, sess.Name) // creates pod
	var pod corev1.Pod
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &pod); err != nil {
		t.Fatalf("pod must be created: %v", err)
	}
	var np networkingv1.NetworkPolicy
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "session-" + sess.Name}, &np); err != nil {
		t.Fatalf("network policy must be created before the pod: %v", err)
	}
	if len(np.OwnerReferences) != 1 || np.OwnerReferences[0].Name != sess.Name {
		t.Fatal("policy must be owned by the session")
	}
	var got jugv1.Session
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Status.Phase != jugv1.PhaseStarting || got.Status.ExpiresAt == nil {
		t.Fatalf("phase after create: %+v", got.Status)
	}

	// The pod becomes Ready with an IP.
	pod.Status.PodIP = "10.0.0.7"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	_ = cl.Status().Update(context.Background(), &pod)
	reconcile(t, r, sess.Name)
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Status.Phase != jugv1.PhaseReady || got.Status.Endpoint != "http://10.0.0.7:9000" {
		t.Fatalf("phase after ready: %+v", got.Status)
	}

	// The reaper asks for termination.
	got.Spec.DesiredPhase = jugv1.PhaseTerminating
	_ = cl.Update(context.Background(), &got)
	reconcile(t, r, sess.Name) // marks Terminating, cleans up, deletes the Session
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &pod); err == nil {
		t.Fatal("pod must be deleted on termination")
	}
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sec.Name}, &corev1.Secret{}); err == nil {
		t.Fatal("pod token secret must be deleted on termination")
	}
}

func TestReconcileFailsOnImagePullAndMissingType(t *testing.T) {
	l := kubeCfg(t, "")
	st, sess, sec := seed(t, l)
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(st, sess, sec).WithStatusSubresource(&jugv1.Session{}).Build()
	egress, _ := egressnone.New(&core.Context{Config: config.NewStoreFrom(l, slog.Default()), Log: slog.Default()})
	r := newReconciler(t, cl, egress)
	reconcile(t, r, sess.Name)
	reconcile(t, r, sess.Name)
	var pod corev1.Pod
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &pod)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "wrapper", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "no such image"}}}}
	_ = cl.Status().Update(context.Background(), &pod)
	reconcile(t, r, sess.Name)
	var got jugv1.Session
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Status.Phase != jugv1.PhaseFailed || !strings.Contains(got.Status.Message, "ImagePullBackOff") {
		t.Fatalf("image pull failure must fail the session: %+v", got.Status)
	}

	orphan := &jugv1.Session{ObjectMeta: metav1.ObjectMeta{Name: "ghost-1", Namespace: ns}, Spec: jugv1.SessionSpec{Subject: "x", UserHash: "1", ServerType: "ghost", PodTokenSecretName: "s"}}
	_ = cl.Create(context.Background(), orphan)
	reconcile(t, r, orphan.Name)
	reconcile(t, r, orphan.Name)
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: orphan.Name}, &got)
	if got.Status.Phase != jugv1.PhaseFailed {
		t.Fatalf("unknown server type must fail the session: %+v", got.Status)
	}
}

func TestProxyModePublishesAllowlist(t *testing.T) {
	l := kubeCfg(t, ", proxy: { address: juggernaut-egress.juggernaut-system.svc:3128 }")
	l.Config.Network.EgressEnforcer = config.EgressProxy
	l.Config.Servers[0].Egress = []config.Egress{{Host: "api.atlassian.com", Ports: []int{443}, Protocol: "TCP"}}
	st, sess, sec := seed(t, l)
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(st, sess, sec).WithStatusSubresource(&jugv1.Session{}).Build()
	kube := &fakeKube{cl: cl}
	egress, err := egressproxy.New(&core.Context{Config: config.NewStoreFrom(l, slog.Default()), Log: slog.Default(), Kube: kube})
	if err != nil {
		t.Fatal(err)
	}
	r := newReconciler(t, cl, egress)
	if err := r.EnsureNamespaceObjects(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "default-deny-all"}, &networkingv1.NetworkPolicy{}); err != nil {
		t.Fatal("namespace default-deny must exist")
	}
	reconcile(t, r, sess.Name)
	reconcile(t, r, sess.Name)
	var pod corev1.Pod
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &pod)
	pod.Status.PodIP = "10.0.0.9"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	_ = cl.Status().Update(context.Background(), &pod)
	reconcile(t, r, sess.Name)
	var cm corev1.ConfigMap
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "juggernaut-system", Name: "juggernaut-egress-allowlist"}, &cm); err != nil {
		t.Fatalf("allowlist configmap: %v", err)
	}
	if !strings.Contains(cm.Data["allowlist.json"], `"10.0.0.9"`) || !strings.Contains(cm.Data["allowlist.json"], "api.atlassian.com:443") {
		t.Fatalf("allowlist content: %s", cm.Data["allowlist.json"])
	}
	var got jugv1.Session
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	got.Spec.DesiredPhase = jugv1.PhaseTerminating
	_ = cl.Update(context.Background(), &got)
	reconcile(t, r, sess.Name)
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: "juggernaut-system", Name: "juggernaut-egress-allowlist"}, &cm)
	if strings.Contains(cm.Data["allowlist.json"], "10.0.0.9") {
		t.Fatal("allowlist entry must be removed on cleanup")
	}
}

func TestMTLSIssuesPodCertificate(t *testing.T) {
	l := kubeCfg(t, ", podAuth: mtls")
	st, sess, sec := seed(t, l)
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(st, sess, sec).WithStatusSubresource(&jugv1.Session{}).Build()
	pk := &PodPKI{Client: cl, SystemNamespace: "juggernaut-system", Cfg: *l.Config.Network.MTLS}
	if err := pk.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	var gw corev1.Secret
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "juggernaut-system", Name: "juggernaut-gateway-client-tls"}, &gw); err != nil || len(gw.Data["tls.crt"]) == 0 {
		t.Fatalf("gateway client cert: %v", err)
	}
	egress, _ := egressnone.New(&core.Context{Config: config.NewStoreFrom(l, slog.Default()), Log: slog.Default()})
	r := newReconciler(t, cl, egress)
	r.PKI = pk
	reconcile(t, r, sess.Name)
	reconcile(t, r, sess.Name)
	var got corev1.Secret
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sec.Name}, &got)
	if len(got.Data["tls.crt"]) == 0 || len(got.Data["tls.key"]) == 0 || len(got.Data["ca.crt"]) == 0 {
		t.Fatal("pod certificate must be issued into the pod secret before the pod starts")
	}
	var cm corev1.ConfigMap
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "jira-wrapper"}, &cm)
	if !strings.Contains(cm.Data["wrapper.json"], `"gatewayURI":"spiffe://juggernaut/gateway"`) {
		t.Fatalf("wrapper config must carry TLS settings: %s", cm.Data["wrapper.json"])
	}
	var pod corev1.Pod
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &pod)
	pod.Status.PodIP = "10.0.0.3"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	_ = cl.Status().Update(context.Background(), &pod)
	reconcile(t, r, sess.Name)
	var s jugv1.Session
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &s)
	if !strings.HasPrefix(s.Status.Endpoint, "https://") {
		t.Fatalf("mtls endpoints must be https: %s", s.Status.Endpoint)
	}
}

func TestConfigSyncerRendersAndPrunes(t *testing.T) {
	l := kubeCfg(t, "")
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).Build()
	syncer := &ConfigSyncer{Client: cl, Namespace: ns, Log: slog.Default()}
	if err := syncer.Sync(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	var list jugv1.ServerTypeList
	_ = cl.List(context.Background(), &list, client.InNamespace(ns))
	if len(list.Items) != 2 {
		t.Fatalf("expected 2 server types, got %d", len(list.Items))
	}
	l.Config.Servers = l.Config.Servers[:1]
	l.Hash = "newhash"
	if err := syncer.Sync(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	_ = cl.List(context.Background(), &list, client.InNamespace(ns))
	if len(list.Items) != 1 || list.Items[0].Spec.ConfigHash != "newhash" {
		t.Fatalf("prune/update: %+v", list.Items)
	}
}

func TestReaper(t *testing.T) {
	l := kubeCfg(t, "")
	st, sess, sec := seed(t, l)
	st.Spec.IdleTimeout = metav1.Duration{Duration: time.Minute}
	st.Spec.MaxSessionAge = metav1.Duration{Duration: time.Hour}
	sess.Status.Phase = jugv1.PhaseReady
	sess.CreationTimestamp = metav1.NewTime(time.Now().Add(-10 * time.Minute))
	cl := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(st, sess, sec).WithStatusSubresource(&jugv1.Session{}).Build()
	table := memory.NewMemory()
	reaper := &Reaper{Client: cl, Table: table, Namespace: ns, Log: slog.Default()}
	var reasons []string
	reaper.OnTerminate = func(r string) { reasons = append(reasons, r) }

	// Active recently → kept.
	_ = table.Touch(context.Background(), sess.Name, time.Now())
	if err := reaper.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got jugv1.Session
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Spec.DesiredPhase == jugv1.PhaseTerminating {
		t.Fatal("recently active session must not be reaped")
	}
	// Idle but in flight → marked Idle, not terminated.
	_ = table.Touch(context.Background(), sess.Name, time.Now().Add(-5*time.Minute))
	_, _ = table.InFlight(context.Background(), sess.Name, +1)
	_ = reaper.sweep(context.Background())
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Spec.DesiredPhase == jugv1.PhaseTerminating || got.Status.Phase != jugv1.PhaseIdle {
		t.Fatalf("in-flight work must protect an idle pod: %+v", got.Status)
	}
	// Idle and nothing in flight → terminated.
	_, _ = table.InFlight(context.Background(), sess.Name, -1)
	_ = reaper.sweep(context.Background())
	_ = cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sess.Name}, &got)
	if got.Spec.DesiredPhase != jugv1.PhaseTerminating || len(reasons) != 1 || reasons[0] != "idle" {
		t.Fatalf("idle session must be terminated: %+v %v", got.Spec, reasons)
	}
}

// fakeKube satisfies core.KubeAccess for adapters that need a client.
type fakeKube struct{ cl client.Client }

func (f *fakeKube) Client() client.Client   { return f.cl }
func (f *fakeKube) RESTConfig() *restConfig { return nil }
func (f *fakeKube) HasKind(schemaGVK) bool  { return false }
