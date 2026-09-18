package controller

import (
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
)

// PodOptions carries cluster-level knobs from juggernaut.yaml's network section.
type PodOptions struct {
	// WrapperImage provides /juggernaut-wrapper via an init container when the
	// server image does not bundle it.
	WrapperImage string
	// EgressProxy, when set, is exported as HTTPS_PROXY and DNS is disabled (proxy mode).
	EgressProxy string
	// ExtraEnv is appended to the wrapper container (e.g. NO_PROXY).
	ExtraEnv []corev1.EnvVar
}

// BuildPod renders the session pod. Defaults satisfy Pod Security Admission
// "restricted": non-root, RO rootfs, no capabilities, seccomp RuntimeDefault,
// no service account token, no privilege escalation.
func BuildPod(sess *jugv1.Session, st *jugv1.ServerType, opts PodOptions) *corev1.Pod {
	labels := map[string]string{
		jugv1.LabelSession:    "true",
		jugv1.LabelSessionID:  sess.Name,
		jugv1.LabelServerType: sess.Spec.ServerType,
		jugv1.LabelUserHash:   sess.Spec.UserHash,
		jugv1.LabelConfigHash: sess.Spec.ConfigHash,
		jugv1.LabelManagedBy:  jugv1.ManagedByValue,
	}
	sec := st.Spec.Security
	volumes := []corev1.Volume{
		{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptr.To(mustQuantity("1Mi"))}}},
		{Name: "pod-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: sess.Spec.PodTokenSecretName, DefaultMode: ptr.To[int32](0o400)}}},
		{Name: "wrapper-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: st.Name + "-wrapper"}}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "run", MountPath: "/run/juggernaut"},
		{Name: "pod-token", MountPath: "/run/juggernaut-secret", ReadOnly: true},
		{Name: "wrapper-config", MountPath: "/etc/juggernaut", ReadOnly: true},
	}
	if sec.WritableTmp {
		volumes = append(volumes, corev1.Volume{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "tmp", MountPath: "/tmp"})
	}
	for i, p := range sec.ExtraWritablePaths {
		name := fmt.Sprintf("writable-%d", i)
		volumes = append(volumes, corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		mounts = append(mounts, corev1.VolumeMount{Name: name, MountPath: path.Clean(p)})
	}

	env := []corev1.EnvVar{
		{Name: "JUGGERNAUT_WRAPPER_CONFIG", Value: "/etc/juggernaut/wrapper.json"},
		{Name: "JUGGERNAUT_POD_NAME", Value: sess.Name},
	}
	for k, v := range st.Spec.Env {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}
	if opts.EgressProxy != "" {
		env = append(env,
			corev1.EnvVar{Name: "HTTPS_PROXY", Value: "http://" + opts.EgressProxy},
			corev1.EnvVar{Name: "HTTP_PROXY", Value: "http://" + opts.EgressProxy},
			corev1.EnvVar{Name: "NO_PROXY", Value: "127.0.0.1,localhost"},
		)
	}
	env = append(env, opts.ExtraEnv...)

	containerSec := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(sec.ReadOnlyRootFilesystem),
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To(sec.RunAsUser),
		RunAsGroup:               ptr.To(sec.RunAsGroup),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}

	wrapperCmd := []string{"/juggernaut-wrapper"}
	var initContainers []corev1.Container
	if opts.WrapperImage != "" {
		volumes = append(volumes, corev1.Volume{Name: "wrapper-bin", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "wrapper-bin", MountPath: "/opt/juggernaut", ReadOnly: true})
		initContainers = append(initContainers, corev1.Container{
			Name: "install-wrapper", Image: opts.WrapperImage,
			Command:         []string{"/juggernaut-wrapper", "--install", "/opt/juggernaut/juggernaut-wrapper"},
			VolumeMounts:    []corev1.VolumeMount{{Name: "wrapper-bin", MountPath: "/opt/juggernaut"}},
			SecurityContext: containerSec,
		})
		wrapperCmd = []string{"/opt/juggernaut/juggernaut-wrapper"}
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: sess.Name, Namespace: sess.Namespace, Labels: labels,
			Annotations: map[string]string{"juggernaut.io/subject-hash": sess.Spec.UserHash},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  ptr.To(false),
			EnableServiceLinks:            ptr.To(false),
			TerminationGracePeriodSeconds: ptr.To[int64](30),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				RunAsUser:      ptr.To(sec.RunAsUser),
				RunAsGroup:     ptr.To(sec.RunAsGroup),
				FSGroup:        ptr.To(sec.RunAsGroup),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: initContainers,
			Containers: []corev1.Container{{
				Name:            "wrapper",
				Image:           st.Spec.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         wrapperCmd,
				Args:            []string{"--config", "/etc/juggernaut/wrapper.json"},
				Env:             env,
				Ports: []corev1.ContainerPort{
					{Name: "mcp", ContainerPort: st.Spec.WrapperPort, Protocol: corev1.ProtocolTCP},
					{Name: "probes", ContainerPort: st.Spec.ReadinessPort, Protocol: corev1.ProtocolTCP},
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromString("probes")}},
					PeriodSeconds:    1,
					FailureThreshold: 3,
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("probes")}},
					PeriodSeconds:    10,
					FailureThreshold: 3,
				},
				Resources:       st.Spec.Resources,
				SecurityContext: containerSec,
				VolumeMounts:    mounts,
			}},
			Volumes: volumes,
		},
	}
	if st.Spec.RuntimeClassName != "" {
		pod.Spec.RuntimeClassName = ptr.To(st.Spec.RuntimeClassName)
	}
	if opts.EgressProxy != "" {
		// Proxy mode: no resolver at all. The proxy resolves allowlisted names.
		pod.Spec.DNSPolicy = corev1.DNSNone
		pod.Spec.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{}}
	}
	return pod
}

func mustQuantity(s string) resourceQuantity {
	q, err := parseQuantity(s)
	if err != nil {
		panic(err)
	}
	return q
}
