package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServerTypeSpec is the fully defaulted rendering of one servers[] entry of
// juggernaut.yaml. ConfigHash identifies the config version it came from.
type ServerTypeSpec struct {
	ConfigHash       string                      `json:"configHash"`
	Description      string                      `json:"description,omitempty"`
	Image            string                      `json:"image"`
	Transport        string                      `json:"transport"`
	Command          []string                    `json:"command,omitempty"`
	Args             []string                    `json:"args,omitempty"`
	Env              map[string]string           `json:"env,omitempty"`
	HTTPPort         int32                       `json:"httpPort,omitempty"`
	HTTPPath         string                      `json:"httpPath,omitempty"`
	WrapperPort      int32                       `json:"wrapperPort"`
	ReadinessPort    int32                       `json:"readinessPort"`
	TokenMode        string                      `json:"tokenMode"`
	TokenEnv         string                      `json:"tokenEnv,omitempty"`
	TokenFile        string                      `json:"tokenFile,omitempty"`
	TokenHeader      string                      `json:"tokenHeader,omitempty"`
	Egress           []EgressRule                `json:"egress,omitempty"`
	Resources        corev1.ResourceRequirements `json:"resources,omitempty"`
	RuntimeClassName string                      `json:"runtimeClassName,omitempty"`
	IdleTimeout      metav1.Duration             `json:"idleTimeout"`
	MaxSessionAge    metav1.Duration             `json:"maxSessionAge"`
	MaxPods          int32                       `json:"maxPods"`
	Security         SecuritySpec                `json:"security,omitempty"`
	// WrapperConfigJSON is the rendered wrapper configuration mounted into the pod.
	WrapperConfigJSON string `json:"wrapperConfigJSON"`
}

// EgressRule is one allowed destination.
type EgressRule struct {
	Host     string  `json:"host"`
	Ports    []int32 `json:"ports"`
	Protocol string  `json:"protocol"`
}

// SecuritySpec carries per-server security overrides.
type SecuritySpec struct {
	WritableTmp            bool     `json:"writableTmp,omitempty"`
	RunAsUser              int64    `json:"runAsUser"`
	RunAsGroup             int64    `json:"runAsGroup"`
	ReadOnlyRootFilesystem bool     `json:"readOnlyRootFilesystem"`
	ExtraWritablePaths     []string `json:"extraWritablePaths,omitempty"`
}

// ServerTypeStatus reports aggregate pod counts.
type ServerTypeStatus struct {
	ActivePods int32 `json:"activePods"`
}

// ServerType is a rendered server definition.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=jst
// +kubebuilder:printcolumn:name="Transport",type=string,JSONPath=`.spec.transport`
// +kubebuilder:printcolumn:name="Token",type=string,JSONPath=`.spec.tokenMode`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activePods`
type ServerType struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServerTypeSpec   `json:"spec,omitempty"`
	Status ServerTypeStatus `json:"status,omitempty"`
}

// ServerTypeList is a list of ServerType.
//
// +kubebuilder:object:root=true
type ServerTypeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServerType `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServerType{}, &ServerTypeList{})
}
