package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase is the session pod lifecycle state (docs/DESIGN.md §4).
type Phase string

const (
	PhasePending     Phase = "Pending"
	PhaseStarting    Phase = "Starting"
	PhaseReady       Phase = "Ready"
	PhaseIdle        Phase = "Idle"
	PhaseTerminating Phase = "Terminating"
	PhaseFailed      Phase = "Failed"
	PhaseGone        Phase = "Gone"
)

// SessionSpec is created by the gateway when a user first needs a server type.
type SessionSpec struct {
	// Subject is the IdP subject of the owning user.
	Subject string `json:"subject"`
	// UserHash is a short hash of the subject used in labels and names.
	UserHash string `json:"userHash"`
	// ServerType names the ServerType this session runs.
	ServerType string `json:"serverType"`
	// ConfigHash pins the config version the pod is rendered from.
	ConfigHash string `json:"configHash"`
	// DesiredPhase is set to Terminating by the reaper or an admin.
	DesiredPhase Phase `json:"desiredPhase,omitempty"`
	// PodTokenSecretName is the Secret holding the per-pod shared secret. The
	// gateway creates it together with the Session; the plaintext never appears here.
	PodTokenSecretName string `json:"podTokenSecretName"`
}

// SessionStatus is written by the controller.
type SessionStatus struct {
	Phase      Phase              `json:"phase,omitempty"`
	PodName    string             `json:"podName,omitempty"`
	PodIP      string             `json:"podIP,omitempty"`
	Endpoint   string             `json:"endpoint,omitempty"`
	Message    string             `json:"message,omitempty"`
	StartedAt  *metav1.Time       `json:"startedAt,omitempty"`
	ReadyAt    *metav1.Time       `json:"readyAt,omitempty"`
	ExpiresAt  *metav1.Time       `json:"expiresAt,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Session is one session pod for (user, server type).
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=jsess
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.serverType`
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.userHash`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Session struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SessionSpec   `json:"spec,omitempty"`
	Status SessionStatus `json:"status,omitempty"`
}

// SessionList is a list of Session.
//
// +kubebuilder:object:root=true
type SessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Session `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Session{}, &SessionList{})
}

// Well-known labels on session pods and objects.
const (
	LabelSession    = "juggernaut.io/session"
	LabelSessionID  = "juggernaut.io/session-id"
	LabelServerType = "juggernaut.io/server-type"
	LabelUserHash   = "juggernaut.io/user-hash"
	LabelConfigHash = "juggernaut.io/config-hash"
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	ManagedByValue  = "juggernaut-controller"
	// FinalizerSession makes sure pods and secrets are gone before the Session is.
	FinalizerSession = "juggernaut.io/session-cleanup"
)
