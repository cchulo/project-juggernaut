// Package config loads, validates and hot-reloads juggernaut.yaml, the single
// source of truth for a Juggernaut deployment. The Go types mirror
// schemas/juggernaut.schema.json; the schema is authoritative for structure,
// Validate() adds the semantic checks the schema cannot express.
package config

import "time"

// APIVersion is the only config version this build understands.
const APIVersion = "juggernaut.io/v1alpha1"

// Config is the root of juggernaut.yaml.
type Config struct {
	APIVersion    string        `json:"apiVersion"`
	Kind          string        `json:"kind"`
	Identity      Identity      `json:"identity"`
	Gateway       Gateway       `json:"gateway"`
	Network       Network       `json:"network"`
	Servers       []Server      `json:"servers"`
	Authorization Authorization `json:"authorization"`
}

// Duration is a Go duration in YAML ("15m", "1h30m").
type Duration struct{ time.Duration }

// SecretRef says where a secret value comes from. Exactly one field is set.
type SecretRef struct {
	Env  string `json:"env,omitempty"`
	File string `json:"file,omitempty"`
}

// Listener is a bind address with optional TLS.
type Listener struct {
	Address string       `json:"address"`
	TLS     *ListenerTLS `json:"tls,omitempty"`
}

// ListenerTLS is a certificate pair on disk; ClientCAFile turns on mutual TLS.
type ListenerTLS struct {
	CertFile     string `json:"certFile"`
	KeyFile      string `json:"keyFile"`
	ClientCAFile string `json:"clientCAFile,omitempty"`
}

// Identity is the IdP connection and token brokering configuration.
type Identity struct {
	// Type selects the identity adapter (bearer_jwt, bearer_introspect). Default:
	// bearer_introspect when introspection.enabled, else bearer_jwt.
	Type     string         `json:"type,omitempty"`
	Options  map[string]any `json:"options,omitempty"`
	Provider string         `json:"provider,omitempty"`
	// Issuer and Audience are required for bearer_* types; unused by none and static.
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	// Principal is who every request is under identity.type none.
	Principal *PrincipalSeed `json:"principal,omitempty"`
	// AllowRemote (type none) lifts the loopback rule; every request then needs the bearer named by StaticTokenEnv.
	AllowRemote    bool   `json:"allowRemote,omitempty"`
	StaticTokenEnv string `json:"staticTokenEnv,omitempty"`
	// Tokens maps bearer strings to principals under identity.type static (tests and demos only).
	Tokens        map[string]PrincipalSeed `json:"tokens,omitempty"`
	JWKSURL       string                   `json:"jwksURL,omitempty"`
	GroupsClaim   string                   `json:"groupsClaim,omitempty"`
	UsernameClaim string                   `json:"usernameClaim,omitempty"`
	Scopes        Scopes                   `json:"scopes,omitempty"`
	Introspection Introspection            `json:"introspection,omitempty"`
	Broker        Broker                   `json:"broker,omitempty"`
	KeycloakAdmin *KeycloakAdmin           `json:"keycloakAdmin,omitempty"`
}

// PrincipalSeed is a principal written in the config (type none / static).
type PrincipalSeed struct {
	Subject string   `json:"subject"`
	Groups  []string `json:"groups,omitempty"`
	// Scopes are the OAuth scopes the principal holds; empty means every scope the gateway knows.
	Scopes []string `json:"scopes,omitempty"`
	Kind   string   `json:"kind,omitempty"` // user | service
}

// Scopes are the OAuth scope names the gateway requires and advertises.
type Scopes struct {
	MCP        string `json:"mcp,omitempty"`
	Admin      string `json:"admin,omitempty"`
	UsersAdmin string `json:"usersAdmin,omitempty"`
}

// Introspection configures periodic revocation checks against the IdP.
type Introspection struct {
	Enabled         bool       `json:"enabled,omitempty"`
	Interval        Duration   `json:"interval,omitempty"`
	Endpoint        string     `json:"endpoint,omitempty"`
	ClientID        string     `json:"clientId,omitempty"`
	ClientSecretRef *SecretRef `json:"clientSecretRef,omitempty"`
}

// BrokerMode selects how downstream per-user tokens are minted.
type BrokerMode string

const (
	BrokerExchange     BrokerMode = "exchange"
	BrokerRefreshToken BrokerMode = "refresh-token"
	BrokerNone         BrokerMode = "none"
)

// Broker is the token broker configuration (RFC 8693 exchange by default).
// Mode is the adapter type name.
type Broker struct {
	Mode            BrokerMode     `json:"mode"`
	Options         map[string]any `json:"options,omitempty"`
	TokenEndpoint   string         `json:"tokenEndpoint,omitempty"`
	ClientID        string         `json:"clientId,omitempty"`
	ClientSecretRef *SecretRef     `json:"clientSecretRef,omitempty"`
	CacheTTL        Duration       `json:"cacheTTL,omitempty"`
}

// KeycloakAdmin is the service-account client the admin UI uses.
type KeycloakAdmin struct {
	BaseURL         string    `json:"baseURL,omitempty"`
	Realm           string    `json:"realm"`
	ClientID        string    `json:"clientId"`
	ClientSecretRef SecretRef `json:"clientSecretRef"`
	AdminRole       string    `json:"adminRole,omitempty"`
}

// RuntimeKind selects where session pods run.
type RuntimeKind string

const (
	// RuntimeLocal runs session "pods" as local processes or docker containers (milestone 0).
	RuntimeLocal RuntimeKind = "local"
	// RuntimeKube runs session pods on Kubernetes through the controller (milestone 1+).
	RuntimeKube RuntimeKind = "kube"
)

// Gateway holds gateway-wide settings.
type Gateway struct {
	PublicURL          string             `json:"publicURL"`
	Listeners          Listeners          `json:"listeners,omitempty"`
	AllowInsecureAdmin bool               `json:"allowInsecureAdmin,omitempty"`
	Runtime            Runtime            `json:"runtime,omitempty"`
	ColdStartBudget    Duration           `json:"coldStartBudget,omitempty"`
	IdleTimeout        Duration           `json:"idleTimeout,omitempty"`
	MaxSessionAge      Duration           `json:"maxSessionAge,omitempty"`
	MaxBodyBytes       int64              `json:"maxBodyBytes,omitempty"`
	Caps               Caps               `json:"caps,omitempty"`
	Tools              ToolsOpts          `json:"tools,omitempty"`
	Routing            Routing            `json:"routing,omitempty"`
	UserSecrets        UserSecretsGateway `json:"userSecrets,omitempty"`
	Redis              *Redis             `json:"redis,omitempty"`
	Audit              Audit              `json:"audit,omitempty"`
	Telemetry          Telemetry          `json:"telemetry,omitempty"`
}

// Runtime selects and configures the session backend.
type Runtime struct {
	Kind  RuntimeKind   `json:"kind,omitempty"`
	Local *LocalRuntime `json:"local,omitempty"`
}

// LocalRuntime configures the milestone-0 backend.
type LocalRuntime struct {
	// Mode is "docker" (docker run per session) or "process" (exec the wrapper binary directly).
	Mode string `json:"mode,omitempty"`
	// WrapperBinary is the path to juggernaut-wrapper for process mode.
	WrapperBinary string `json:"wrapperBinary,omitempty"`
	// Network is the docker network to attach session containers to.
	Network string `json:"network,omitempty"`
	// PortRange is "from-to" for host ports in process mode.
	PortRange string `json:"portRange,omitempty"`
}

// Listeners are the three listeners of the gateway.
type Listeners struct {
	Data    Listener `json:"data,omitempty"`
	Admin   Listener `json:"admin,omitempty"`
	Metrics Listener `json:"metrics,omitempty"`
}

// Caps are cluster-wide hard limits.
type Caps struct {
	PodsPerUser int `json:"podsPerUser,omitempty"`
	TotalPods   int `json:"totalPods,omitempty"`
}

// ToolsOpts controls eager vs lazy tool loading.
type ToolsOpts struct {
	DefaultLoading     string   `json:"defaultLoading,omitempty"`
	LazyForClients     []string `json:"lazyForClients,omitempty"`
	LazyForGroups      []string `json:"lazyForGroups,omitempty"`
	NamespaceSeparator string   `json:"namespaceSeparator,omitempty"`
}

// Routing selects the routing-table adapter (memory, redis). Default: redis
// when gateway.redis is set, else memory.
type Routing struct {
	Type    string         `json:"type,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

// UserSecretsGateway configures the user-secret vault on the gateway side.
type UserSecretsGateway struct {
	// Store selects the UserSecretStore adapter (memory, redis). Default: the routing type.
	Store Routing `json:"store,omitempty"`
	// VaultKeyHeader carries the user's derived key in tier A (default X-Juggernaut-Vault-Key).
	VaultKeyHeader string `json:"vaultKeyHeader,omitempty"`
	// SecretHeaderPrefix is the header prefix for plaintext secrets supplied by the client
	// (default X-Juggernaut-Secret-).
	SecretHeaderPrefix string `json:"secretHeaderPrefix,omitempty"`
	// SealedHeaderPrefix is the header prefix for tier-B blobs sealed to a pod key
	// (default X-Juggernaut-Sealed-Secrets-; the adapter name follows).
	SealedHeaderPrefix string `json:"sealedHeaderPrefix,omitempty"`
}

// Redis is the routing-table store.
type Redis struct {
	Address     string     `json:"address"`
	PasswordRef *SecretRef `json:"passwordRef,omitempty"`
	DB          int        `json:"db,omitempty"`
	KeyPrefix   string     `json:"keyPrefix,omitempty"`
	TLS         bool       `json:"tls,omitempty"`
}

// Audit configures the tool-call audit log. Sink is the audit adapter type.
type Audit struct {
	Sink            string         `json:"sink,omitempty"`
	Options         map[string]any `json:"options,omitempty"`
	File            string         `json:"file,omitempty"`
	RedactArguments []string       `json:"redactArguments,omitempty"`
}

// Telemetry configures OpenTelemetry export.
type Telemetry struct {
	OTLPEndpoint string  `json:"otlpEndpoint,omitempty"`
	ServiceName  string  `json:"serviceName,omitempty"`
	SampleRatio  float64 `json:"sampleRatio,omitempty"`
}

// EgressEnforcer selects the hostname-level egress mechanism.
type EgressEnforcer string

const (
	EgressCilium EgressEnforcer = "cilium"
	EgressProxy  EgressEnforcer = "proxy"
	EgressNone   EgressEnforcer = "none"
)

// Network holds isolation settings.
type Network struct {
	SessionsNamespace  string            `json:"sessionsNamespace,omitempty"`
	NamespacePerGroup  bool              `json:"namespacePerGroup,omitempty"`
	EgressEnforcer     EgressEnforcer    `json:"egressEnforcer,omitempty"`
	Proxy              *ProxyNetwork     `json:"proxy,omitempty"`
	PodAuth            string            `json:"podAuth,omitempty"`
	MTLS               *MTLS             `json:"mtls,omitempty"`
	GatewayPodSelector map[string]string `json:"gatewayPodSelector,omitempty"`
	DenyCIDRs          []string          `json:"denyCIDRs,omitempty"`
	APIServerCIDR      string            `json:"apiServerCIDR,omitempty"`
	ImagePolicy        ImagePolicy       `json:"imagePolicy,omitempty"`
	AllowInsecure      bool              `json:"allowInsecure,omitempty"`
}

// MTLS locates the gateway's client certificate for podAuth mtls. The
// controller issues it from the internal CA; the gateway mounts the Secret.
type MTLS struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	CAFile   string `json:"caFile,omitempty"`
	// CASecretName is the Secret the controller keeps the CA in (system namespace).
	CASecretName string `json:"caSecretName,omitempty"`
	// GatewaySecretName is the Secret the controller issues the gateway client cert into.
	GatewaySecretName string `json:"gatewaySecretName,omitempty"`
	// TrustDomain is the SPIFFE trust domain used in URI SANs.
	TrustDomain string `json:"trustDomain,omitempty"`
}

// ProxyNetwork is the egress proxy address for proxy mode.
type ProxyNetwork struct {
	Address string `json:"address,omitempty"`
}

// ImagePolicy controls which images may be spawned.
type ImagePolicy struct {
	RequireDigest *bool  `json:"requireDigest,omitempty"`
	Cosign        Cosign `json:"cosign,omitempty"`
}

// Cosign enables signature verification of session images.
type Cosign struct {
	Enabled      bool       `json:"enabled,omitempty"`
	PublicKeyRef *SecretRef `json:"publicKeyRef,omitempty"`
}

// Transport is the MCP transport an upstream server speaks.
type Transport string

const (
	TransportStdio          Transport = "stdio"
	TransportStreamableHTTP Transport = "streamable-http"
	TransportSSE            Transport = "sse"
)

// Server is one server type (an "adapter" in API terms).
type Server struct {
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	Image            string            `json:"image"`
	Transport        Transport         `json:"transport"`
	Command          []string          `json:"command,omitempty"`
	Args             []string          `json:"args,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	EnvFrom          []SecretRef       `json:"envFrom,omitempty"`
	HTTP             *HTTPServer       `json:"http,omitempty"`
	Wrapper          Wrapper           `json:"wrapper,omitempty"`
	Token            Token             `json:"token"`
	UserSecrets      *UserSecrets      `json:"userSecrets,omitempty"`
	Egress           []Egress          `json:"egress,omitempty"`
	Resources        Resources         `json:"resources,omitempty"`
	RuntimeClassName string            `json:"runtimeClassName,omitempty"`
	IdleTimeout      Duration          `json:"idleTimeout,omitempty"`
	MaxSessionAge    Duration          `json:"maxSessionAge,omitempty"`
	MaxPods          int               `json:"maxPods,omitempty"`
	Security         Security          `json:"security,omitempty"`
	Tools            ToolExposure      `json:"tools,omitempty"`
}

// HTTPServer describes where an HTTP-transport server listens inside the pod.
type HTTPServer struct {
	Port    int    `json:"port,omitempty"`
	Path    string `json:"path,omitempty"`
	SSEPath string `json:"ssePath,omitempty"`
}

// Wrapper configures the in-pod stdio wrapper.
type Wrapper struct {
	Restart        RestartPolicy `json:"restart,omitempty"`
	StartupTimeout Duration      `json:"startupTimeout,omitempty"`
	LogRedaction   *bool         `json:"logRedaction,omitempty"`
	Port           int           `json:"port,omitempty"`
	ReadinessPort  int           `json:"readinessPort,omitempty"`
}

// RestartPolicy bounds child restarts.
type RestartPolicy struct {
	MaxRestarts int      `json:"maxRestarts,omitempty"`
	Window      Duration `json:"window,omitempty"`
	BackoffMax  Duration `json:"backoffMax,omitempty"`
}

// TokenMode says how the per-user token reaches the server process.
type TokenMode string

const (
	TokenEnv    TokenMode = "env"
	TokenFile   TokenMode = "file"
	TokenHeader TokenMode = "header"
	TokenStatic TokenMode = "static"
	TokenNone   TokenMode = "none"
)

// Token is the per-server token configuration.
type Token struct {
	Mode      TokenMode  `json:"mode"`
	Audience  string     `json:"audience,omitempty"`
	Scopes    []string   `json:"scopes,omitempty"`
	Env       string     `json:"env,omitempty"`
	File      string     `json:"file,omitempty"`
	Header    string     `json:"header,omitempty"`
	Scheme    string     `json:"scheme,omitempty"`
	StaticRef *SecretRef `json:"staticRef,omitempty"`
}

// UserSecrets declares third-party credentials a user supplies for their own
// pod of this server type (Jira/Confluence API tokens for mcp-atlassian).
type UserSecrets struct {
	// Sources in lookup order: header (plaintext per request), store (sealed vault,
	// needs the vault key header), sealed (tier B blob sealed to the pod key).
	Sources []string         `json:"sources,omitempty"`
	Items   []UserSecretItem `json:"items"`
}

// UserSecretItem is one credential: the name the user supplies and where the
// server reads it (env for stdio, header for HTTP, file for either).
type UserSecretItem struct {
	Name     string `json:"name"`
	Env      string `json:"env,omitempty"`
	Header   string `json:"header,omitempty"`
	File     string `json:"file,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// Egress is one allowed destination.
type Egress struct {
	Host     string `json:"host"`
	Ports    []int  `json:"ports,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Resources are Kubernetes resource requests/limits.
type Resources struct {
	Requests ResourceList `json:"requests,omitempty"`
	Limits   ResourceList `json:"limits,omitempty"`
}

// ResourceList mirrors corev1.ResourceList with string quantities.
type ResourceList struct {
	CPU              Quantity `json:"cpu,omitempty"`
	Memory           Quantity `json:"memory,omitempty"`
	EphemeralStorage Quantity `json:"ephemeral-storage,omitempty"`
}

// Security relaxes or tightens the restricted pod defaults per server.
type Security struct {
	WritableTmp            bool     `json:"writableTmp,omitempty"`
	RunAsUser              int64    `json:"runAsUser,omitempty"`
	RunAsGroup             int64    `json:"runAsGroup,omitempty"`
	ReadOnlyRootFilesystem *bool    `json:"readOnlyRootFilesystem,omitempty"`
	ExtraWritablePaths     []string `json:"extraWritablePaths,omitempty"`
}

// ToolExposure filters, renames and scopes tools of a server.
type ToolExposure struct {
	Expose *Expose             `json:"expose,omitempty"`
	Prefix string              `json:"prefix,omitempty"`
	Rename map[string]string   `json:"rename,omitempty"`
	Groups map[string][]string `json:"groups,omitempty"`
}

// Expose is an allow or deny list of upstream tool names.
type Expose struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names,omitempty"`
}

// Authorization maps IdP groups to server types. Type selects the policy
// adapter (default groups).
type Authorization struct {
	Type    string         `json:"type,omitempty"`
	Options map[string]any `json:"options,omitempty"`
	Groups  []Group        `json:"groups"`
}

// Group is one IdP group's grants.
type Group struct {
	Name        string      `json:"name"`
	ServerTypes []string    `json:"serverTypes"`
	PodsPerUser int         `json:"podsPerUser,omitempty"`
	Admin       bool        `json:"admin,omitempty"`
	Tools       *GroupTools `json:"tools,omitempty"`
}

// GroupTools holds per-group tool options.
type GroupTools struct {
	Loading string `json:"loading,omitempty"`
}

// Server returns the server type with the given name, or nil.
func (c *Config) Server(name string) *Server {
	for i := range c.Servers {
		if c.Servers[i].Name == name {
			return &c.Servers[i]
		}
	}
	return nil
}

// ServerNames lists configured server type names in file order.
func (c *Config) ServerNames() []string {
	out := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		out = append(out, s.Name)
	}
	return out
}
