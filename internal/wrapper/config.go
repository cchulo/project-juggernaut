// Package wrapper adapts a stdio MCP server (or fronts an HTTP one) inside a
// session pod: it owns the child process, speaks Streamable HTTP to the gateway,
// requires the per-pod shared secret, injects the per-user token according to
// the server's token mode, reports readiness, and redacts tokens from logs.
// It makes no outbound network connections of its own.
package wrapper

import (
	"encoding/json"
	"os"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Config is the wrapper's runtime configuration, rendered by the backend
// (local: JSON file; kube: ConfigMap or env) from the server type definition.
type Config struct {
	ServerName     string            `json:"serverName"`
	Transport      config.Transport  `json:"transport"`
	Command        []string          `json:"command,omitempty"`
	Args           []string          `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	HTTPPort       int               `json:"httpPort,omitempty"` // upstream HTTP server port (http transports)
	HTTPPath       string            `json:"httpPath,omitempty"`
	ListenPort     int               `json:"listenPort"`
	ReadinessPort  int               `json:"readinessPort"`
	PodTokenFile   string            `json:"podTokenFile"`
	Token          config.Token      `json:"token"`
	Restart        config.RestartPolicy
	StartupTimeout time.Duration `json:"startupTimeout"`
	LogRedaction   bool          `json:"logRedaction"`
	// UserSecrets declares which client-supplied secrets the child receives and how.
	UserSecrets []config.UserSecretItem `json:"userSecrets,omitempty"`
	// SecretHeaderPrefix / SealedHeader are the gateway → wrapper header names.
	SecretHeaderPrefix string `json:"secretHeaderPrefix,omitempty"`
	SealedHeader       string `json:"sealedHeader,omitempty"`
	// TLS, when set, serves the data port with mutual TLS (podAuth mtls).
	TLS *TLSFiles `json:"tls,omitempty"`
}

// TLSFiles are the mounted certificate files for mutual TLS.
type TLSFiles struct {
	CertFile     string `json:"certFile"`
	KeyFile      string `json:"keyFile"`
	ClientCAFile string `json:"clientCAFile"`
	// GatewayURI is the SPIFFE URI the gateway's client certificate must carry.
	GatewayURI string `json:"gatewayURI"`
}

// ConfigFromServer renders the wrapper configuration for a server type.
func ConfigFromServer(s *config.Server, listenPort, readinessPort int, podTokenFile string) *Config {
	c := &Config{
		ServerName:     s.Name,
		Transport:      s.Transport,
		Command:        s.Command,
		Args:           s.Args,
		Env:            s.Env,
		ListenPort:     listenPort,
		ReadinessPort:  readinessPort,
		PodTokenFile:   podTokenFile,
		Token:          s.Token,
		Restart:        s.Wrapper.Restart,
		StartupTimeout: s.Wrapper.StartupTimeout.Or(20 * time.Second),
		LogRedaction:   s.Wrapper.LogRedaction == nil || *s.Wrapper.LogRedaction,
	}
	if s.HTTP != nil {
		c.HTTPPort = s.HTTP.Port
		c.HTTPPath = s.HTTP.Path
	}
	if s.UserSecrets != nil {
		c.UserSecrets = s.UserSecrets.Items
	}
	c.SecretHeaderPrefix = "X-Juggernaut-Secret-"
	c.SealedHeader = "X-Juggernaut-Sealed-Secrets"
	return c
}

// WriteFile persists the configuration as JSON.
func (c *Config) WriteFile(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ReadConfig loads a JSON wrapper config.
func ReadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
