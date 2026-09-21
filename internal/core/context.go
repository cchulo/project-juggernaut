package core

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Secrets is where adapters get credentials. Values never live in
// juggernaut.yaml; the file carries references ({env: NAME} / {file: PATH})
// that a Secrets implementation resolves.
type Secrets interface {
	// Get resolves a reference. A nil or empty reference yields "" and no error.
	Get(ref *config.SecretRef) (string, error)
	// Env reads a plain environment variable (for values that are not in the file at all, e.g. the KEK).
	Env(name string) (string, bool)
}

// EnvSecrets resolves references against the process environment and the
// filesystem (compose env_file, Kubernetes envFrom / mounted Secrets).
type EnvSecrets struct{}

// Get resolves the reference.
func (EnvSecrets) Get(ref *config.SecretRef) (string, error) {
	if ref == nil || !ref.IsSet() {
		return "", nil
	}
	return ref.Resolve()
}

// Env reads an environment variable.
func (EnvSecrets) Env(name string) (string, bool) { return os.LookupEnv(name) }

// StaticSecrets serves fixed values; for tests.
type StaticSecrets map[string]string

// Get looks the reference's env name up in the map.
func (s StaticSecrets) Get(ref *config.SecretRef) (string, error) {
	if ref == nil || !ref.IsSet() {
		return "", nil
	}
	key := ref.Env
	if key == "" {
		key = ref.File
	}
	v, ok := s[key]
	if !ok {
		return "", fmt.Errorf("secret %s not provided", key)
	}
	return v, nil
}

// Env looks a name up in the map.
func (s StaticSecrets) Env(name string) (string, bool) { v, ok := s[name]; return v, ok }

// Context is what every adapter is constructed with: the live configuration,
// a Secrets source, a logger, and the adapter's own options map from
// juggernaut.yaml. Adapters read config through the store so hot reloads reach them.
type Context struct {
	Config  *config.Store
	Secrets Secrets
	Log     *slog.Logger
	Options Options
	// Kube is nil outside a cluster.
	Kube KubeAccess
}

// Cfg returns the current configuration.
func (c *Context) Cfg() *config.Config { return c.Config.Get().Config }

// Loaded returns the current configuration with its hash.
func (c *Context) Loaded() *config.Loaded { return c.Config.Get() }

// Options is an adapter's `options:` map. Helpers return the zero value when unset.
type Options map[string]any

// String returns a string option.
func (o Options) String(key, def string) string {
	if v, ok := o[key].(string); ok && v != "" {
		return v
	}
	return def
}

// Int returns an integer option (YAML numbers decode as float64).
func (o Options) Int(key string, def int) int {
	switch v := o[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}

// Bool returns a boolean option.
func (o Options) Bool(key string, def bool) bool {
	if v, ok := o[key].(bool); ok {
		return v
	}
	return def
}

// TypeRef is the shape of every adapter selector in juggernaut.yaml:
// a type name plus free-form options the adapter interprets.
type TypeRef struct {
	Type    string         `json:"type,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

// Or returns the type or def when unset.
func (t TypeRef) Or(def string) string {
	if strings.TrimSpace(t.Type) == "" {
		return def
	}
	return t.Type
}
