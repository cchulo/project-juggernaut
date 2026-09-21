package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"sigs.k8s.io/yaml"
)

//go:generate cp ../../schemas/juggernaut.schema.json ./juggernaut.schema.json

// Loaded is a validated, defaulted configuration plus the hash of its source.
type Loaded struct {
	Config *Config
	// Hash is sha256 of the raw file; it changes whenever the file changes and
	// is stamped onto ServerType objects so pods reference the config they were built from.
	Hash string
	// Path is where the file was read from (empty for in-memory loads).
	Path string
}

// LoadFile reads, validates and defaults juggernaut.yaml.
func LoadFile(path string) (*Loaded, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	l, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.Path = path
	return l, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// Interpolate replaces ${NAME} and ${NAME:-default} with environment values so
// endpoints can differ between compose and Kubernetes without two files.
// Secret values still belong in SecretRefs, not in interpolated strings.
func Interpolate(raw []byte, lookup func(string) (string, bool)) []byte {
	return envRef.ReplaceAllFunc(raw, func(m []byte) []byte {
		sm := envRef.FindSubmatch(m)
		if v, ok := lookup(string(sm[1])); ok {
			return []byte(v)
		}
		return sm[2] // default (possibly empty)
	})
}

// Parse validates and defaults a YAML document.
func Parse(raw []byte) (*Loaded, error) {
	raw = Interpolate(raw, os.LookupEnv)
	jsonBytes, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if err := validateSchema(jsonBytes); err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	ApplyDefaults(&c)
	if err := Validate(&c); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &Loaded{Config: &c, Hash: hex.EncodeToString(sum[:8])}, nil
}

func validateSchema(jsonBytes []byte) error {
	schema, err := compiledSchema()
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return fmt.Errorf("schema validation failed:\n%s", indent(ve.Error()))
		}
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// ApplyDefaults fills zero values with the defaults documented in the schema.
func ApplyDefaults(c *Config) {
	id := &c.Identity
	if id.Type == "" {
		if id.Introspection.Enabled {
			id.Type = "bearer_introspect"
		} else {
			id.Type = "bearer_jwt"
		}
	}
	if id.Provider == "" {
		id.Provider = "generic"
	}
	if id.StaticTokenEnv == "" {
		id.StaticTokenEnv = "JUGGERNAUT_TOKEN"
	}
	if id.Type == "none" && id.Principal == nil {
		id.Principal = &PrincipalSeed{Subject: "local", Groups: []string{"everyone", "juggernaut-admins"}}
	}
	if id.Principal != nil && id.Principal.Kind == "" {
		id.Principal.Kind = "user"
	}
	for k, seed := range id.Tokens {
		if seed.Kind == "" {
			seed.Kind = "user"
			id.Tokens[k] = seed
		}
	}
	if id.GroupsClaim == "" {
		id.GroupsClaim = "groups"
	}
	if id.UsernameClaim == "" {
		id.UsernameClaim = "preferred_username"
	}
	if id.Scopes.MCP == "" {
		id.Scopes.MCP = "juggernaut:mcp"
	}
	if id.Scopes.Admin == "" {
		id.Scopes.Admin = "juggernaut:admin"
	}
	if id.Scopes.UsersAdmin == "" {
		id.Scopes.UsersAdmin = "juggernaut:users.admin"
	}
	if id.Introspection.Interval.Duration == 0 {
		id.Introspection.Interval.Duration = 60 * time.Second
	}
	if id.Broker.Mode == "" {
		id.Broker.Mode = BrokerNone
	}
	if id.Broker.CacheTTL.Duration == 0 {
		id.Broker.CacheTTL.Duration = 5 * time.Minute
	}
	if id.KeycloakAdmin != nil && id.KeycloakAdmin.AdminRole == "" {
		id.KeycloakAdmin.AdminRole = "juggernaut-admin"
	}

	g := &c.Gateway
	if g.Listeners.Data.Address == "" {
		g.Listeners.Data.Address = ":8080"
	}
	if g.Listeners.Admin.Address == "" {
		g.Listeners.Admin.Address = "127.0.0.1:24680"
	}
	if g.Listeners.Metrics.Address == "" {
		g.Listeners.Metrics.Address = ":9090"
	}
	if g.Runtime.Kind == "" {
		g.Runtime.Kind = RuntimeKube
	}
	if g.Runtime.Kind == RuntimeLocal {
		if g.Runtime.Local == nil {
			g.Runtime.Local = &LocalRuntime{}
		}
		l := g.Runtime.Local
		if l.Mode == "" {
			l.Mode = "docker"
		}
		if l.WrapperBinary == "" {
			l.WrapperBinary = "juggernaut-wrapper"
		}
		if l.Network == "" {
			l.Network = "juggernaut"
		}
		if l.PortRange == "" {
			l.PortRange = "39000-39999"
		}
	}
	if g.ColdStartBudget.Duration == 0 {
		g.ColdStartBudget.Duration = 60 * time.Second
	}
	if g.IdleTimeout.Duration == 0 {
		g.IdleTimeout.Duration = 15 * time.Minute
	}
	if g.MaxSessionAge.Duration == 0 {
		g.MaxSessionAge.Duration = 12 * time.Hour
	}
	if g.MaxBodyBytes == 0 {
		g.MaxBodyBytes = 4 << 20
	}
	if g.Caps.PodsPerUser == 0 {
		g.Caps.PodsPerUser = 5
	}
	if g.Caps.TotalPods == 0 {
		g.Caps.TotalPods = 2000
	}
	if g.Tools.DefaultLoading == "" {
		g.Tools.DefaultLoading = "eager"
	}
	if g.Tools.NamespaceSeparator == "" {
		g.Tools.NamespaceSeparator = "__"
	}
	if g.Redis != nil && g.Redis.KeyPrefix == "" {
		g.Redis.KeyPrefix = "jg:"
	}
	if g.Routing.Type == "" {
		if g.Redis != nil {
			g.Routing.Type = "redis"
		} else {
			g.Routing.Type = "memory"
		}
	}
	if c.Authorization.Type == "" {
		c.Authorization.Type = "groups"
	}
	us := &g.UserSecrets
	if us.Store.Type == "" {
		us.Store.Type = g.Routing.Type
	}
	if us.VaultKeyHeader == "" {
		us.VaultKeyHeader = "X-Juggernaut-Vault-Key"
	}
	if us.SecretHeaderPrefix == "" {
		us.SecretHeaderPrefix = "X-Juggernaut-Secret-"
	}
	if us.SealedHeaderPrefix == "" {
		us.SealedHeaderPrefix = "X-Juggernaut-Sealed-Secrets-"
	}
	if g.Audit.Sink == "" {
		g.Audit.Sink = "stdout"
	}
	if g.Telemetry.ServiceName == "" {
		g.Telemetry.ServiceName = "juggernaut-gateway"
	}

	n := &c.Network
	if n.SessionsNamespace == "" {
		n.SessionsNamespace = "juggernaut-sessions"
	}
	if n.EgressEnforcer == "" {
		n.EgressEnforcer = EgressCilium
	}
	if n.PodAuth == "" {
		n.PodAuth = "shared-secret"
	}
	if n.PodAuth == "mtls" {
		if n.MTLS == nil {
			n.MTLS = &MTLS{}
		}
		if n.MTLS.CertFile == "" {
			n.MTLS.CertFile = "/etc/juggernaut/tls/tls.crt"
		}
		if n.MTLS.KeyFile == "" {
			n.MTLS.KeyFile = "/etc/juggernaut/tls/tls.key"
		}
		if n.MTLS.CAFile == "" {
			n.MTLS.CAFile = "/etc/juggernaut/tls/ca.crt"
		}
		if n.MTLS.CASecretName == "" {
			n.MTLS.CASecretName = "juggernaut-pod-ca"
		}
		if n.MTLS.GatewaySecretName == "" {
			n.MTLS.GatewaySecretName = "juggernaut-gateway-client-tls"
		}
		if n.MTLS.TrustDomain == "" {
			n.MTLS.TrustDomain = "juggernaut"
		}
	}
	if n.GatewayPodSelector == nil {
		n.GatewayPodSelector = map[string]string{"app.kubernetes.io/name": "juggernaut-gateway"}
	}
	if n.DenyCIDRs == nil {
		n.DenyCIDRs = []string{"169.254.169.254/32", "169.254.0.0/16", "fd00::/8"}
	}
	if n.ImagePolicy.RequireDigest == nil {
		t := true
		n.ImagePolicy.RequireDigest = &t
	}

	for i := range c.Servers {
		s := &c.Servers[i]
		if s.HTTP == nil && s.Transport != TransportStdio {
			s.HTTP = &HTTPServer{}
		}
		if s.HTTP != nil {
			if s.HTTP.Port == 0 {
				s.HTTP.Port = 8081
			}
			if s.HTTP.Path == "" {
				s.HTTP.Path = "/mcp"
			}
			if s.HTTP.SSEPath == "" {
				s.HTTP.SSEPath = "/sse"
			}
		}
		w := &s.Wrapper
		if w.Restart.MaxRestarts == 0 {
			w.Restart.MaxRestarts = 5
		}
		if w.Restart.Window.Duration == 0 {
			w.Restart.Window.Duration = 10 * time.Minute
		}
		if w.Restart.BackoffMax.Duration == 0 {
			w.Restart.BackoffMax.Duration = 30 * time.Second
		}
		if w.StartupTimeout.Duration == 0 {
			w.StartupTimeout.Duration = 20 * time.Second
		}
		if w.LogRedaction == nil {
			t := true
			w.LogRedaction = &t
		}
		if w.Port == 0 {
			w.Port = 9000
		}
		if w.ReadinessPort == 0 {
			w.ReadinessPort = 9001
		}
		if s.Token.File == "" {
			s.Token.File = "/run/juggernaut/token"
		}
		if s.Token.Header == "" {
			s.Token.Header = "Authorization"
		}
		if s.Token.Scheme == "" {
			s.Token.Scheme = "Bearer"
		}
		for j := range s.Egress {
			if len(s.Egress[j].Ports) == 0 {
				s.Egress[j].Ports = []int{443}
			}
			if s.Egress[j].Protocol == "" {
				s.Egress[j].Protocol = "TCP"
			}
		}
		if s.Resources.Requests.CPU == "" {
			s.Resources.Requests.CPU = "100m"
		}
		if s.Resources.Requests.Memory == "" {
			s.Resources.Requests.Memory = "128Mi"
		}
		if s.Resources.Limits.CPU == "" {
			s.Resources.Limits.CPU = "500m"
		}
		if s.Resources.Limits.Memory == "" {
			s.Resources.Limits.Memory = "512Mi"
		}
		if s.MaxPods == 0 {
			s.MaxPods = 200
		}
		if s.Security.RunAsUser == 0 {
			s.Security.RunAsUser = 65532
		}
		if s.Security.RunAsGroup == 0 {
			s.Security.RunAsGroup = 65532
		}
		if s.Security.ReadOnlyRootFilesystem == nil {
			t := true
			s.Security.ReadOnlyRootFilesystem = &t
		}
		if s.Tools.Expose == nil {
			s.Tools.Expose = &Expose{Mode: "all"}
		}
		if s.UserSecrets != nil && len(s.UserSecrets.Sources) == 0 {
			s.UserSecrets.Sources = []string{"header", "store", "sealed"}
		}
	}
}

var (
	fqdnRe   = regexp.MustCompile(`^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+$`)
	digestRe = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)
)

// Validate performs the semantic checks the JSON Schema cannot express.
func Validate(c *Config) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.APIVersion != APIVersion {
		add("apiVersion must be %s", APIVersion)
	}
	if c.Kind != "Config" {
		add("kind must be Config")
	}
	if c.Gateway.Listeners.Data.Address == c.Gateway.Listeners.Admin.Address {
		add("gateway.listeners.admin must not be the same listener as gateway.listeners.data")
	}
	if !isLoopback(c.Gateway.Listeners.Admin.Address) && c.Gateway.Listeners.Admin.TLS == nil && !c.Gateway.AllowInsecureAdmin {
		add("gateway.listeners.admin is not loopback-bound; set tls or allowInsecureAdmin: true")
	}
	if c.Gateway.ColdStartBudget.Duration > 180*time.Second {
		add("gateway.coldStartBudget must be <= 180s")
	}
	if c.Gateway.Runtime.Kind == RuntimeKube && c.Gateway.Routing.Type == "memory" {
		add("gateway.routing.type memory cannot be shared between gateway replicas; configure gateway.redis when gateway.runtime.kind is kube")
	}
	if c.Gateway.Routing.Type == "redis" && c.Gateway.Redis == nil {
		add("gateway.redis is required when gateway.routing.type is redis")
	}
	if c.Network.EgressEnforcer == EgressNone && !c.Network.AllowInsecure {
		add("network.egressEnforcer: none requires network.allowInsecure: true")
	}
	if c.Network.EgressEnforcer == EgressProxy && (c.Network.Proxy == nil || c.Network.Proxy.Address == "") {
		add("network.proxy.address is required when network.egressEnforcer is proxy")
	}
	switch c.Identity.Type {
	case "bearer_jwt", "bearer_introspect":
		if c.Identity.Issuer == "" || c.Identity.Audience == "" {
			add("identity.issuer and identity.audience are required for identity.type %s", c.Identity.Type)
		}
	case "none", "static":
		if c.Identity.Broker.Mode == BrokerExchange || c.Identity.Broker.Mode == BrokerRefreshToken {
			add("identity.type %s issues no real tokens; identity.broker.mode must be none (servers can use token modes none or static)", c.Identity.Type)
		}
		if c.Identity.Type == "static" && len(c.Identity.Tokens) == 0 {
			add("identity.type static requires identity.tokens")
		}
		if c.Identity.KeycloakAdmin != nil {
			add("identity.keycloakAdmin needs a bearer identity type for the admin listener")
		}
	}
	if c.Network.PodAuth == "mtls" && c.Gateway.Runtime.Kind != RuntimeKube {
		add("network.podAuth: mtls needs gateway.runtime.kind kube (the controller issues the certificates)")
	}
	if (c.Identity.Type == "none" || c.Identity.Type == "static") && !isLoopback(c.Gateway.Listeners.Data.Address) && !c.Network.AllowInsecure {
		add("identity.type %s off a loopback data listener requires network.allowInsecure: true (development only)", c.Identity.Type)
	}
	if c.Gateway.UserSecrets.Store.Type == "memory" && c.Gateway.Runtime.Kind == RuntimeKube {
		add("gateway.userSecrets.store.type memory cannot be shared between gateway replicas; configure gateway.redis")
	}
	if c.Identity.Broker.Mode == BrokerExchange && !c.Identity.Broker.ClientSecretRef.IsSet() {
		add("identity.broker.clientSecretRef is required for broker mode exchange")
	}

	seen := map[string]bool{}
	for _, s := range c.Servers {
		if seen[s.Name] {
			add("servers: duplicate name %q", s.Name)
		}
		seen[s.Name] = true
		if *c.Network.ImagePolicy.RequireDigest && !digestRe.MatchString(s.Image) {
			add("servers[%s].image must be pinned by digest (@sha256:...) or set network.imagePolicy.requireDigest: false", s.Name)
		}
		if s.Transport == TransportStdio && len(s.Command) == 0 {
			add("servers[%s]: stdio transport requires command", s.Name)
		}
		if len(s.Command) > 0 && !strings.HasPrefix(s.Command[0], "/") {
			add("servers[%s].command[0] must be an absolute path inside the image", s.Name)
		}
		switch s.Token.Mode {
		case TokenEnv:
			if s.Token.Env == "" {
				add("servers[%s].token.env is required for token mode env", s.Name)
			}
		case TokenHeader:
			if s.Transport == TransportStdio {
				add("servers[%s]: token mode header is not possible for stdio transport (use env or file)", s.Name)
			}
		case TokenStatic:
			if !s.Token.StaticRef.IsSet() {
				add("servers[%s].token.staticRef is required for token mode static", s.Name)
			}
		}
		if (s.Token.Mode == TokenEnv || s.Token.Mode == TokenFile || s.Token.Mode == TokenHeader) &&
			c.Identity.Broker.Mode == BrokerExchange && s.Token.Audience == "" {
			add("servers[%s].token.audience is required with broker mode exchange", s.Name)
		}
		if s.Token.Mode != TokenNone && s.Token.Mode != TokenStatic && c.Identity.Broker.Mode == BrokerNone {
			add("servers[%s]: token mode %s needs identity.broker.mode exchange or refresh-token", s.Name, s.Token.Mode)
		}
		if s.UserSecrets != nil {
			seenNames := map[string]bool{}
			for _, it := range s.UserSecrets.Items {
				if it.Name == "" || seenNames[it.Name] {
					add("servers[%s].userSecrets.items: names must be unique and non-empty", s.Name)
				}
				seenNames[it.Name] = true
				if it.Env == "" && it.Header == "" && it.File == "" {
					add("servers[%s].userSecrets.items[%s]: one of env, header, file is required", s.Name, it.Name)
				}
				if it.Header != "" && s.Transport == TransportStdio {
					add("servers[%s].userSecrets.items[%s]: header delivery is not possible for stdio", s.Name, it.Name)
				}
			}
			for _, src := range s.UserSecrets.Sources {
				if src != "header" && src != "store" && src != "sealed" {
					add("servers[%s].userSecrets.sources: unknown source %q", s.Name, src)
				}
			}
		}
		for _, e := range s.Egress {
			if !fqdnRe.MatchString(e.Host) {
				add("servers[%s].egress: %q is not a valid hostname", s.Name, e.Host)
			}
		}
		if len(s.Egress) == 0 && c.Network.EgressEnforcer != EgressNone {
			add("servers[%s].egress is empty: the pod would have no network access; declare allowed hosts or set token mode none for offline servers", s.Name)
		}
		if s.Tools.Expose != nil && s.Tools.Expose.Mode != "all" && len(s.Tools.Expose.Names) == 0 {
			add("servers[%s].tools.expose.names must be set for mode %s", s.Name, s.Tools.Expose.Mode)
		}
		for tool, groups := range s.Tools.Groups {
			for _, g := range groups {
				if !c.hasGroup(g) {
					add("servers[%s].tools.groups[%s] references unknown group %q", s.Name, tool, g)
				}
			}
		}
	}

	for _, g := range c.Authorization.Groups {
		for _, st := range g.ServerTypes {
			if st == "*" {
				continue
			}
			if !seen[st] {
				add("authorization.groups[%s] references unknown server type %q", g.Name, st)
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Config) hasGroup(name string) bool {
	for _, g := range c.Authorization.Groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
