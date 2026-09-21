package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log/slog"
)

const base = `
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity: { type: static, tokens: { t: { subject: a } }, broker: { mode: none } }
gateway: { publicURL: http://127.0.0.1:8080, runtime: { kind: local } }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - { name: a, image: x/a:1, transport: stdio, command: ["/bin/a"], token: { mode: none } }
authorization:
  groups: [{ name: g, serverTypes: [a] }]
`

func mustFail(t *testing.T, doc, want string) {
	t.Helper()
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestInterpolation(t *testing.T) {
	t.Setenv("JG_TEST_HOST", "gw.internal")
	out := Interpolate([]byte("url: https://${JG_TEST_HOST}/mcp other: ${JG_UNSET:-fallback} none: ${JG_UNSET}"), os.LookupEnv)
	if got := string(out); got != "url: https://gw.internal/mcp other: fallback none: " {
		t.Fatalf("interpolate: %q", got)
	}
}

func TestValidationRules(t *testing.T) {
	mustFail(t, strings.Replace(base, "type: static, tokens: { t: { subject: a } }, broker: { mode: none }", "type: static, tokens: { t: { subject: a } }, broker: { mode: exchange, clientId: c, clientSecretRef: { env: X } }", 1), "identity.broker.mode must be none")
	offLoopback := strings.Replace(base, "publicURL: http://127.0.0.1:8080, runtime: { kind: local }", "publicURL: http://x, runtime: { kind: local }, listeners: { data: { address: \":8080\" } }", 1)
	offLoopback = strings.Replace(offLoopback, "egressEnforcer: none, allowInsecure: true", "egressEnforcer: none", 1)
	mustFail(t, offLoopback, "requires network.allowInsecure")
	mustFail(t, strings.Replace(base, `token: { mode: none }`, `token: { mode: env }`, 1), "missing property 'env'")
	mustFail(t, strings.Replace(base, `token: { mode: none }`, `token: { mode: header }`, 1), "token/mode") // the schema forbids header mode on stdio before the semantic rule runs
	mustFail(t, strings.Replace(base, `command: ["/bin/a"]`, `command: ["bin/a"]`, 1), "absolute path")
	mustFail(t, strings.Replace(base, "serverTypes: [a]", "serverTypes: [nope]", 1), "unknown server type")
	mustFail(t, strings.Replace(base, "requireDigest: false", "requireDigest: true", 1), "pinned by digest")
	mustFail(t, strings.Replace(base, "egressEnforcer: none, allowInsecure: true", "egressEnforcer: none", 1), "requires network.allowInsecure")
	mustFail(t, strings.Replace(base, "egressEnforcer: none, allowInsecure: true", "egressEnforcer: proxy, allowInsecure: true", 1), "network.proxy.address is required")
	mustFail(t, strings.Replace(base, "runtime: { kind: local }", "runtime: { kind: local }, listeners: { admin: { address: \"0.0.0.0:24680\" } }", 1), "admin is not loopback-bound")
	mustFail(t, strings.Replace(base, "runtime: { kind: local }", "runtime: { kind: local }, coldStartBudget: 10m", 1), "coldStartBudget must be <= 180s")
	mustFail(t, strings.Replace(base, "egressEnforcer: none, allowInsecure: true", "egressEnforcer: none, allowInsecure: true, podAuth: mtls", 1), "needs gateway.runtime.kind kube")
	mustFail(t, strings.Replace(base, `token: { mode: none }`, `token: { mode: none }, userSecrets: { items: [{ name: X }] }`, 1), "one of env, header, file is required")
	mustFail(t, strings.Replace(base, `token: { mode: none }`, `token: { mode: none }, userSecrets: { items: [{ name: X, header: H }] }`, 1), "header delivery is not possible for stdio")
	mustFail(t, "apiVersion: juggernaut.io/v0\nkind: Config\n", "schema validation failed")
}

func TestDefaultsAndDerivedSelectors(t *testing.T) {
	l, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	c := l.Config
	if c.Gateway.Routing.Type != "memory" || c.Gateway.UserSecrets.Store.Type != "memory" || c.Authorization.Type != "groups" {
		t.Fatalf("derived selectors: %+v %+v %s", c.Gateway.Routing, c.Gateway.UserSecrets.Store, c.Authorization.Type)
	}
	if c.Gateway.UserSecrets.VaultKeyHeader != "X-Juggernaut-Vault-Key" || c.Servers[0].Wrapper.Port != 9000 || c.Servers[0].Resources.Limits.Memory != "512Mi" {
		t.Fatalf("defaults: %+v", c.Gateway.UserSecrets)
	}
	kube := strings.Replace(base, "runtime: { kind: local }", "runtime: { kind: kube }, redis: { address: \"r:6379\" }", 1)
	l2, err := Parse([]byte(kube))
	if err != nil {
		t.Fatal(err)
	}
	if l2.Config.Gateway.Routing.Type != "redis" || l2.Config.Gateway.UserSecrets.Store.Type != "redis" {
		t.Fatal("redis must be derived when gateway.redis is set")
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "juggernaut.yaml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan *Loaded, 4)
	st.OnReload(func(l *Loaded) { reloaded <- l })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = st.Watch(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Invalid edit: rejected, previous config stays live, counter increments.
	if err := os.WriteFile(path, []byte("apiVersion: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(900 * time.Millisecond)
	if st.ReloadErrors() == 0 || st.Get().Config.Servers[0].Name != "a" {
		t.Fatalf("invalid reload must be rejected and keep the old config (errors=%d)", st.ReloadErrors())
	}
	// Valid edit: swapped in.
	if err := os.WriteFile(path, []byte(strings.Replace(base, "runtime: { kind: local }", "runtime: { kind: local }, coldStartBudget: 42s", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-reloaded:
		if l.Config.Gateway.ColdStartBudget.Duration != 42*time.Second {
			t.Fatalf("reload delivered wrong config: %+v", l.Config.Servers[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("valid reload was not delivered")
	}
}
