package contracttest

import (
	"log/slog"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// LaptopConfig is a minimal, valid configuration for adapter tests (type
// static identity, no broker, local runtime, no isolation). extra is appended
// verbatim to override sections.
const LaptopConfig = `
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity:
  type: static
  tokens:
    alice-token: { subject: alice, groups: [engineering] }
    ci-token: { subject: ci-bot, kind: service, groups: [engineering], scopes: [juggernaut:mcp] }
  broker: { mode: none }
gateway:
  publicURL: http://127.0.0.1:8080
  runtime: { kind: local }
  tools: { lazyForClients: ["cursor"] }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - name: jira
    image: example/jira:1
    transport: stdio
    command: ["/bin/jira"]
    token: { mode: none }
    tools:
      expose: { mode: allow, names: [search, create] }
      rename: { search: search_issues }
      groups: { create: [product] }
  - name: github
    image: example/gh:1
    transport: streamable-http
    token: { mode: none }
authorization:
  groups:
    - { name: engineering, serverTypes: [jira], podsPerUser: 7 }
    - { name: product, serverTypes: [jira] }
    - { name: everyone, serverTypes: [github] }
    - { name: admins, serverTypes: ["*"], admin: true }
`

// Context builds an adapter context from a YAML document with static secrets.
func Context(t *testing.T, yamlDoc string, secrets core.StaticSecrets, opts map[string]any) *core.Context {
	t.Helper()
	l, err := config.Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	if secrets == nil {
		secrets = core.StaticSecrets{}
	}
	return &core.Context{Config: config.NewStoreFrom(l, slog.Default()), Secrets: secrets, Log: slog.Default(), Options: core.Options(opts)}
}
