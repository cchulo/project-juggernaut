package config

import (
	"bytes"
	"os"
	"testing"
)

func TestExampleValidates(t *testing.T) {
	l, err := LoadFile("../../examples/juggernaut.yaml")
	if err != nil {
		t.Fatalf("example config should validate: %v", err)
	}
	if got := len(l.Config.Servers); got != 2 {
		t.Fatalf("expected 2 servers, got %d", got)
	}
	jira := l.Config.Server("jira")
	if jira == nil || jira.Token.Mode != TokenEnv || jira.Wrapper.Port != 9000 {
		t.Fatalf("defaults not applied: %+v", jira)
	}
}

func TestEmbeddedSchemaMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile("../../schemas/juggernaut.schema.json")
	if err != nil {
		t.Skip("canonical schema not present")
	}
	if !bytes.Equal(canonical, schemaJSON) {
		t.Fatal("internal/config/juggernaut.schema.json is out of date; run `go generate ./internal/config`")
	}
}

func TestRejectsHeaderTokenOnStdio(t *testing.T) {
	doc := []byte(`
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity: { issuer: https://idp/realms/x, audience: gw, broker: { mode: none } }
gateway: { publicURL: https://gw, runtime: { kind: local }, listeners: { admin: { address: "127.0.0.1:24680" } } }
network: { egressEnforcer: none, allowInsecure: true, imagePolicy: { requireDigest: false } }
servers:
  - name: a
    image: example/a:1
    transport: stdio
    command: ["/bin/a"]
    token: { mode: header }
authorization:
  groups: [{ name: g, serverTypes: [a] }]
`)
	if _, err := Parse(doc); err == nil {
		t.Fatal("expected validation error for header token mode on stdio")
	}
}
