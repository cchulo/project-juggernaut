package groups

import (
	"log/slog"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

func store(t *testing.T) *config.Store {
	t.Helper()
	l, err := config.Parse([]byte(`
apiVersion: juggernaut.io/v1alpha1
kind: Config
identity: { issuer: https://idp/realms/x, audience: gw, broker: { mode: none } }
gateway:
  publicURL: https://gw
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
    - { name: admins, serverTypes: ["*"], admin: true }
`))
	if err != nil {
		t.Fatal(err)
	}
	return config.NewStoreFrom(l, slog.Default())
}

func TestContract(t *testing.T) {
	ctx := contracttest.Context(t, contracttest.LaptopConfig, nil, map[string]any{"always_groups": []any{"everyone"}})
	pol, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := &core.Principal{Subject: "u1", Groups: []string{"engineering"}}
	contracttest.AccessPolicy(t, pol, ctx.Cfg(), p)
	if g := pol.Grants(p, ""); !g.Allows("github") {
		t.Fatalf("always_groups everyone must grant github: %+v", g)
	}
}

func TestGrantsAndToolRules(t *testing.T) {
	st := store(t)
	pol, err := registry.Policy.Build(Type, &core.Context{Config: st, Log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	eng := &core.Principal{Subject: "u1", Groups: []string{"engineering"}}
	g := pol.Grants(eng, "Cursor 1.2")
	if !g.Allows("jira") || g.Allows("github") || g.Admin || g.PodsPerUser != 7 || !g.LazyTools {
		t.Fatalf("unexpected grants: %+v", g)
	}
	jira := st.Get().Config.Server("jira")
	if r := pol.ToolRule(g, jira, "search"); !r.Visible || r.Name != "search_issues" {
		t.Fatalf("rename/allow failed: %+v", r)
	}
	if r := pol.ToolRule(g, jira, "delete"); r.Visible {
		t.Fatal("tool outside the allowlist must be hidden")
	}
	if r := pol.ToolRule(g, jira, "create"); r.Visible {
		t.Fatal("per-group tool must be hidden from engineering")
	}
	admin := pol.Grants(&core.Principal{Subject: "a", Groups: []string{"admins"}}, "claude-code")
	if !admin.Admin || !admin.Allows("github") || admin.LazyTools {
		t.Fatalf("admin grants wrong: %+v", admin)
	}
	if r := pol.ToolRule(admin, jira, "create"); !r.Visible {
		t.Fatal("admins see every tool")
	}
}
