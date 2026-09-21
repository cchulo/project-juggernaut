// Package contracttest is the harness every adapter must pass: one function
// per contract that checks the contract's shape and the invariants every
// implementation must keep. Adapter tests call the function for their kind
// with a built adapter; adapter-specific behaviour gets its own tests next to it.
//
//	func TestMemory(t *testing.T) { contracttest.RoutingTable(t, memory.NewMemory()) }
package contracttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// IdentityProvider checks resolve / reject / challenge / metadata shapes.
// bad may be nil when the adapter accepts every request (type none on loopback).
func IdentityProvider(t *testing.T, a contracts.IdentityProvider, good contracts.RequestInfo, bad *contracts.RequestInfo) {
	t.Helper()
	p, err := a.Resolve(context.Background(), good)
	if err != nil || p == nil || p.Subject == "" {
		t.Fatalf("Resolve(good) = %v, %v; want a principal with a subject", p, err)
	}
	if p.Kind != "user" && p.Kind != "service" {
		t.Fatalf("principal kind must be user or service, got %q", p.Kind)
	}
	if bad != nil {
		if _, err := a.Resolve(context.Background(), *bad); !errors.Is(err, contracts.ErrUnauthenticated) {
			t.Fatalf("Resolve(bad) must wrap ErrUnauthenticated, got %v", err)
		}
	}
	if ch := a.Challenge(contracts.ChallengeInvalidToken, "x", ""); len(ch) < len("Bearer") || ch[:6] != "Bearer" {
		t.Fatalf("Challenge must start with Bearer, got %q", ch)
	}
	if md := a.ProtectedResourceMetadata(); md != nil && (md.Resource == "" || len(md.AuthorizationServers) == 0) {
		t.Fatalf("metadata must name resource and authorization servers: %+v", md)
	}
}

// AccessPolicy checks determinism and the tool-rule invariants.
func AccessPolicy(t *testing.T, pol contracts.AccessPolicy, cfg *config.Config, p *core.Principal) {
	t.Helper()
	g1 := pol.Grants(p, "")
	g2 := pol.Grants(p, "")
	if g1.Subject != p.Subject || len(g1.ServerTypes) != len(g2.ServerTypes) {
		t.Fatalf("Grants must be deterministic and carry the subject: %+v vs %+v", g1, g2)
	}
	for i := 1; i < len(g1.ServerTypes); i++ {
		if g1.ServerTypes[i-1] >= g1.ServerTypes[i] {
			t.Fatalf("ServerTypes must be sorted and unique: %v", g1.ServerTypes)
		}
	}
	for _, st := range g1.ServerTypes {
		if cfg.Server(st) == nil {
			t.Fatalf("grant names unknown server type %q", st)
		}
	}
	for i := range cfg.Servers {
		s := &cfg.Servers[i]
		if s.Tools.Expose != nil && s.Tools.Expose.Mode == "allow" {
			if r := pol.ToolRule(g1, s, "definitely-not-listed-tool"); r.Visible {
				t.Fatalf("allowlist mode must hide unlisted tools on %s", s.Name)
			}
		}
		if r := pol.ToolRule(g1, s, "x"); r.Visible && r.Name == "" {
			t.Fatalf("visible rule must carry a name on %s", s.Name)
		}
	}
}

// RoutingTable checks the pod / session / activity round trips.
func RoutingTable(t *testing.T, tbl contracts.RoutingTable) {
	t.Helper()
	ctx := context.Background()
	key := core.PodKey{Subject: "u-" + t.Name(), ServerType: "jira"}
	if _, err := tbl.GetPod(ctx, key); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("GetPod(unknown) must be ErrNotFound, got %v", err)
	}
	pod := &contracts.Pod{Key: key, Name: key.Name(), Phase: contracts.PhaseReady, Endpoint: "http://10.0.0.1:9000",
		CreatedAt: time.Now().Truncate(time.Second), PodToken: "secret-token-value"}
	if err := tbl.PutPod(ctx, pod); err != nil {
		t.Fatal(err)
	}
	got, err := tbl.GetPod(ctx, key)
	if err != nil || got.Name != pod.Name || got.Endpoint != pod.Endpoint || got.PodToken != pod.PodToken {
		t.Fatalf("GetPod round trip: %+v %v", got, err)
	}
	perUser, perType, total, err := tbl.CountPods(ctx, key.Subject, "jira")
	if err != nil || perUser < 1 || perType < 1 || total < 1 {
		t.Fatalf("CountPods: %d %d %d %v", perUser, perType, total, err)
	}
	pods, err := tbl.ListPods(ctx, key.Subject)
	if err != nil || len(pods) != 1 {
		t.Fatalf("ListPods(subject): %v %v", pods, err)
	}
	sess := &contracts.McpSession{ID: core.NewMcpSessionID(), Subject: key.Subject, ServerType: "jira", PodName: pod.Name, CreatedAt: time.Now()}
	if err := tbl.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if s, err := tbl.GetSession(ctx, sess.ID); err != nil || s.PodName != pod.Name {
		t.Fatalf("GetSession: %+v %v", s, err)
	}
	if err := tbl.Touch(ctx, pod.Name, time.Now()); err != nil {
		t.Fatal(err)
	}
	if la, err := tbl.LastActive(ctx, pod.Name); err != nil || time.Since(la) > time.Minute {
		t.Fatalf("LastActive: %v %v", la, err)
	}
	if n, _ := tbl.InFlight(ctx, pod.Name, +1); n != 1 {
		t.Fatalf("InFlight +1 = %d", n)
	}
	if n, _ := tbl.InFlight(ctx, pod.Name, -1); n != 0 {
		t.Fatalf("InFlight -1 = %d", n)
	}
	if n, _ := tbl.InFlight(ctx, pod.Name, -1); n != 0 {
		t.Fatalf("InFlight must not go negative, got %d", n)
	}
	if err := tbl.DeleteSessionsForPod(ctx, pod.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.GetSession(ctx, sess.ID); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("session must be gone after DeleteSessionsForPod, got %v", err)
	}
	if err := tbl.DeletePod(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.GetPod(ctx, key); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("pod must be gone after DeletePod, got %v", err)
	}
}

// TokenBroker checks the no-token modes and that Revoke is safe to call.
func TokenBroker(t *testing.T, b contracts.TokenBroker, p *core.Principal) {
	t.Helper()
	ctx := context.Background()
	for _, mode := range []config.TokenMode{config.TokenNone, config.TokenStatic} {
		s := &config.Server{Name: "s", Token: config.Token{Mode: mode}}
		if tok, err := b.TokenFor(ctx, p, s, time.Minute); err != nil || tok != nil {
			t.Fatalf("token mode %s must yield nil, nil; got %v %v", mode, tok, err)
		}
	}
	if err := b.Revoke(ctx, p.Subject); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// AuditSink checks that Write accepts a full record and Close is idempotent-safe.
func AuditSink(t *testing.T, s contracts.AuditSink) {
	t.Helper()
	s.Write(contracts.AuditRecord{Time: time.Now(), Kind: "tool_call", Subject: "u", ServerType: "jira", Tool: "jira__search",
		Arguments: []byte(`{"q":"x"}`), DurationMS: 3, Outcome: "ok"})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Provisioner checks the not-found and idempotent-release invariants without
// spawning anything.
func Provisioner(t *testing.T, p contracts.Provisioner) {
	t.Helper()
	ctx := context.Background()
	key := core.PodKey{Subject: "nobody-" + t.Name(), ServerType: "none"}
	if _, err := p.Status(ctx, key); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("Status(unknown) must be ErrNotFound, got %v", err)
	}
	if err := p.Release(ctx, key); err != nil {
		t.Fatalf("Release(unknown) must be idempotent, got %v", err)
	}
	if _, err := p.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
}
