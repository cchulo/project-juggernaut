package gateway

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	brokernone "github.com/cchulo/project-juggernaut/internal/adapters/broker/none"
	"github.com/cchulo/project-juggernaut/internal/adapters/policy/groups"
	"github.com/cchulo/project-juggernaut/internal/adapters/routing/memory"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
	"github.com/cchulo/project-juggernaut/internal/testutil"
)

func newManager(t *testing.T, extraYAML string, prov contracts.Provisioner) (*Manager, *config.Store) {
	t.Helper()
	ctx := contracttest.Context(t, contracttest.LaptopConfig+extraYAML, nil, nil)
	pol, _ := groups.New(ctx)
	br, _ := brokernone.New(ctx)
	m := NewManager(ctx.Config, pol, memory.NewMemory(), prov, br, slog.Default())
	return m, ctx.Config
}

var alice = &core.Principal{Subject: "alice", Username: "alice", Groups: []string{"engineering"}}

func TestEnsurePodColdStartHold(t *testing.T) {
	prov := testutil.NewFakeProvisioner()
	prov.ReadyAfter = 2
	m, _ := newManager(t, "", prov)
	start := time.Now()
	pod, srv, err := m.EnsurePod(context.Background(), alice, "jira")
	if err != nil || pod.Phase != contracts.PhaseReady || srv.Name != "jira" || pod.Endpoint != prov.Endpoint {
		t.Fatalf("EnsurePod: %+v %v %v", pod, srv, err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("expected the cold-start hold to poll at least once")
	}
	if len(prov.Ensured) != 1 || prov.Ensured[0] != (core.PodKey{Subject: "alice", ServerType: "jira"}) {
		t.Fatalf("provisioner not asked once: %v", prov.Ensured)
	}
	// Warm path: no new Ensure.
	if _, _, err := m.EnsurePod(context.Background(), alice, "jira"); err != nil || len(prov.Ensured) != 1 {
		t.Fatalf("warm path must not re-ensure: %v %v", err, prov.Ensured)
	}
	if pod.PodToken == "" || len(pod.PodToken) < 32 {
		t.Fatal("pod token must be generated")
	}
}

func TestEnsurePodGrantsAndCaps(t *testing.T) {
	prov := testutil.NewFakeProvisioner()
	m, _ := newManager(t, "", prov)
	if _, _, err := m.EnsurePod(context.Background(), alice, "github"); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("engineering is not granted github: %v", err)
	}
	if _, _, err := m.EnsurePod(context.Background(), alice, "nope"); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type: %v", err)
	}
	prov2 := testutil.NewFakeProvisioner()
	m2, _ := newManager(t, "", prov2)
	// engineering has podsPerUser 7 but jira maxPods can be forced low via config override.
	l, _ := config.Parse([]byte(contracttest.LaptopConfig))
	l.Config.Servers[0].MaxPods = 1
	m2.store = config.NewStoreFrom(l, slog.Default())
	if _, _, err := m2.EnsurePod(context.Background(), alice, "jira"); err != nil {
		t.Fatal(err)
	}
	bob := &core.Principal{Subject: "bob", Username: "bob", Groups: []string{"engineering"}}
	if _, _, err := m2.EnsurePod(context.Background(), bob, "jira"); !errors.Is(err, ErrCapReached) {
		t.Fatalf("per-type cap must apply: %v", err)
	}
}

func TestEnsurePodFailureAndBudget(t *testing.T) {
	prov := testutil.NewFakeProvisioner()
	prov.FailWith = "ImagePullBackOff"
	m, _ := newManager(t, "", prov)
	if _, _, err := m.EnsurePod(context.Background(), alice, "jira"); !errors.Is(err, ErrPodFailed) {
		t.Fatalf("failed pod: %v", err)
	}
	if len(prov.Released) != 1 {
		t.Fatal("a failed pod must be released")
	}
	slow := testutil.NewFakeProvisioner()
	slow.ReadyAfter = 1000
	m2, st := newManager(t, "", slow)
	l := st.Get()
	l.Config.Gateway.ColdStartBudget = config.Duration{Duration: 700 * time.Millisecond}
	if _, _, err := m2.EnsurePod(context.Background(), alice, "jira"); !errors.Is(err, ErrColdStart) {
		t.Fatalf("budget exceeded must be ErrColdStart: %v", err)
	}
}

func TestReleaseAllAndSessionsFor(t *testing.T) {
	prov := testutil.NewFakeProvisioner()
	m, _ := newManager(t, "", prov)
	if _, _, err := m.EnsurePod(context.Background(), alice, "jira"); err != nil {
		t.Fatal(err)
	}
	views, err := m.SessionsFor(context.Background(), "alice")
	if err != nil || len(views) != 1 || views[0].Adapter != "jira" || views[0].Phase != "Ready" {
		t.Fatalf("SessionsFor: %+v %v", views, err)
	}
	if err := m.ReleaseAll(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if views, _ := m.SessionsFor(context.Background(), "alice"); len(views) != 0 {
		t.Fatal("ReleaseAll must remove pods")
	}
}
