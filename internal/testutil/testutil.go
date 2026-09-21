// Package testutil holds helpers shared by unit and integration tests: free
// ports, building test binaries, a fake provisioner, and a config factory.
package testutil

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// FreePort asks the kernel for an unused loopback port.
func FreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// RepoRoot walks up from this file to the module root.
func RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above testutil")
	return ""
}

var (
	buildMu    sync.Mutex
	buildCache = map[string]string{}
)

// BuildBinary compiles a package once per test run and returns the binary path.
func BuildBinary(t *testing.T, pkg string) string {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if p, ok := buildCache[pkg]; ok {
		return p
	}
	dir, err := os.MkdirTemp("", "jg-bin-")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = RepoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	buildCache[pkg] = out
	return out
}

// WaitFor polls until cond is true or the deadline passes.
func WaitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// FakeProvisioner is a scripted contracts.Provisioner for gateway tests.
type FakeProvisioner struct {
	mu       sync.Mutex
	pods     map[core.PodKey]*contracts.PodStatus
	Ensured  []core.PodKey
	Released []core.PodKey
	// ReadyAfter is how many Status calls a pod stays Starting before Ready.
	ReadyAfter int
	polls      map[core.PodKey]int
	// FailWith, when set, makes every new pod fail with this message.
	FailWith string
	Endpoint string
}

// NewFakeProvisioner builds one.
func NewFakeProvisioner() *FakeProvisioner {
	return &FakeProvisioner{pods: map[core.PodKey]*contracts.PodStatus{}, polls: map[core.PodKey]int{}, Endpoint: "http://127.0.0.1:1"}
}

func (f *FakeProvisioner) Ensure(_ context.Context, spec contracts.SpawnSpec) (*contracts.PodStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Ensured = append(f.Ensured, spec.Key)
	if st, ok := f.pods[spec.Key]; ok {
		return st, nil
	}
	st := &contracts.PodStatus{Name: spec.Key.Name(), Phase: contracts.PhaseStarting, Started: time.Now()}
	f.pods[spec.Key] = st
	return st, nil
}

func (f *FakeProvisioner) Status(_ context.Context, key core.PodKey) (*contracts.PodStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.pods[key]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	f.polls[key]++
	if f.FailWith != "" {
		st.Phase, st.Message = contracts.PhaseFailed, f.FailWith
	} else if f.polls[key] > f.ReadyAfter {
		st.Phase, st.Endpoint = contracts.PhaseReady, f.Endpoint
	}
	cp := *st
	return &cp, nil
}

func (f *FakeProvisioner) Release(_ context.Context, key core.PodKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Released = append(f.Released, key)
	delete(f.pods, key)
	return nil
}

func (f *FakeProvisioner) List(context.Context) ([]contracts.PodStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []contracts.PodStatus
	for _, s := range f.pods {
		out = append(out, *s)
	}
	return out, nil
}

func (f *FakeProvisioner) Logs(_ context.Context, key core.PodKey, _ int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.pods[key]; !ok {
		return "", contracts.ErrNotFound
	}
	return fmt.Sprintf("logs of %s", key.Name()), nil
}

var _ contracts.Provisioner = (*FakeProvisioner)(nil)
