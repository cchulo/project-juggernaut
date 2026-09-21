// Package local is the laptop provisioner: session "pods" are docker
// containers (mode docker) or juggernaut-wrapper processes (mode process) on
// the same host as the gateway. There is no isolation; it exists to prove the
// token flow and the stdio wrapper before Kubernetes enters the picture.
//
// Options: state_dir (default /var/lib/juggernaut); the rest comes from gateway.runtime.local.
package local

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/wrapper"
)

// Type is the registry name.
const Type = "local"

func init() { registry.Provision.Register(Type, New) }

// New builds the provisioner from gateway.runtime.local.
func New(ctx *core.Context) (contracts.Provisioner, error) {
	rt := ctx.Cfg().Gateway.Runtime
	lc := config.LocalRuntime{Mode: "docker", WrapperBinary: "juggernaut-wrapper", Network: "juggernaut", PortRange: "39000-39999"}
	if rt.Local != nil {
		lc = *rt.Local
	}
	stateDir := ctx.Options.String("state_dir", "")
	if stateDir == "" {
		if v, ok := ctx.Secrets.Env("JUGGERNAUT_STATE_DIR"); ok {
			stateDir = v
		} else {
			stateDir = "/var/lib/juggernaut"
		}
	}
	return NewBackend(lc, stateDir, ctx.Log)
}

// Backend implements contracts.Provisioner on the local machine.
type Backend struct {
	cfg  config.LocalRuntime
	log  *slog.Logger
	mu   sync.Mutex
	pods map[core.PodKey]*entry
	// nextPort hands out host ports in process mode.
	nextPort, lastPort int
	stateDir           string
}

type entry struct {
	status    contracts.PodStatus
	cmd       *exec.Cmd
	container string
	logPath   string
	cancel    context.CancelFunc
}

// NewBackend builds the backend. stateDir holds per-pod token files and logs.
func NewBackend(cfg config.LocalRuntime, stateDir string, log *slog.Logger) (*Backend, error) {
	from, to, err := parseRange(cfg.PortRange)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &Backend{cfg: cfg, log: log, pods: map[core.PodKey]*entry{}, nextPort: from, lastPort: to, stateDir: stateDir}, nil
}

func parseRange(s string) (int, int, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	from, err1 := strconv.Atoi(a)
	to, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || from <= 0 || to < from {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return from, to, nil
}

// Ensure starts the pod if it does not exist.
func (b *Backend) Ensure(ctx context.Context, spec contracts.SpawnSpec) (*contracts.PodStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.pods[spec.Key]; ok && e.status.Phase != contracts.PhaseGone && e.status.Phase != contracts.PhaseFailed {
		st := e.status
		return &st, nil
	}
	name := spec.Key.Name()
	dir := filepath.Join(b.stateDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tokenPath := filepath.Join(dir, "pod-token")
	if err := os.WriteFile(tokenPath, []byte(spec.PodToken), 0o600); err != nil {
		return nil, err
	}
	var e *entry
	var err error
	switch b.cfg.Mode {
	case "process":
		e, err = b.startProcess(ctx, spec, name, dir, tokenPath)
	default:
		e, err = b.startDocker(ctx, spec, name, dir, tokenPath)
	}
	if err != nil {
		return nil, err
	}
	e.status.Name = name
	e.status.Phase = contracts.PhaseStarting
	e.status.Started = time.Now()
	b.pods[spec.Key] = e
	go b.watchReady(spec.Key, e, spec.Server.Wrapper.StartupTimeout.Or(20*time.Second)+10*time.Second)
	st := e.status
	return &st, nil
}

func (b *Backend) watchReady(key core.PodKey, e *entry, budget time.Duration) {
	readyURL := strings.Replace(e.status.Endpoint, ":"+portOf(e.status.Endpoint), ":"+strconv.Itoa(readyPortFor(e)), 1) + "/readyz"
	err := WaitReady(context.Background(), readyURL, budget)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		e.status.Phase = contracts.PhaseFailed
		e.status.Message = err.Error()
		b.log.Warn("local pod failed to become ready", "pod", key.Name(), "err", err)
		return
	}
	e.status.Phase = contracts.PhaseReady
	b.log.Info("local pod ready", "pod", key.Name(), "endpoint", e.status.Endpoint)
}

func readyPortFor(e *entry) int {
	if e.cmd != nil { // process mode: readiness port is data port + 1
		p, _ := strconv.Atoi(portOf(e.status.Endpoint))
		return p + 1
	}
	return 9001
}

func portOf(endpoint string) string {
	i := strings.LastIndex(endpoint, ":")
	return endpoint[i+1:]
}

func (b *Backend) startProcess(ctx context.Context, spec contracts.SpawnSpec, name, dir, tokenPath string) (*entry, error) {
	if b.nextPort+1 > b.lastPort {
		return nil, fmt.Errorf("local port range exhausted")
	}
	port := b.nextPort
	b.nextPort += 2
	wcfg := wrapper.ConfigFromServer(spec.Server, port, port+1, tokenPath)
	cfgPath := filepath.Join(dir, "wrapper.json")
	if err := wcfg.WriteFile(cfgPath); err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(pctx, b.cfg.WrapperBinary, "--config", cfgPath)
	logf, err := os.Create(filepath.Join(dir, "wrapper.log"))
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), "JUGGERNAUT_POD_NAME="+name)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start wrapper: %w", err)
	}
	_ = ctx
	return &entry{
		cmd:     cmd,
		cancel:  cancel,
		logPath: logf.Name(),
		status:  contracts.PodStatus{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", port)},
	}, nil
}

func (b *Backend) startDocker(ctx context.Context, spec contracts.SpawnSpec, name, dir, tokenPath string) (*entry, error) {
	wcfg := wrapper.ConfigFromServer(spec.Server, 9000, 9001, "/run/juggernaut/pod-token")
	cfgPath := filepath.Join(dir, "wrapper.json")
	if err := wcfg.WriteFile(cfgPath); err != nil {
		return nil, err
	}
	args := []string{"run", "-d", "--rm",
		"--name", "juggernaut-" + name,
		"--network", b.cfg.Network,
		"--label", "juggernaut.io/session=true",
		"--label", "juggernaut.io/server-type=" + spec.Key.ServerType,
		"--label", "juggernaut.io/user-hash=" + core.UserHash(spec.Key.Subject),
		"--read-only", "--tmpfs", "/run/juggernaut:rw,size=1m,mode=700", "--tmpfs", "/tmp",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"-v", cfgPath + ":/etc/juggernaut/wrapper.json:ro",
		"-v", tokenPath + ":/run/juggernaut/pod-token:ro",
		"--entrypoint", "/juggernaut-wrapper",
	}
	for k, v := range spec.Server.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, spec.Server.Image, "--config", "/etc/juggernaut/wrapper.json")
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	id := strings.TrimSpace(string(out))
	ip, err := exec.CommandContext(ctx, "docker", "inspect", "-f",
		"{{(index .NetworkSettings.Networks \""+b.cfg.Network+"\").IPAddress}}", id).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	return &entry{
		container: id,
		status:    contracts.PodStatus{Endpoint: "http://" + strings.TrimSpace(string(ip)) + ":9000"},
	}, nil
}

// Status reports a pod.
func (b *Backend) Status(_ context.Context, key core.PodKey) (*contracts.PodStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.pods[key]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	st := e.status
	return &st, nil
}

// Release stops the pod.
func (b *Backend) Release(ctx context.Context, key core.PodKey) error {
	b.mu.Lock()
	e, ok := b.pods[key]
	delete(b.pods, key)
	b.mu.Unlock()
	if !ok {
		return nil
	}
	if e.cancel != nil {
		e.cancel()
	}
	if e.container != "" {
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", e.container).Run()
	}
	_ = os.RemoveAll(filepath.Join(b.stateDir, key.Name()))
	return nil
}

// List returns all pods.
func (b *Backend) List(context.Context) ([]contracts.PodStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]contracts.PodStatus, 0, len(b.pods))
	for _, e := range b.pods {
		out = append(out, e.status)
	}
	return out, nil
}

// Logs tails the wrapper log.
func (b *Backend) Logs(ctx context.Context, key core.PodKey, tailLines int) (string, error) {
	b.mu.Lock()
	e, ok := b.pods[key]
	b.mu.Unlock()
	if !ok {
		return "", contracts.ErrNotFound
	}
	if e.container != "" {
		out, err := exec.CommandContext(ctx, "docker", "logs", "--tail", strconv.Itoa(tailLines), e.container).CombinedOutput()
		return string(out), err
	}
	data, err := os.ReadFile(e.logPath)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > tailLines {
		lines = lines[len(lines)-tailLines:]
	}
	return strings.Join(lines, "\n"), nil
}

var _ contracts.Provisioner = (*Backend)(nil)
