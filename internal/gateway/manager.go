package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// Manager implements contracts.SessionManager: the (user, server type) → pod
// use case, including caps and the cold-start hold. It is the single owner of
// that logic; the data plane, the router and the admin listener all go through it.
type Manager struct {
	store       *config.Store
	policy      contracts.AccessPolicy
	table       contracts.RoutingTable
	provisioner contracts.Provisioner
	broker      contracts.TokenBroker
	log         *slog.Logger
}

// NewManager builds a manager.
func NewManager(store *config.Store, policy contracts.AccessPolicy, t contracts.RoutingTable, p contracts.Provisioner, br contracts.TokenBroker, log *slog.Logger) *Manager {
	return &Manager{store: store, policy: policy, table: t, provisioner: p, broker: br, log: log}
}

// Errors surfaced to handlers.
var (
	ErrCapReached  = errors.New("pod cap reached")
	ErrColdStart   = errors.New("session pod starting")
	ErrPodFailed   = errors.New("session pod failed")
	ErrNotGranted  = errors.New("server type not granted")
	ErrUnknownType = errors.New("unknown server type")
)

// EnsurePod returns a Ready pod for (principal, server type), creating it and
// holding for up to the cold-start budget when needed.
func (m *Manager) EnsurePod(ctx context.Context, p *core.Principal, serverType string) (*contracts.Pod, *config.Server, error) {
	l := m.store.Get()
	cfg := l.Config
	srv := cfg.Server(serverType)
	if srv == nil {
		return nil, nil, ErrUnknownType
	}
	grants := m.policy.Grants(p, "")
	if !grants.Allows(serverType) {
		return nil, nil, ErrNotGranted
	}
	key := core.PodKey{Subject: p.Subject, ServerType: serverType}

	pod, err := m.table.GetPod(ctx, key)
	if err != nil && !errors.Is(err, contracts.ErrNotFound) {
		return nil, nil, err
	}
	if pod == nil {
		perUser, perType, total, err := m.table.CountPods(ctx, p.Subject, serverType)
		if err != nil {
			return nil, nil, err
		}
		if perUser >= grants.PodsPerUser || perType >= srv.MaxPods || total >= cfg.Gateway.Caps.TotalPods {
			return nil, nil, ErrCapReached
		}
		pod = &contracts.Pod{
			Key: key, Name: key.Name(), Phase: contracts.PhasePending, CreatedAt: time.Now(),
			ConfigHash: l.Hash, PodToken: newPodToken(),
		}
		if err := m.table.PutPod(ctx, pod); err != nil {
			return nil, nil, err
		}
		if _, err := m.provisioner.Ensure(ctx, contracts.SpawnSpec{
			Key: key, Server: srv, Network: cfg.Network, ConfigHash: l.Hash, PodToken: pod.PodToken,
		}); err != nil {
			_ = m.table.DeletePod(ctx, key)
			return nil, nil, fmt.Errorf("spawn: %w", err)
		}
		m.log.Info("session pod created", "pod", pod.Name, "user", p.Username, "serverType", serverType)
	}
	if pod.Phase == contracts.PhaseReady {
		return pod, srv, nil
	}
	return m.hold(ctx, pod, srv, key, cfg.Gateway.ColdStartBudget.Or(60*time.Second))
}

// hold polls the provisioner until the pod is Ready, Failed, or the budget elapses.
func (m *Manager) hold(ctx context.Context, pod *contracts.Pod, srv *config.Server, key core.PodKey, budget time.Duration) (*contracts.Pod, *config.Server, error) {
	deadline := time.Now().Add(budget)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		st, err := m.provisioner.Status(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		switch st.Phase {
		case contracts.PhaseReady:
			pod.Phase = contracts.PhaseReady
			pod.Endpoint = st.Endpoint
			if err := m.table.PutPod(ctx, pod); err != nil {
				return nil, nil, err
			}
			_ = m.table.Touch(ctx, pod.Name, time.Now())
			return pod, srv, nil
		case contracts.PhaseFailed:
			_ = m.provisioner.Release(ctx, key)
			_ = m.table.DeletePod(ctx, key)
			return nil, nil, fmt.Errorf("%w: %s", ErrPodFailed, st.Message)
		}
		if time.Now().After(deadline) {
			return nil, nil, ErrColdStart
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// Release terminates a pod and purges its sessions.
func (m *Manager) Release(ctx context.Context, key core.PodKey) error {
	if err := m.provisioner.Release(ctx, key); err != nil && !errors.Is(err, contracts.ErrNotFound) {
		return err
	}
	_ = m.table.DeleteSessionsForPod(ctx, key.Name())
	return m.table.DeletePod(ctx, key)
}

// ReleaseAll terminates every pod of a subject (revocation / admin disable).
func (m *Manager) ReleaseAll(ctx context.Context, subject string) error {
	pods, err := m.table.ListPods(ctx, subject)
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range pods {
		errs = append(errs, m.Release(ctx, p.Key))
	}
	errs = append(errs, m.broker.Revoke(ctx, subject))
	return errors.Join(errs...)
}

// SessionsFor lists a subject's pods as API views.
func (m *Manager) SessionsFor(ctx context.Context, subject string) ([]contracts.SessionView, error) {
	pods, err := m.table.ListPods(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]contracts.SessionView, 0, len(pods))
	for _, p := range pods {
		la, _ := m.table.LastActive(ctx, p.Name)
		inflight, _ := m.table.InFlight(ctx, p.Name, 0)
		v := contracts.SessionView{ID: p.Name, Adapter: p.Key.ServerType, User: p.Key.Subject, Phase: string(p.Phase),
			PodName: p.Name, CreatedAt: p.CreatedAt.Format(time.RFC3339), InFlight: inflight}
		if !la.IsZero() {
			v.LastActiveAt = la.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out, nil
}

var _ contracts.SessionManager = (*Manager)(nil)

func newPodToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
