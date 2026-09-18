package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/authz"
	"github.com/cchulo/project-juggernaut/internal/broker"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/runtime"
	"github.com/cchulo/project-juggernaut/internal/session"
)

// Manager owns the (user, server type) → pod mapping and the cold-start hold.
type Manager struct {
	store   *config.Store
	table   session.Table
	backend runtime.Backend
	broker  broker.Broker
	log     *slog.Logger
}

// NewManager builds a manager.
func NewManager(store *config.Store, t session.Table, b runtime.Backend, br broker.Broker, log *slog.Logger) *Manager {
	return &Manager{store: store, table: t, backend: b, broker: br, log: log}
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
func (m *Manager) EnsurePod(ctx context.Context, p *auth.Principal, serverType string) (*session.Pod, *config.Server, error) {
	l := m.store.Get()
	cfg := l.Config
	srv := cfg.Server(serverType)
	if srv == nil {
		return nil, nil, ErrUnknownType
	}
	grants := authz.Compute(cfg, p, "")
	if !grants.Allows(serverType) {
		return nil, nil, ErrNotGranted
	}
	key := session.PodKey{Subject: p.Subject, ServerType: serverType}

	pod, err := m.table.GetPod(ctx, key)
	if err != nil && !errors.Is(err, session.ErrNotFound) {
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
		pod = &session.Pod{
			Key:        key,
			Name:       key.Name(),
			Phase:      session.PhasePending,
			CreatedAt:  time.Now(),
			ConfigHash: l.Hash,
			PodToken:   newPodToken(),
		}
		if err := m.table.PutPod(ctx, pod); err != nil {
			return nil, nil, err
		}
		if _, err := m.backend.Ensure(ctx, runtime.SpawnSpec{
			Key: key, Server: srv, Network: cfg.Network, ConfigHash: l.Hash, PodToken: pod.PodToken,
		}); err != nil {
			_ = m.table.DeletePod(ctx, key)
			return nil, nil, fmt.Errorf("spawn: %w", err)
		}
		m.log.Info("session pod created", "pod", pod.Name, "user", p.Username, "serverType", serverType)
	}
	if pod.Phase == session.PhaseReady {
		return pod, srv, nil
	}
	// Cold start: hold the request, polling the backend, bounded by the budget.
	budget := cfg.Gateway.ColdStartBudget.Or(60 * time.Second)
	deadline := time.Now().Add(budget)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		st, err := m.backend.Status(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		switch st.Phase {
		case session.PhaseReady:
			pod.Phase = session.PhaseReady
			pod.Endpoint = st.Endpoint
			if err := m.table.PutPod(ctx, pod); err != nil {
				return nil, nil, err
			}
			_ = m.table.Touch(ctx, pod.Name, time.Now())
			return pod, srv, nil
		case session.PhaseFailed:
			_ = m.backend.Release(ctx, key)
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
func (m *Manager) Release(ctx context.Context, key session.PodKey) error {
	if err := m.backend.Release(ctx, key); err != nil && !errors.Is(err, runtime.ErrNotFound) {
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

func newPodToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// SessionsFor returns the session pods of a subject as API views (used by the admin listener).
func (m *Manager) SessionsFor(ctx context.Context, subject string) ([]any, error) {
	pods, err := m.table.ListPods(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(pods))
	for _, p := range pods {
		la, _ := m.table.LastActive(ctx, p.Name)
		inflight, _ := m.table.InFlight(ctx, p.Name, 0)
		out = append(out, SessionView{ID: p.Name, Adapter: p.Key.ServerType, User: p.Key.Subject, Phase: string(p.Phase),
			PodName: p.Name, CreatedAt: p.CreatedAt, LastActiveAt: la, InFlight: inflight})
	}
	return out, nil
}
