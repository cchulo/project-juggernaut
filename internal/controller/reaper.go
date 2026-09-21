package controller

import (
	"context"
	"log/slog"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// Reaper terminates idle and over-age session pods.
//
// Idle = no request for the server type's idleTimeout AND nothing in flight.
// Over-age = older than maxSessionAge with nothing in flight, or older than
// maxSessionAge + HardGrace regardless.
type Reaper struct {
	Client    client.Client
	Table     contracts.RoutingTable
	Namespace string
	Interval  time.Duration
	HardGrace time.Duration
	Log       *slog.Logger
	// OnTerminate feeds the idle-terminations metric; may be nil.
	OnTerminate func(reason string)
}

// Run loops until ctx is done.
func (r *Reaper) Run(ctx context.Context) error {
	interval := r.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	if r.HardGrace == 0 {
		r.HardGrace = 15 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.sweep(ctx); err != nil {
				r.Log.Warn("reaper sweep failed", "err", err)
			}
		}
	}
}

func (r *Reaper) sweep(ctx context.Context) error {
	var sessions jugv1.SessionList
	if err := r.Client.List(ctx, &sessions, client.InNamespace(r.Namespace)); err != nil {
		return err
	}
	types := map[string]*jugv1.ServerType{}
	var stList jugv1.ServerTypeList
	if err := r.Client.List(ctx, &stList, client.InNamespace(r.Namespace)); err != nil {
		return err
	}
	for i := range stList.Items {
		types[stList.Items[i].Name] = &stList.Items[i]
	}
	now := time.Now()
	for i := range sessions.Items {
		s := &sessions.Items[i]
		if s.Spec.DesiredPhase == jugv1.PhaseTerminating || !s.DeletionTimestamp.IsZero() {
			continue
		}
		st := types[s.Spec.ServerType]
		if st == nil {
			r.terminate(ctx, s, "server type removed")
			continue
		}
		switch s.Status.Phase {
		case jugv1.PhaseFailed:
			r.terminate(ctx, s, "failed")
			continue
		case jugv1.PhaseReady, jugv1.PhaseIdle:
		default:
			// Starting/Pending pods that never became ready within budget + grace are failed by the reconciler.
			continue
		}
		inflight, _ := r.Table.InFlight(ctx, s.Name, 0)
		age := now.Sub(s.CreationTimestamp.Time)
		maxAge := st.Spec.MaxSessionAge.Duration
		if age > maxAge+r.HardGrace {
			r.terminate(ctx, s, "max age (hard)")
			continue
		}
		if age > maxAge && inflight == 0 {
			r.terminate(ctx, s, "max age")
			continue
		}
		last, err := r.Table.LastActive(ctx, s.Name)
		if err != nil {
			if s.Status.ReadyAt != nil {
				last = s.Status.ReadyAt.Time
			} else {
				last = s.CreationTimestamp.Time
			}
		}
		idle := now.Sub(last)
		if idle > st.Spec.IdleTimeout.Duration && inflight == 0 {
			r.terminate(ctx, s, "idle")
			continue
		}
		if idle > st.Spec.IdleTimeout.Duration && s.Status.Phase != jugv1.PhaseIdle {
			// Idle but protected by in-flight work: mark it so operators can see why it lingers.
			s.Status.Phase = jugv1.PhaseIdle
			_ = r.Client.Status().Update(ctx, s)
		}
	}
	return nil
}

func (r *Reaper) terminate(ctx context.Context, s *jugv1.Session, reason string) {
	s.Spec.DesiredPhase = jugv1.PhaseTerminating
	if err := r.Client.Update(ctx, s); err != nil {
		r.Log.Warn("terminate failed", "session", s.Name, "err", err)
		return
	}
	_ = r.Table.DeleteSessionsForPod(ctx, s.Name)
	_ = r.Table.DeletePod(ctx, core.PodKey{Subject: s.Spec.Subject, ServerType: s.Spec.ServerType})
	r.Log.Info("session terminated", "session", s.Name, "reason", reason)
	if r.OnTerminate != nil {
		r.OnTerminate(reason)
	}
}
