package session

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Table. It is the milestone-0 store and the LRU tier
// in front of Redis later.
type Memory struct {
	mu       sync.RWMutex
	pods     map[PodKey]*Pod
	sessions map[string]*McpSession
	active   map[string]time.Time
	inflight map[string]int
}

// NewMemory returns an empty table.
func NewMemory() *Memory {
	return &Memory{
		pods:     map[PodKey]*Pod{},
		sessions: map[string]*McpSession{},
		active:   map[string]time.Time{},
		inflight: map[string]int{},
	}
}

func (m *Memory) GetPod(_ context.Context, key PodKey) (*Pod, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pods[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *Memory) PutPod(_ context.Context, p *Pod) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *p
	m.pods[p.Key] = &cp
	return nil
}

func (m *Memory) DeletePod(_ context.Context, key PodKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.pods[key]; ok {
		delete(m.active, p.Name)
		delete(m.inflight, p.Name)
	}
	delete(m.pods, key)
	return nil
}

func (m *Memory) ListPods(_ context.Context, subject string) ([]*Pod, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Pod
	for _, p := range m.pods {
		if subject == "" || p.Key.Subject == subject {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *Memory) CountPods(_ context.Context, subject, serverType string) (int, int, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var perUser, perType int
	for _, p := range m.pods {
		if p.Phase == PhaseGone || p.Phase == PhaseTerminating {
			continue
		}
		if p.Key.Subject == subject {
			perUser++
		}
		if p.Key.ServerType == serverType {
			perType++
		}
	}
	return perUser, perType, len(m.pods), nil
}

func (m *Memory) GetSession(_ context.Context, id string) (*McpSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *Memory) PutSession(_ context.Context, s *McpSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	m.sessions[s.ID] = &cp
	return nil
}

func (m *Memory) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *Memory) DeleteSessionsForPod(_ context.Context, podName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.PodName == podName {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *Memory) Touch(_ context.Context, podName string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[podName] = at
	return nil
}

func (m *Memory) LastActive(_ context.Context, podName string) (time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.active[podName]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) InFlight(_ context.Context, podName string, delta int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inflight[podName] += delta
	if m.inflight[podName] < 0 {
		m.inflight[podName] = 0
	}
	return m.inflight[podName], nil
}

var _ Table = (*Memory)(nil)
