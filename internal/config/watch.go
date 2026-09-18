package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Store holds the live configuration and swaps it atomically on reload.
// Consumers call Get() per request; a failed reload keeps the previous value.
type Store struct {
	cur       atomic.Pointer[Loaded]
	path      string
	log       *slog.Logger
	onReload  []func(*Loaded)
	reloadErr atomic.Int64
}

// NewStore loads the file once and returns a store ready to Watch.
func NewStore(path string, log *slog.Logger) (*Store, error) {
	l, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, log: log}
	s.cur.Store(l)
	return s, nil
}

// Get returns the current configuration.
func (s *Store) Get() *Loaded { return s.cur.Load() }

// OnReload registers a callback invoked after a successful swap.
func (s *Store) OnReload(fn func(*Loaded)) { s.onReload = append(s.onReload, fn) }

// ReloadErrors returns how many reloads were rejected since start (exported as a metric).
func (s *Store) ReloadErrors() int64 { return s.reloadErr.Load() }

// Watch reloads on file changes until ctx is done. ConfigMap mounts update via
// symlink swaps, so the directory is watched and a hash-based poll backs it up.
func (s *Store) Watch(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(filepath.Dir(s.path)); err != nil {
		return err
	}
	debounce := time.NewTimer(0)
	<-debounce.C
	poll := time.NewTicker(30 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.Events:
			debounce.Reset(500 * time.Millisecond)
		case err := <-w.Errors:
			s.log.Warn("config watcher error", "err", err)
		case <-debounce.C:
			s.reload()
		case <-poll.C:
			s.reload()
		}
	}
}

func (s *Store) reload() {
	l, err := LoadFile(s.path)
	if err != nil {
		s.reloadErr.Add(1)
		s.log.Error("config reload rejected; previous config stays live", "path", s.path, "err", err)
		return
	}
	if cur := s.cur.Load(); cur != nil && cur.Hash == l.Hash {
		return
	}
	s.cur.Store(l)
	s.log.Info("config reloaded", "hash", l.Hash, "servers", len(l.Config.Servers))
	for _, fn := range s.onReload {
		fn(l)
	}
}
