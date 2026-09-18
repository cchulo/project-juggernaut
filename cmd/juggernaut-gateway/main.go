// Command juggernaut-gateway is the OAuth-protected MCP gateway.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/broker"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/gateway"
	"github.com/cchulo/project-juggernaut/internal/runtime"
	"github.com/cchulo/project-juggernaut/internal/runtime/local"
	"github.com/cchulo/project-juggernaut/internal/session"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_CONFIG", "/etc/juggernaut/juggernaut.yaml"), "path to juggernaut.yaml")
	stateDir := flag.String("state-dir", envOr("JUGGERNAUT_STATE_DIR", "/var/lib/juggernaut"), "state directory for the local runtime")
	logLevel := flag.String("log-level", envOr("JUGGERNAUT_LOG_LEVEL", "info"), "debug|info|warn|error")
	flag.Parse()

	log := newLogger(*logLevel)
	log.Info("juggernaut-gateway starting", "version", version.Version, "config", *cfgPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *cfgPath, *stateDir); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, cfgPath, stateDir string) error {
	store, err := config.NewStore(cfgPath, log)
	if err != nil {
		return err
	}
	cfg := store.Get().Config
	if cfg.Network.EgressEnforcer == config.EgressNone {
		log.Warn("network.egressEnforcer is none: session pods have unrestricted egress. Laptop use only.")
	}

	verifier, err := auth.NewVerifier(ctx, cfg.Identity, nil)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	br, err := broker.New(cfg.Identity, (*config.SecretRef).Resolve)
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}

	var backend runtime.Backend
	switch cfg.Gateway.Runtime.Kind {
	case config.RuntimeLocal:
		backend, err = local.New(*cfg.Gateway.Runtime.Local, stateDir, log)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("runtime kind %q is not available in this milestone; use gateway.runtime.kind: local", cfg.Gateway.Runtime.Kind)
	}

	srv := gateway.New(gateway.Deps{
		Store: store, Verifier: verifier, Broker: br, Table: session.NewMemory(), Backend: backend, Log: log,
	})
	go func() {
		if err := store.Watch(ctx); err != nil {
			log.Error("config watch stopped", "err", err)
		}
	}()
	return srv.Run(ctx)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
