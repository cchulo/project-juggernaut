// Command juggernaut-gateway is the OAuth-protected MCP gateway. It is a thin
// shell: flags, logging and signals; internal/app wires the adapters.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/cchulo/project-juggernaut/internal/adapters/all"
	"github.com/cchulo/project-juggernaut/internal/app"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_CONFIG", "/etc/juggernaut/juggernaut.yaml"), "path to juggernaut.yaml")
	logLevel := flag.String("log-level", envOr("JUGGERNAUT_LOG_LEVEL", "info"), "debug|info|warn|error")
	flag.Parse()

	log := newLogger(*logLevel)
	log.Info("juggernaut-gateway starting", "version", version.Version, "config", *cfgPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := config.NewStore(*cfgPath, log)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	gw, err := app.GatewayFromConfig(ctx, store, core.EnvSecrets{}, log)
	if err != nil {
		log.Error("wiring", "err", err)
		os.Exit(1)
	}
	defer gw.Close()
	if err := gw.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
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
