// Command juggernaut-wrapper runs inside every stdio session pod. It owns the
// MCP server child process, exposes it over Streamable HTTP to the gateway only,
// injects the per-user token and reports readiness.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cchulo/project-juggernaut/internal/version"
	"github.com/cchulo/project-juggernaut/internal/wrapper"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_WRAPPER_CONFIG", "/etc/juggernaut/wrapper.json"), "wrapper config JSON")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := wrapper.ReadConfig(*cfgPath)
	if err != nil {
		log.Error("read config", "err", err)
		os.Exit(2)
	}
	srv, err := wrapper.NewServer(cfg, log)
	if err != nil {
		log.Error("init", "err", err)
		os.Exit(2)
	}
	log.Info("juggernaut-wrapper", "version", version.Version, "server", cfg.ServerName)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Error("wrapper exited", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
