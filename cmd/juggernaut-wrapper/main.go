// Command juggernaut-wrapper runs inside every stdio session pod. It owns the
// MCP server child process, exposes it over Streamable HTTP to the gateway only,
// injects the per-user token and reports readiness.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cchulo/project-juggernaut/internal/version"
	"github.com/cchulo/project-juggernaut/internal/wrapper"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_WRAPPER_CONFIG", "/etc/juggernaut/wrapper.json"), "wrapper config JSON")
	install := flag.String("install", "", "copy this binary to the given path and exit (init-container mode)")
	flag.Parse()

	if *install != "" {
		if err := installSelf(*install); err != nil {
			slog.Error("install", "err", err)
			os.Exit(1)
		}
		return
	}

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

// installSelf copies the running binary into a shared emptyDir so a server
// image without the wrapper can still run it.
func installSelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
