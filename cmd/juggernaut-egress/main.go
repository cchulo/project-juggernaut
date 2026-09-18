// Command juggernaut-egress is the fallback egress enforcer: a CONNECT proxy
// that only tunnels to allowlisted host:port pairs per session pod.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cchulo/project-juggernaut/internal/egress"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	listen := flag.String("listen", ":3128", "CONNECT listener")
	allowlist := flag.String("allowlist", "/etc/juggernaut-egress/allowlist.json", "allowlist file (mounted ConfigMap)")
	deny := flag.String("deny-cidrs", "169.254.169.254/32,169.254.0.0/16,fd00::/8", "comma-separated CIDRs never reachable")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("juggernaut-egress starting", "version", version.Version, "listen", *listen)
	cidrs, err := egress.ParseCIDRs(strings.Split(*deny, ","))
	if err != nil {
		log.Error("deny-cidrs", "err", err)
		os.Exit(2)
	}
	p := &egress.Proxy{
		AllowlistPath: *allowlist,
		DenyCIDRs:     cidrs,
		Log:           log,
		Dialer:        &net.Dialer{Timeout: 10 * time.Second},
		Resolver:      net.DefaultResolver,
	}
	if err := p.LoadAllowlist(); err != nil {
		log.Error("allowlist", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = p.Watch(ctx) }()

	srv := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
