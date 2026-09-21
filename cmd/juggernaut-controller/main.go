// Command juggernaut-controller reconciles juggernaut.yaml into ServerType
// objects and Session objects into isolated session pods, and runs the idle
// reaper. It is a thin shell; internal/app wires the adapters.
package main

import (
	"flag"
	"log/slog"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	_ "github.com/cchulo/project-juggernaut/internal/adapters/all"
	"github.com/cchulo/project-juggernaut/internal/app"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	cfgPath := flag.String("config", envOr("JUGGERNAUT_CONFIG", "/etc/juggernaut/juggernaut.yaml"), "path to juggernaut.yaml")
	o := app.ControllerOptions{}
	flag.StringVar(&o.WrapperImage, "wrapper-image", envOr("JUGGERNAUT_WRAPPER_IMAGE", ""), "image providing /juggernaut-wrapper for server images that lack it")
	flag.StringVar(&o.MetricsAddr, "metrics-bind-address", ":9091", "metrics listener")
	flag.StringVar(&o.ProbeAddr, "health-probe-bind-address", ":8081", "probe listener")
	flag.BoolVar(&o.LeaderElect, "leader-elect", false, "enable leader election")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log.Info("juggernaut-controller starting", "version", version.Version)

	ctx := ctrl.SetupSignalHandler()
	store, err := config.NewStore(*cfgPath, log)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	mgr, err := app.ControllerFromConfig(ctx, store, core.EnvSecrets{}, log, o)
	if err != nil {
		log.Error("wiring", "err", err)
		os.Exit(1)
	}
	if err := mgr.Start(ctx); err != nil {
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
