// opendsec-nodeagent runs on every machine: it reports to the fleet service
// and carries out the operations it hands back (spec §28.4).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/nodeagent"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func main() {
	cfgPath := flag.String("config", "/etc/opendsec/opendsec.json", "cluster config (fleet addresses and tls)")
	name := flag.String("name", os.Getenv("OPENDSEC_NODE"), "node name (its certificate is node-<name>)")
	addr := flag.String("addr", os.Getenv("OPENDSEC_NODE_ADDR"), "the node's private address")
	fleetAddr := flag.String("fleet", "", "fleet replicas (comma separated); default: fleet.replicas in the config")
	root := flag.String("root", "/opt/opendsec", "release directory")
	level := flag.String("log", "info", "log level")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics at http://ADDR/metrics (e.g. :9466)")
	check := flag.Bool("check", false, "print the version and exit (an agent about to replace this one runs it first)")
	flag.Parse()
	if *check {
		fmt.Println(metrics.Version)
		return
	}
	log := cmdutil.Logger(*level)
	if *metricsAddr != "" {
		metrics.Serve(*metricsAddr, log)
	}
	// The config is read once: an agent keeps reaching the fleet with the
	// addresses it started with, even if a config it applies is wrong.
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cmdutil.Fatal(log, "config", err)
	}
	if *name == "" {
		cmdutil.Fatal(log, "flags", errors.New("-name (or OPENDSEC_NODE) is required"))
	}
	target := *fleetAddr
	if target == "" {
		target = cfg.Fleet.ClientAddr()
	}
	if target == "" {
		cmdutil.Fatal(log, "config", errors.New("no fleet replicas configured"))
	}
	sec, err := cluster.Security(cfg, pki.Identity{Role: pki.RoleNode, ID: *name})
	if err != nil {
		cmdutil.Fatal(log, "security", err)
	}
	conn, err := rpcutil.Dial(target, sec, nil)
	if err != nil {
		cmdutil.Fatal(log, "dial fleet", err)
	}
	a := nodeagent.New(nodeagent.Options{Name: *name, Addr: *addr, Fleet: pb.NewFleetClient(conn), Version: metrics.Version,
		Root: *root, Log: log.With("c", "nodeagent", "node", *name)})
	metrics.SetReady("nodeagent", func() error { return nil })
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("node agent started", "node", *name, "fleet", target, "version", metrics.Version)
	a.Run(ctx)
}
