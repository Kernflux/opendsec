// opendsec-iam runs the IAM service: standalone, or one replica of a
// Raft-replicated IAM (-replica <id>, spec §15).
package main

import (
	"flag"
	"fmt"

	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/metrics"
)

func main() {
	cfgPath := flag.String("config", "opendsec.json", "cluster config")
	replica := flag.String("replica", "", "replica id to run (replicated IAM)")
	join := flag.Bool("join", false, "a new replica without state: wait to be added (opendsecctl iam member add) instead of bootstrapping a cluster")
	level := flag.String("log", "info", "log level")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics at http://ADDR/metrics (e.g. :9464)")
	flag.Parse()
	log := cmdutil.Logger(*level)
	if *metricsAddr != "" {
		metrics.Serve(*metricsAddr, log)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cmdutil.Fatal(log, "config", err)
	}
	if config.PlaceholderSecret(cfg.IAM.AdminToken) {
		cmdutil.Fatal(log, "config", fmt.Errorf("iam.admin_token is the example's placeholder: set a secret of your own (dsk.admin.<random>, e.g. from `openssl rand -hex 16`)"))
	}
	if len(cfg.IAM.Replicas) > 0 {
		idx := -1
		for i, r := range cfg.IAM.Replicas {
			if r.ID == *replica {
				idx = i
			}
		}
		if idx < 0 {
			cmdutil.Fatal(log, "flags", fmt.Errorf("-replica %q is not one of the configured iam.replicas", *replica))
		}
		c, _, err := cluster.StartIAMReplica(cfg, idx, *join, log)
		if err != nil {
			cmdutil.Fatal(log, "start iam replica", err)
		}
		cmdutil.WaitSignal()
		c.Stop()
		return
	}
	c, _, tok, err := cluster.StartIAM(cfg, log)
	if err != nil {
		cmdutil.Fatal(log, "start iam", err)
	}
	if cfg.IAM.AdminToken == "" {
		fmt.Printf("generated admin token (set iam.admin_token to keep it stable): %s\n", tok)
	}
	cmdutil.WaitSignal()
	cmdutil.Drain(log, 0)
	c.Stop()
}
