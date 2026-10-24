// opendsec-watcher runs the watcher.
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
	replica := flag.String("replica", "", "watcher instance id (with watcher.replicas)")
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
	idx := -1
	for i, r := range cfg.Watcher.List() {
		if r.ID == *replica {
			idx = i
		}
	}
	if idx < 0 {
		cmdutil.Fatal(log, "flags", fmt.Errorf("-replica %q is not a configured watcher instance", *replica))
	}
	c, _, err := cluster.StartWatcher(cfg, idx, log)
	if err != nil {
		cmdutil.Fatal(log, "start watcher", err)
	}
	cmdutil.WaitSignal()
	cmdutil.Drain(log, 0)
	c.Stop()
}
