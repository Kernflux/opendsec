// Package cmdmain holds the main functions of the components whose
// enterprise edition builds (ee/cmd) link extensions into the same program.
package cmdmain

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/metrics"
)

// APIServer runs one apiserver instance (with its embedded placement engine).
func APIServer() {
	cfgPath := flag.String("config", "opendsec.json", "cluster config")
	index := flag.Int("index", 0, "which entry of the apiserver list to run")
	level := flag.String("log", "info", "log level")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics at http://ADDR/metrics (e.g. :9464)")
	pprofAddr := flag.String("pprof", "", "serve net/http/pprof on this address (e.g. 127.0.0.1:6060)")
	drain := flag.Duration("drain-delay", 6*time.Second, "on SIGTERM, fail /readyz and keep serving this long before closing the listener")
	grace := flag.Duration("grace", 30*time.Second, "then let in-flight calls finish for up to this long")
	flag.Parse()
	if *pprofAddr != "" {
		go http.ListenAndServe(*pprofAddr, nil)
	}
	log := cmdutil.Logger(*level)
	if *metricsAddr != "" {
		metrics.Serve(*metricsAddr, log)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cmdutil.Fatal(log, "config", err)
	}
	if *index < 0 || *index >= len(cfg.APIServers) {
		cmdutil.Fatal(log, "flags", fmt.Errorf("-index %d out of range (%d apiservers)", *index, len(cfg.APIServers)))
	}
	c, _, err := cluster.StartAPIServer(cfg, *index, log)
	if err != nil {
		cmdutil.Fatal(log, "start apiserver", err)
	}
	c.Grace = *grace
	cmdutil.WaitSignal()
	cmdutil.Drain(log, *drain)
	c.Stop()
}
