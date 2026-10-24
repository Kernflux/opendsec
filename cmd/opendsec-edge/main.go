// opendsec-edge runs one or more edges. Several ids in one process are useful for
// scheduling experiments with sim backends.
package main

import (
	"flag"
	"net/http"
	_ "net/http/pprof"
	"strings"

	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/metrics"
)

func main() {
	cfgPath := flag.String("config", "opendsec.json", "cluster config")
	idList := flag.String("id", "", "edge id(s), comma separated; 'all' for every configured edge; unlisted ids use edge_template")
	listen := flag.String("addr", "", "listen address (overrides the config; single edge only)")
	advertise := flag.String("advertise", "", "address registered with watchers (single edge only)")
	level := flag.String("log", "info", "log level")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics at http://ADDR/metrics (e.g. :9464)")
	pprofAddr := flag.String("pprof", "", "serve net/http/pprof on this address (e.g. 127.0.0.1:6060)")
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
	var idsToRun []string
	if *idList == "all" {
		for _, e := range cfg.Edges {
			idsToRun = append(idsToRun, e.ID)
		}
	} else {
		idsToRun = strings.Split(*idList, ",")
	}
	if (*listen != "" || *advertise != "") && len(idsToRun) == 1 {
		ec, err := cfg.Edge(strings.TrimSpace(idsToRun[0]))
		if err != nil {
			cmdutil.Fatal(log, "config", err)
		}
		if *listen != "" {
			ec.Addr = *listen
		}
		if *advertise != "" {
			ec.Advertise = *advertise
		}
		if !inList(cfg, ec.ID) { // dynamic edge: pin the overridden copy
			cfg.Edges = append(cfg.Edges, *ec)
		}
	}
	var comps []*cluster.Component
	for _, id := range idsToRun {
		c, _, err := cluster.StartEdge(cfg, strings.TrimSpace(id), true, log)
		if err != nil {
			cmdutil.Fatal(log, "start edge", err)
		}
		log.Info("edge listening", "edge", id, "addr", c.Addr)
		comps = append(comps, c)
	}
	cmdutil.WaitSignal()
	for _, c := range comps {
		c.Stop()
	}
}

func inList(cfg *config.Cluster, id string) bool {
	for _, e := range cfg.Edges {
		if e.ID == id {
			return true
		}
	}
	return false
}
