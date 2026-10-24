// opendsec-e2b serves E2B's API in front of an OpenDsec cluster (spec §37):
// E2B's SDKs then run their sandboxes on OpenDsec, with
//
//	E2B_API_URL=http(s)://<gateway>  E2B_SANDBOX_URL=http(s)://<gateway>  E2B_API_KEY=<OpenDsec token>
//
// It holds no state; run one per e2b.gateways entry, behind a load balancer.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/e2b"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/pkg/client"
)

func main() {
	cfgPath := flag.String("config", "opendsec.json", "cluster config (its e2b section)")
	index := flag.Int("index", 0, "which entry of e2b.gateways to run")
	ca := flag.String("ca", "", "CA certificate of the cluster (default: tls.dir/ca.crt)")
	level := flag.String("log", "info", "log level")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics and /readyz at http://ADDR (e.g. :9467)")
	drain := flag.Duration("drain-delay", 5*time.Second, "on SIGTERM, fail /readyz and keep serving this long before shutting down")
	flag.Parse()
	log := cmdutil.Logger(*level)
	if *metricsAddr != "" {
		metrics.Serve(*metricsAddr, log)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cmdutil.Fatal(log, "config", err)
	}
	if cfg.E2B == nil || *index < 0 || *index >= len(cfg.E2B.Gateways) {
		cmdutil.Fatal(log, "flags", fmt.Errorf("-index %d: no such entry in e2b.gateways", *index))
	}
	gw := cfg.E2B.Gateways[*index]
	var addrs []string
	for _, a := range cfg.APIServers {
		addrs = append(addrs, a.Addr)
	}
	var opts []client.Option
	if *ca == "" && cfg.TLS.Dir != "" {
		*ca = filepath.Join(cfg.TLS.Dir, "ca.crt")
	}
	if *ca != "" {
		opts = append(opts, client.WithCAFile(*ca))
	}
	api, err := client.Dial(strings.Join(addrs, ","), "", cfg.E2B.Project, opts...) // calls carry their caller's token
	if err != nil {
		cmdutil.Fatal(log, "dial apiservers", err)
	}
	defer api.Close()
	metrics.SetReady("apiservers", api.Ready)

	srv := &http.Server{Addr: gw.Addr, Handler: e2b.New(*cfg.E2B, api, log.With("c", "e2b")).Handler(),
		ReadHeaderTimeout: 30 * time.Second}
	// HTTP/2 without TLS too (h2c), for Connect's streams.
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetHTTP2(true)
	srv.Protocols.SetUnencryptedHTTP2(true)
	go func() {
		cmdutil.WaitSignal()
		cmdutil.Drain(log, *drain)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Info("e2b gateway listening", "addr", gw.Addr, "tls", gw.TLSCert != "", "project", cfg.E2B.Project)
	if gw.TLSCert != "" {
		err = srv.ListenAndServeTLS(gw.TLSCert, gw.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		cmdutil.Fatal(log, "serve", err)
	}
}
