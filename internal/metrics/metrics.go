// Package metrics holds the services' Prometheus metrics (spec §26.3) and
// serves them over HTTP (-metrics on every binary). It depends on no other
// OpenDsec package, so any of them can record into it.
package metrics

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry holds every OpenDsec metric, plus the Go runtime's and the process's.
var Registry = prometheus.NewRegistry()

// Buckets for latencies from milliseconds (a create, an exec) to minutes
// (a long command, a snapshot transfer).
var latency = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 300}

var (
	rpcHandled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opendsec_rpc_server_handled_total",
		Help: "RPCs served, by service, method and outcome (ok or the OpenDsec error reason).",
	}, []string{"service", "method", "reason"})
	rpcSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_rpc_server_handling_seconds", Buckets: latency,
		Help: "Time to serve an RPC (streams: until they end), by service and method.",
	}, []string{"service", "method"})

	createSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_edge_create_seconds", Buckets: latency,
		Help: "Sandbox creation on an edge (admission to running), by backend and outcome.",
	}, []string{"backend", "reason"})
	createPhase = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_edge_create_phase_seconds", Buckets: latency,
		Help: "Phases of a backend's sandbox creation (prepare, network, config, start, ...).",
	}, []string{"backend", "phase"})
	opSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_edge_op_seconds", Buckets: latency,
		Help: "Lifecycle operations on an edge (pause, resume, stop, snapshot), by backend and outcome.",
	}, []string{"backend", "op", "reason"})
	snapTransfer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_snapshot_transfer_seconds", Buckets: latency,
		Help: "Snapshot files moved between nodes: fetched from a peer edge, pulled from or published to the store.",
	}, []string{"kind"})
	snapBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opendsec_snapshot_transfer_bytes_total",
		Help: "Snapshot data received from peer edges (holes and zero runs excluded).",
	}, []string{"kind"})

	apiCreates = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_apiserver_create_seconds", Buckets: latency,
		Help: "Sandbox creation through the apiserver (placement, admission, edge), by backend and outcome.",
	}, []string{"backend", "reason"})
	apiRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opendsec_apiserver_placement_retries_total",
		Help: "Creations retried on another edge, by the reason the edge gave.",
	}, []string{"reason"})
	forkSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_apiserver_fork_seconds", Buckets: latency,
		Help: "ForkSandbox calls, snapshot to the last copy, by whether the snapshot stayed on its edge.",
	}, []string{"held"})
	moves = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "opendsec_apiserver_move_seconds", Buckets: latency,
		Help: "Paused sandboxes moved to another edge (spec §26.2), by outcome.",
	}, []string{"reason"})

	hostMounts = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "opendsec_host_mounts",
		Help: "Entries in this process's mount table: what every new mount namespace copies (spec §25).",
	}, func() float64 { return float64(countLines("/proc/self/mountinfo")) })
)

// Version is the build's version: set with -ldflags "-X
// github.com/kernflux/opendsec/internal/metrics.Version=..." (the Makefile does), else the module's.
var Version = ""

func init() {
	if Version == "" {
		Version = "dev"
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 12 {
					Version = s.Value[:12]
				}
			}
		}
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "opendsec_build_info", Help: "Always 1; the version of the running binary.",
	}, []string{"version"})
	buildInfo.WithLabelValues(Version).Set(1)
	ready := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "opendsec_ready", Help: "1 while /readyz answers 200.",
	}, func() float64 {
		if Ready() != nil {
			return 0
		}
		return 1
	})
	Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		rpcHandled, rpcSeconds, createSeconds, createPhase, opSeconds, snapTransfer, snapBytes,
		apiCreates, apiRetries, forkSeconds, moves, hostMounts, buildInfo, ready, certExpiry)
}

func countLines(p string) int {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	for s := bufio.NewScanner(f); s.Scan(); {
		n++
	}
	return n
}

func reason(r string) string {
	if r == "" {
		return "ok"
	}
	return r
}

// RPC records one served RPC; r is the OpenDsec error reason, "" on success.
func RPC(service, method, r string, d time.Duration) {
	rpcHandled.WithLabelValues(service, method, reason(r)).Inc()
	rpcSeconds.WithLabelValues(service, method).Observe(d.Seconds())
}

// Create records a sandbox creation on an edge.
func Create(backend, r string, d time.Duration) {
	createSeconds.WithLabelValues(backend, reason(r)).Observe(d.Seconds())
}

// CreatePhase records one phase of a backend's creation.
func CreatePhase(backend, phase string, d time.Duration) {
	createPhase.WithLabelValues(backend, phase).Observe(d.Seconds())
}

// Op records a lifecycle operation on an edge.
func Op(backend, op, r string, d time.Duration) {
	opSeconds.WithLabelValues(backend, op, reason(r)).Observe(d.Seconds())
}

// Transfer records snapshot files moved between nodes: kind is "fetch"
// (from a peer edge), "pull" (from the store) or "publish" (to it).
func Transfer(kind string, d time.Duration) {
	snapTransfer.WithLabelValues(kind).Observe(d.Seconds())
}

// TransferBytes counts snapshot data received from a peer ("fetched").
func TransferBytes(kind string, n int64) { snapBytes.WithLabelValues(kind).Add(float64(n)) }

// APICreate records a creation through the apiserver.
func APICreate(backend, r string, d time.Duration) {
	apiCreates.WithLabelValues(backend, reason(r)).Observe(d.Seconds())
}

// PlacementRetry counts a creation retried elsewhere.
func PlacementRetry(r string) { apiRetries.WithLabelValues(reason(r)).Inc() }

// Fork records a ForkSandbox call.
func Fork(held bool, d time.Duration) {
	h := "false"
	if held {
		h = "true"
	}
	forkSeconds.WithLabelValues(h).Observe(d.Seconds())
}

var certExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "opendsec_tls_cert_expiry_timestamp_seconds",
	Help: "When the certificates this process loaded expire (unix time), by identity (\"ca\" for the CA).",
}, []string{"identity"})

// CertExpiry records when a loaded certificate expires.
func CertExpiry(identity string, at time.Time) {
	certExpiry.WithLabelValues(identity).Set(float64(at.Unix()))
}

// Move records a move of a paused sandbox.
func Move(r string, d time.Duration) { moves.WithLabelValues(reason(r)).Observe(d.Seconds()) }

// ---- per-instance collectors -------------------------------------------------

// Several edges (or watchers) can run in one process (sim clusters, tests),
// and restart in it: their state metrics are collectors registered by id,
// replaced on restart.
var (
	instMu sync.Mutex
	inst   = map[string]prometheus.Collector{}
)

// SetCollector registers c under key, replacing what was registered under
// it; nil just unregisters.
func SetCollector(key string, c prometheus.Collector) {
	instMu.Lock()
	defer instMu.Unlock()
	if old := inst[key]; old != nil {
		Registry.Unregister(old)
		delete(inst, key)
	}
	if c != nil && Registry.Register(c) == nil {
		inst[key] = c
	}
}

// Gauge is a gauge read at scrape time.
type Gauge struct {
	Help string
	F    func() float64
}

// Gauges makes a collector of gauges by name, each with labels.
func Gauges(labels prometheus.Labels, gauges map[string]Gauge) prometheus.Collector {
	var m multi
	for name, g := range gauges {
		m = append(m, prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: g.Help, ConstLabels: labels}, g.F))
	}
	return m
}

type multi []prometheus.Collector

func (m multi) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range m {
		c.Describe(ch)
	}
}

func (m multi) Collect(ch chan<- prometheus.Metric) {
	for _, c := range m {
		c.Collect(ch)
	}
}

// ---- health (spec §27.1) -------------------------------------------------------

var (
	readyMu  sync.Mutex
	checks   = map[string]func() error{}
	draining atomic.Bool
)

// SetReady registers the readiness check of a component under name (nil
// removes it): /readyz answers 200 only while every check returns nil.
func SetReady(name string, check func() error) {
	readyMu.Lock()
	defer readyMu.Unlock()
	if check == nil {
		delete(checks, name)
	} else {
		checks[name] = check
	}
}

// Drain makes /readyz fail from now on: the process is shutting down, and
// load balancers should stop sending it new connections.
func Drain() { draining.Store(true) }

// Ready runs the readiness checks; nil when the process should get traffic.
func Ready() error {
	if draining.Load() {
		return errors.New("shutting down")
	}
	readyMu.Lock()
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	readyMu.Unlock()
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		readyMu.Lock()
		f := checks[n]
		readyMu.Unlock()
		if f == nil {
			continue
		}
		if err := f(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
		}
	}
	return errors.Join(errs...)
}

func readyz(w http.ResponseWriter, _ *http.Request) {
	if err := Ready(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	io.WriteString(w, "ok\n")
}

// Serve serves the metrics at addr (/metrics), liveness (/healthz) and
// readiness (/readyz) until the process exits; a mux of its own, so the
// endpoint never exposes pprof.
func Serve(addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/readyz", readyz)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error("metrics endpoint", "addr", addr, "err", err)
		}
	}()
}

// Text renders the current metrics in the Prometheus text format (tests).
func Text() string {
	var b bytes.Buffer
	rec := &textWriter{h: http.Header{}, b: &b}
	promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}).ServeHTTP(rec, &http.Request{Header: http.Header{}})
	return b.String()
}

type textWriter struct {
	h http.Header
	b *bytes.Buffer
}

func (w *textWriter) Header() http.Header         { return w.h }
func (w *textWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
func (w *textWriter) WriteHeader(int)             {}
