package edge

import (
	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/metrics"
)

// An edge's state as Prometheus metrics (spec §26.3), read at scrape time.

var (
	descSandboxes = prometheus.NewDesc("opendsec_edge_sandboxes", "Sandboxes on the edge, by backend and state.",
		[]string{"edge", "backend", "state"}, nil)
	descCapacity = prometheus.NewDesc("opendsec_edge_capacity", "Schedulable capacity (overcommit applied), by resource.",
		[]string{"edge", "resource"}, nil)
	descAlloc = prometheus.NewDesc("opendsec_edge_allocated", "Resources charged to the edge's sandboxes, by resource.",
		[]string{"edge", "resource"}, nil)
	descMemAvail = prometheus.NewDesc("opendsec_edge_mem_available_mb", "The node's MemAvailable, as the edge's pressure check sees it.",
		[]string{"edge"}, nil)
	descDiskAvail = prometheus.NewDesc("opendsec_edge_disk_available_mb", "Free space on the edge's state filesystem.",
		[]string{"edge"}, nil)
	descDraining = prometheus.NewDesc("opendsec_edge_draining", "1 while the edge takes no new sandboxes.", []string{"edge"}, nil)
	descPressure = prometheus.NewDesc("opendsec_edge_under_pressure", "1 while the edge rejects creations under memory or disk pressure.",
		[]string{"edge", "pressure"}, nil)
	descMovedIn = prometheus.NewDesc("opendsec_edge_moved_in", "Sandboxes here that moved from another edge (spec §26.2).",
		[]string{"edge"}, nil)
	descCreated  = prometheus.NewDesc("opendsec_edge_created_total", "Sandboxes the edge created.", []string{"edge"}, nil)
	descRejected = prometheus.NewDesc("opendsec_edge_rejected_total", "Creations the edge rejected (no capacity, draining, pressure).",
		[]string{"edge"}, nil)
	descRuntime = prometheus.NewDesc("opendsec_edge_runtime_info", "1 per runtime binary the edge runs, by its version (spec §28.12).",
		[]string{"edge", "component", "version"}, nil)
)

type collector struct{ e *Edge }

// RegisterMetrics exports the edge's state (replacing an earlier process's
// edge of the same id, as after an in-process restart).
func (e *Edge) RegisterMetrics() { metrics.SetCollector("edge/"+e.cfg.ID, collector{e}) }

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descSandboxes, descCapacity, descAlloc, descMemAvail, descDiskAvail,
		descDraining, descPressure, descMovedIn, descCreated, descRejected, descRuntime} {
		ch <- d
	}
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	e := c.e
	id := e.cfg.ID
	st := e.Status(false).State
	type key struct{ backend, state string }
	counts := map[key]int{}
	e.mu.Lock()
	for _, r := range e.sbs {
		if !r.ended() {
			counts[key{r.sb.Spec.Backend, pb.SandboxState_name[int32(r.sb.State)]}]++
		}
	}
	e.mu.Unlock()
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, append([]string{id}, labels...)...)
	}
	for k, v := range st.RuntimeVersions {
		gauge(descRuntime, 1, k, v)
	}
	for k, n := range counts {
		gauge(descSandboxes, float64(n), k.backend, k.state)
	}
	for name, v := range map[string][2]float64{
		"cpu_cores": {st.Capacity.GetCpuCores(), st.Alloc.GetCpuCores()},
		"memory_mb": {float64(st.Capacity.GetMemoryMb()), float64(st.Alloc.GetMemoryMb())},
		"disk_mb":   {float64(st.Capacity.GetDiskMb()), float64(st.Alloc.GetDiskMb())},
		"gpus":      {float64(st.Capacity.GetGpus()), float64(st.Alloc.GetGpus())},
	} {
		gauge(descCapacity, v[0], name)
		gauge(descAlloc, v[1], name)
	}
	if e.Pressure != nil {
		gauge(descMemAvail, float64(st.MemAvailableMb))
	}
	if e.DiskPressure != nil {
		gauge(descDiskAvail, float64(st.DiskAvailableMb))
	}
	gauge(descDraining, b2f(st.Draining))
	for _, p := range []string{"memory", "disk"} {
		gauge(descPressure, b2f(st.UnderPressure && st.Pressure == p), p)
	}
	gauge(descMovedIn, float64(len(st.MovedIn)))
	ch <- prometheus.MustNewConstMetric(descCreated, prometheus.CounterValue, float64(st.TotalCreated), id)
	ch <- prometheus.MustNewConstMetric(descRejected, prometheus.CounterValue, float64(st.TotalRejected), id)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
