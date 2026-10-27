// Package placement chooses an edge for each new sandbox (paper §3, spec §3.4).
//
// Two stages: filter (healthy, not draining, right backend/hardware, enough
// allocatable capacity, right zone), then power-of-k choices: sample k
// eligible edges uniformly and take the least loaded. Each engine overlays its
// own recent and in-flight placements on the watcher snapshot, so load is counted
// without coordinating with other apiserver instances. The edge keeps final
// admission authority; a rejected edge is penalized briefly.
package placement

import (
	"cmp"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const (
	ZoneOnprem = "onprem"
	ZoneCloud  = "cloud"
)

type Request struct {
	Backend string
	Res     *pb.Resources
	GPUMode string // "" | shared | exclusive
	Image   string
	// PreferEdge is chosen whenever it can host the sandbox, over the load
	// balancing: fork copies stay next to their snapshot (spec §19.4).
	PreferEdge string
	// Snapshot the sandbox starts from: among the edges that fit, those
	// with it in their node cache are chosen first (spec §19.12).
	Snapshot string
	// Runtime versions the sandbox needs (a memory snapshot restores only on
	// the Firecracker that made it, spec §28.12): edges reporting another
	// version are skipped; edges reporting none are not.
	Runtime map[string]string
}

// runtimeOK reports whether edge ed may run a sandbox needing want.
func runtimeOK(ed *pb.EdgeState, want map[string]string) bool {
	for k, v := range want {
		if have := ed.RuntimeVersions[k]; have != "" && v != "" && have != v {
			return false
		}
	}
	return true
}

// Decision describes why an edge was chosen.
type Decision struct {
	Edge  *pb.EdgeState
	Zone  string
	Burst bool    // placed on a cloud edge (on-prem over threshold, or full)
	Load  float64 // load of the chosen edge before this placement

	reservation uint64
}

type pending struct {
	id      uint64
	res     *pb.Resources
	backend string
	disk    float64 // writable disk charged on the chosen edge
	at      float64
}

// usage is a sum of resources and per-backend sandbox counts.
type usage struct {
	cpu, mem, gpus, disk float64
	counts               map[string]float64
}

func (u *usage) add(p pending, sign float64) {
	u.cpu += sign * p.res.GetCpuCores()
	u.mem += sign * float64(p.res.GetMemoryMb())
	u.gpus += sign * float64(p.res.GetGpus())
	u.disk += sign * p.disk
	if u.counts == nil {
		u.counts = map[string]float64{}
	}
	u.counts[p.backend] += sign
}

// overlay holds this engine's recent placements on one edge. applied is the
// running sum of entries newer than the edge's last report, so computing an
// edge's view is O(1) regardless of placement rate.
type overlay struct {
	entries  []pending
	lastSeen float64
	applied  usage
}

type Engine struct {
	cfg         config.Placement
	burstImages map[string]bool
	now         func() float64

	mu      sync.Mutex
	snap    *pb.Snapshot
	overlay map[string]*overlay
	penalty map[string]float64 // edge -> penalized until
	rng     *rand.Rand
	seq     uint64
	// images[edge][backend] is the set of images a restricted backend runs;
	// absent = any image (spec §17.1).
	images map[string]map[string]map[string]bool
	// snapCached[snapshot] is the set of edges caching it.
	snapCached map[string]map[string]bool
}

func New(cfg config.Placement) *Engine {
	e := &Engine{
		cfg:         cfg,
		burstImages: map[string]bool{},
		now:         rpcutil.Now,
		snap:        &pb.Snapshot{},
		overlay:     map[string]*overlay{},
		penalty:     map[string]float64{},
		rng:         rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}
	for _, img := range cfg.BurstEligibleImages {
		e.burstImages[img] = true
	}
	if e.cfg.K < 1 {
		e.cfg.K = 1
	}
	return e
}

// UpdateSnapshot installs a newer watcher snapshot. Overlay entries the edge
// has already reported stop counting; entries older than the grace window are
// dropped.
func (e *Engine) UpdateSnapshot(s *pb.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Snapshots may come from different watcher instances, whose version
	// counters are unrelated: only the time a snapshot was taken orders them.
	if s.TakenAt < e.snap.TakenAt {
		return
	}
	e.snap = s
	e.images = map[string]map[string]map[string]bool{}
	e.snapCached = map[string]map[string]bool{}
	for _, ed := range s.Edges {
		for _, id := range ed.Snapshots {
			if e.snapCached[id] == nil {
				e.snapCached[id] = map[string]bool{}
			}
			e.snapCached[id][ed.Id] = true
		}
		for b, l := range ed.ImagesByBackend {
			set := make(map[string]bool, len(l.Names))
			for _, n := range l.Names {
				set[n] = true
			}
			if e.images[ed.Id] == nil {
				e.images[ed.Id] = map[string]map[string]bool{}
			}
			e.images[ed.Id][b] = set
		}
	}
	for _, ed := range s.Edges {
		o := e.overlay[ed.Id]
		if o == nil {
			e.overlay[ed.Id] = &overlay{lastSeen: ed.LastSeen}
			continue
		}
		o.lastSeen = ed.LastSeen
		o.applied = usage{}
		kept := o.entries[:0]
		for _, p := range o.entries {
			if p.at < ed.LastSeen-e.cfg.OverlayGrace {
				continue
			}
			kept = append(kept, p)
			if p.at > ed.LastSeen {
				o.applied.add(p, 1)
			}
		}
		o.entries = kept
	}
}

func (e *Engine) Snapshot() *pb.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snap
}

// view is an edge's reported state plus this engine's in-flight placements.
type view struct {
	edge  *pb.EdgeState
	ov    *usage
	floor float64 // config.Placement.UsageFloor
}

// hasImageLocked: can edge ed run image on backend?
func (e *Engine) hasImageLocked(ed *pb.EdgeState, backend, image string) bool {
	set, restricted := e.images[ed.Id][backend]
	return !restricted || set[image]
}

func (e *Engine) viewLocked(ed *pb.EdgeState) view {
	v := view{edge: ed, floor: max(0, e.cfg.UsageFloor)}
	if o := e.overlay[ed.Id]; o != nil {
		v.ov = &o.applied
	} else {
		v.ov = &usage{}
	}
	return v
}

func (v view) cpu() float64  { return v.edge.Alloc.GetCpuCores() + v.ov.cpu }
func (v view) mem() float64  { return float64(v.edge.Alloc.GetMemoryMb()) + v.ov.mem }
func (v view) gpus() float64 { return float64(v.edge.Alloc.GetGpus()) + v.ov.gpus }
func (v view) disk() float64 { return float64(v.edge.Alloc.GetDiskMb()) + v.ov.disk }

// diskFor is the disk a request is charged on edge ed: its own size, or the
// edge backend's default.
func diskFor(ed *pb.EdgeState, r Request) float64 {
	if d := r.Res.GetDiskMb(); d > 0 {
		return float64(d)
	}
	return float64(ed.Capacity.GetDefaultDiskMb()[r.Backend])
}
func (v view) count(b string) float64 {
	return float64(v.edge.CountByBackend[b]) + v.ov.counts[b]
}

// load is max(cpu, memory, gpu, disk, sandbox-slot) utilization of allocatable
// capacity, and of what the host actually uses (spec §3.4): with CPU
// overcommitted, a host whose sandboxes really use their CPU is full long
// before its allocation says so. Use below the floor is the host's baseline
// and does not count. Edges that do not report usage report 0.
func (v view) load() float64 {
	c := v.edge.Capacity
	if c == nil {
		return math.Inf(1)
	}
	slots := 0.0
	for b, m := range c.MaxSandboxes {
		if m > 0 {
			slots += v.count(b) / float64(m)
		}
	}
	l := loadOf(v.cpu(), v.mem(), v.gpus(), slots, c)
	if c.DiskMb > 0 {
		l = math.Max(l, v.disk()/float64(c.DiskMb))
	}
	if u := math.Max(v.edge.CpuUsed, v.edge.MemUsed); u >= v.floor {
		l = math.Max(l, u)
	}
	return l
}

func loadOf(cpu, mem, gpus, slots float64, c *pb.Capacity) float64 {
	l := slots
	if c.CpuCores > 0 {
		l = math.Max(l, cpu/c.CpuCores)
	}
	if c.MemoryMb > 0 {
		l = math.Max(l, mem/float64(c.MemoryMb))
	}
	if c.Gpus > 0 {
		l = math.Max(l, gpus/float64(c.Gpus))
	}
	return l
}

func (v view) fits(r Request) bool {
	ed, c := v.edge, v.edge.Capacity
	if !ed.Healthy || ed.Draining || ed.UnderPressure || c == nil {
		return false
	}
	if m := c.MaxSandboxes[r.Backend]; m <= 0 || v.count(r.Backend)+1 > float64(m) {
		return false
	}
	res := r.Res
	if v.cpu()+res.GetCpuCores() > c.CpuCores+1e-9 || v.mem()+float64(res.GetMemoryMb()) > float64(c.MemoryMb) {
		return false
	}
	if c.DiskMb > 0 && v.disk()+diskFor(ed, r) > float64(c.DiskMb) {
		return false
	}
	switch {
	case r.GPUMode == "shared":
		// Shared mode needs a GPU-equipped node but does not reserve whole GPUs.
		return c.Gpus > 0
	case res.GetGpus() > 0:
		return v.gpus()+float64(res.GetGpus()) <= float64(c.Gpus)
	}
	return true
}

// Utilization is the aggregate load of all healthy edges in zone that offer backend.
func (e *Engine) Utilization(zone, backend string) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.utilizationLocked(zone, backend)
}

func (e *Engine) utilizationLocked(zone, backend string) float64 {
	var cpu, mem, count float64
	c := &pb.Capacity{}
	var maxSb float64
	for _, ed := range e.snap.Edges {
		if ed.Zone != zone || !ed.Healthy || ed.Capacity == nil || ed.Capacity.MaxSandboxes[backend] <= 0 {
			continue
		}
		v := e.viewLocked(ed)
		cpu += v.cpu()
		mem += v.mem()
		count += v.count(backend)
		c.CpuCores += ed.Capacity.CpuCores
		c.MemoryMb += ed.Capacity.MemoryMb
		maxSb += float64(ed.Capacity.MaxSandboxes[backend])
	}
	if maxSb == 0 {
		return 0
	}
	return loadOf(cpu, mem, 0, count/maxSb, c)
}

// Pick chooses an edge for r, skipping edges in exclude, and reserves the
// placement in the overlay. Call Cancel if the creation then fails.
func (e *Engine) Pick(r Request, exclude map[string]bool) (*Decision, error) {
	if cpu := r.Res.GetCpuCores(); !(cpu >= 0) || math.IsInf(cpu, 1) {
		return nil, rpcutil.Err(rpcutil.Invalid, "cpu must be finite and >= 0, not %g", cpu)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	eligible := r.Backend == "container" && e.burstImages[r.Image]
	zones := []string{ZoneOnprem}
	burst := false
	if eligible {
		if thr := e.cfg.BurstThreshold; thr > 0 && thr < 1 {
			if u := e.utilizationLocked(ZoneOnprem, r.Backend); u > thr {
				p := math.Min(1, (u-thr)/(1-thr))
				if e.rng.Float64() < p {
					zones = []string{ZoneCloud, ZoneOnprem}
					burst = true
				}
			}
		}
		if !burst {
			zones = append(zones, ZoneCloud) // cloud only as a fallback
		}
	}

	if r.PreferEdge != "" && !exclude[r.PreferEdge] && e.penalty[r.PreferEdge] <= now {
		for _, ed := range e.snap.Edges {
			if ed.Id != r.PreferEdge || !e.hasImageLocked(ed, r.Backend, r.Image) || !runtimeOK(ed, r.Runtime) {
				continue
			}
			if v := e.viewLocked(ed); v.fits(r) {
				d := &Decision{Edge: ed, Zone: ed.Zone, Burst: ed.Zone == ZoneCloud, Load: v.load()}
				d.reservation = e.reserveLocked(ed, r)
				return d, nil
			}
		}
	}
	// Penalized edges (they just rejected a placement) are a last resort,
	// not out: when every other edge is gone too (two edges restarting one
	// after the other, spec §27.7), trying one beats failing outright.
	for pass := 0; pass < 2; pass++ {
		for _, zone := range zones {
			var cands []view
			for _, ed := range e.snap.Edges {
				if ed.Zone != zone || exclude[ed.Id] || (pass == 0) == (e.penalty[ed.Id] > now) || !e.hasImageLocked(ed, r.Backend, r.Image) ||
					!runtimeOK(ed, r.Runtime) {
					continue
				}
				if v := e.viewLocked(ed); v.fits(r) {
					cands = append(cands, v)
				}
			}
			if len(cands) == 0 {
				continue
			}
			if cached := e.snapCached[r.Snapshot]; len(cached) > 0 {
				var near []view
				for _, v := range cands {
					if cached[v.edge.Id] {
						near = append(near, v)
					}
				}
				if len(near) > 0 {
					cands = near
				}
			}
			best := e.powerOfK(cands)
			d := &Decision{Edge: best.edge, Zone: zone, Burst: zone == ZoneCloud, Load: best.load()}
			d.reservation = e.reserveLocked(best.edge, r)
			return d, nil
		}
	}
	// Distinguish "no edge has this image at all" (a user error) from "the
	// edges that have it are full".
	offered, anywhere := false, false
	pressure := map[string]int{} // edges skipped for node pressure, by kind
	otherRuntime := 0
	for _, ed := range e.snap.Edges {
		if ed.Healthy && ed.Capacity.GetMaxSandboxes()[r.Backend] > 0 {
			offered = true
			if !runtimeOK(ed, r.Runtime) {
				otherRuntime++
			}
			anywhere = anywhere || e.hasImageLocked(ed, r.Backend, r.Image)
			if ed.UnderPressure {
				pressure[cmp.Or(ed.Pressure, "memory")]++
			}
		}
	}
	if offered && !anywhere {
		return nil, rpcutil.Err(rpcutil.NotFound, "image %q is not available for backend %s on any edge", r.Image, r.Backend)
	}
	why := ""
	for _, kind := range []string{"memory", "disk", "cpu"} {
		if n := pressure[kind]; n > 0 {
			why += fmt.Sprintf("; %d edge(s) under %s pressure", n, kind)
		}
	}
	if otherRuntime > 0 {
		var want []string
		for k, v := range r.Runtime {
			want = append(want, k+" "+v)
		}
		sort.Strings(want)
		why += fmt.Sprintf("; %d edge(s) run another %s than the snapshot needs (%s)", otherRuntime,
			"runtime", strings.Join(want, ", "))
	}
	return nil, rpcutil.Err(rpcutil.NoCapacity, "no edge can host backend=%s cpu=%g mem=%dMB disk=%dMB gpus=%d%s",
		r.Backend, r.Res.GetCpuCores(), r.Res.GetMemoryMb(), r.Res.GetDiskMb(), r.Res.GetGpus(), why)
}

// powerOfK samples min(k, n) distinct candidates and returns the least loaded,
// breaking ties uniformly at random.
func (e *Engine) powerOfK(c []view) view {
	k := min(e.cfg.K, len(c))
	var best view
	bestLoad, ties := math.Inf(1), 0
	for i := 0; i < k; i++ {
		j := i + e.rng.IntN(len(c)-i) // partial Fisher-Yates
		c[i], c[j] = c[j], c[i]
		l := c[i].load()
		switch {
		case l < bestLoad:
			best, bestLoad, ties = c[i], l, 1
		case l == bestLoad:
			ties++
			if e.rng.IntN(ties) == 0 {
				best = c[i]
			}
		}
	}
	return best
}

// reserveLocked adds an in-flight placement to the overlay at pick time, so
// concurrent picks (e.g. a 32K-sandbox batch) see each other immediately.
func (e *Engine) reserveLocked(ed *pb.EdgeState, r Request) uint64 {
	o := e.overlay[ed.Id]
	if o == nil {
		o = &overlay{}
		e.overlay[ed.Id] = o
	}
	e.seq++
	p := pending{id: e.seq, res: r.Res, backend: r.Backend, disk: diskFor(ed, r), at: e.now()}
	o.entries = append(o.entries, p)
	if p.at > o.lastSeen {
		o.applied.add(p, 1)
	}
	return p.id
}

// Cancel withdraws a decision whose creation failed (edge rejected it or was
// unreachable), so the overlay no longer counts it.
func (e *Engine) Cancel(d *Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	o := e.overlay[d.Edge.Id]
	if o == nil {
		return
	}
	for i, p := range o.entries {
		if p.id == d.reservation {
			if p.at > o.lastSeen {
				o.applied.add(p, -1)
			}
			o.entries = append(o.entries[:i], o.entries[i+1:]...)
			return
		}
	}
}

// Penalize keeps an edge that rejected a placement out of candidates briefly.
func (e *Engine) Penalize(edgeID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.penalty[edgeID] = e.now() + e.cfg.RejectPenalty
}
