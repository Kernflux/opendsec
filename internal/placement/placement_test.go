package placement

import (
	"fmt"
	"math"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func edge(id, zone string, cpu float64, maxSb int32) *pb.EdgeState {
	return &pb.EdgeState{
		Id: id, Zone: zone, Healthy: true, Backends: []string{"container", "sim"},
		Capacity:       &pb.Capacity{CpuCores: cpu, MemoryMb: 1 << 20, MaxSandboxes: map[string]int32{"container": maxSb, "sim": maxSb}},
		Alloc:          &pb.Resources{},
		CountByBackend: map[string]int32{},
	}
}

func engine(k int, edges ...*pb.EdgeState) *Engine {
	e := New(config.Placement{K: k, RejectPenalty: 2, OverlayGrace: 2, BurstThreshold: 0.8,
		BurstEligibleImages: []string{"img:ok"}, UsageFloor: 0.2})
	e.now = func() float64 { return 100 }
	e.UpdateSnapshot(&pb.Snapshot{Version: 1, TakenAt: 99, Edges: edges})
	return e
}

var small = Request{Backend: "sim", Res: &pb.Resources{CpuCores: 1, MemoryMb: 1024}}

func TestFilter(t *testing.T) {
	sick := edge("sick", ZoneOnprem, 100, 10)
	sick.Healthy = false
	drain := edge("drain", ZoneOnprem, 100, 10)
	drain.Draining = true
	full := edge("full", ZoneOnprem, 100, 10)
	full.CountByBackend["sim"] = 10
	tiny := edge("tiny", ZoneOnprem, 0.5, 10)
	pressured := edge("pressured", ZoneOnprem, 100, 1000)
	pressured.UnderPressure = true
	ok := edge("ok", ZoneOnprem, 100, 1000)
	cloud := edge("cloud", ZoneCloud, 100, 1000)
	e := engine(2, sick, drain, full, tiny, pressured, ok, cloud)
	for i := 0; i < 50; i++ {
		d, err := e.Pick(small, nil)
		if err != nil || d.Edge.Id != "ok" {
			t.Fatalf("pick %d: %v %v", i, d, err)
		}
		e.Cancel(d)
	}
	if _, err := e.Pick(small, map[string]bool{"ok": true}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("want no_capacity, got %v", err)
	}
	gpu := Request{Backend: "sim", Res: &pb.Resources{Gpus: 1}}
	if _, err := e.Pick(gpu, nil); err == nil {
		t.Fatal("gpu request should not fit")
	}
}

func TestOverlayAndPenalty(t *testing.T) {
	a, b := edge("a", ZoneOnprem, 10, 100), edge("b", ZoneOnprem, 10, 100)
	a.LastSeen, b.LastSeen = 99, 99
	e := engine(2, a, b)
	// With k=2 over two edges, alternating placements keep them balanced
	// purely through the overlay (the snapshot never changes).
	for i := 0; i < 10; i++ {
		if _, err := e.Pick(small, nil); err != nil {
			t.Fatal(err)
		}
	}
	if na, nb := len(e.overlay["a"].entries), len(e.overlay["b"].entries); na != 5 || nb != 5 {
		t.Fatalf("overlay a=%d b=%d", na, nb)
	}
	// Both edges are now full on CPU (5 x 1 core of 10... add 5 more each).
	for i := 0; i < 10; i++ {
		e.Pick(small, nil)
	}
	if _, err := e.Pick(small, nil); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("overlay should make edges full: %v", err)
	}
	// A newer snapshot that reflects the placements prunes the overlay.
	a2, b2 := edge("a", ZoneOnprem, 1000, 1000), edge("b", ZoneOnprem, 1000, 1000)
	a2.LastSeen, b2.LastSeen = 110, 110
	e.now = func() float64 { return 120 }
	e.UpdateSnapshot(&pb.Snapshot{Version: 2, TakenAt: 110, Edges: []*pb.EdgeState{a2, b2}})
	if len(e.overlay["a"].entries) != 0 || e.overlay["a"].applied.cpu != 0 {
		t.Fatalf("overlay not pruned: %d", len(e.overlay["a"].entries))
	}
	// Cancel withdraws a reservation.
	d, _ := e.Pick(small, nil)
	if e.overlay[d.Edge.Id].applied.cpu != 1 {
		t.Fatal("pick did not reserve")
	}
	e.Cancel(d)
	if len(e.overlay[d.Edge.Id].entries) != 0 || e.overlay[d.Edge.Id].applied.cpu != 0 {
		t.Fatal("cancel did not withdraw")
	}
	e.Penalize("a")
	for i := 0; i < 20; i++ {
		if d, _ := e.Pick(small, nil); d.Edge.Id != "b" {
			t.Fatal("penalized edge picked")
		}
	}
	// With the other edge out too, the penalized one is a last resort.
	if d, err := e.Pick(small, map[string]bool{"b": true}); err != nil || d.Edge.Id != "a" {
		t.Fatalf("only a penalized edge left: %v %v", d, err)
	}
	e.now = func() float64 { return 123 }
	seenA := false
	for i := 0; i < 50 && !seenA; i++ {
		d, _ := e.Pick(small, nil)
		seenA = d.Edge.Id == "a"
	}
	if !seenA {
		t.Fatal("penalty did not expire")
	}
}

// maxOverMean places n sandboxes and reports max/mean load across edges.
func maxOverMean(k, edges, n int) float64 {
	var es []*pb.EdgeState
	for i := 0; i < edges; i++ {
		es = append(es, edge(fmt.Sprintf("e%d", i), ZoneOnprem, 1e6, 1<<30))
	}
	e := engine(k, es...)
	for i := 0; i < n; i++ {
		e.Pick(small, nil)
	}
	maxN, total := 0, 0
	for _, o := range e.overlay {
		maxN = max(maxN, len(o.entries))
		total += len(o.entries)
	}
	return float64(maxN) / (float64(total) / float64(edges))
}

// TestActualUsage: with CPU overcommitted, two edges with the same
// allocation differ by what their hosts really use (spec §3.4).
func TestActualUsage(t *testing.T) {
	busy := edge("busy", ZoneOnprem, 100, 1000)
	busy.CpuUsed = 0.95
	swapped := edge("swapped", ZoneOnprem, 100, 1000)
	swapped.MemUsed = 0.9
	calm := edge("calm", ZoneOnprem, 100, 1000)
	calm.CpuUsed, calm.MemUsed = 0.2, 0.3
	for _, other := range []*pb.EdgeState{busy, swapped} {
		e := engine(2, other, calm)
		for i := 0; i < 20; i++ {
			d, err := e.Pick(small, nil)
			if err != nil || d.Edge.Id != "calm" {
				t.Fatalf("vs %s, pick %d: %v %v", other.Id, i, d, err)
			}
			if math.Abs(d.Load-0.3) > 1e-9 {
				t.Fatalf("load of calm: %v, want 0.3 (its memory use)", d.Load)
			}
			e.Cancel(d)
		}
	}
	// Allocation still counts when it is the higher of the two.
	alloc := edge("alloc", ZoneOnprem, 100, 1000)
	alloc.Alloc.CpuCores = 80
	alloc.CpuUsed = 0.1
	if d, _ := engine(2, alloc, calm).Pick(small, nil); d.Edge.Id != "calm" {
		t.Fatalf("an edge 80%% allocated beat one 30%% used: %s", d.Edge.Id)
	}
	// An edge over its CPU pressure limit is out, and the error says why.
	hot := edge("hot", ZoneOnprem, 100, 1000)
	hot.UnderPressure, hot.Pressure = true, "cpu"
	if _, err := engine(2, hot).Pick(small, nil); err == nil || !strings.Contains(err.Error(), "1 edge(s) under cpu pressure") {
		t.Fatalf("cpu pressure not explained: %v", err)
	}
	// Baselines below the floor (1.6% and 3% of memory, as bm1 and bm2
	// idle) do not count: the edges tie and share the placements.
	quiet, nfs := edge("quiet", ZoneOnprem, 100, 1000), edge("nfs", ZoneOnprem, 100, 1000)
	quiet.MemUsed, nfs.MemUsed = 0.016, 0.03
	e := engine(2, quiet, nfs)
	got := map[string]int{}
	for i := 0; i < 200; i++ {
		d, err := e.Pick(small, nil)
		if err != nil {
			t.Fatal(err)
		}
		got[d.Edge.Id]++
		e.Cancel(d)
	}
	if got["nfs"] < 60 || got["quiet"] < 60 {
		t.Fatalf("idle edges with different baselines: %v", got)
	}
}

func TestPowerOfTwoBeatsRandom(t *testing.T) {
	r1 := maxOverMean(1, 100, 20000)
	r2 := maxOverMean(2, 100, 20000)
	t.Logf("max/mean: random=%.3f power-of-2=%.3f", r1, r2)
	if r2 >= r1 || r2 > 1.05 {
		t.Fatalf("power-of-2 should balance better: random=%.3f p2=%.3f", r1, r2)
	}
}

func TestBursting(t *testing.T) {
	on := edge("on", ZoneOnprem, 100, 100)
	cl := edge("cl", ZoneCloud, 100, 100)
	req := Request{Backend: "container", Image: "img:ok", Res: &pb.Resources{CpuCores: 1}}
	notEligible := Request{Backend: "container", Image: "img:other", Res: &pb.Resources{CpuCores: 1}}

	// Below threshold: eligible requests stay on-prem.
	on.Alloc.CpuCores = 50
	e := engine(2, on, cl)
	for i := 0; i < 50; i++ {
		d, _ := e.Pick(req, nil)
		if d.Burst {
			t.Fatal("burst below threshold")
		}
		e.Cancel(d)
	}
	// At 90% utilization, p = (0.9-0.8)/0.2 = 0.5 of eligible requests burst.
	on.Alloc.CpuCores = 90
	e = engine(2, on, cl)
	bursts := 0
	for i := 0; i < 4000; i++ {
		d, _ := e.Pick(req, nil)
		if d.Burst {
			bursts++
		}
		e.Cancel(d)
		d2, _ := e.Pick(notEligible, nil)
		if d2.Burst {
			t.Fatal("ineligible request burst")
		}
		e.Cancel(d2)
	}
	if frac := float64(bursts) / 4000; math.Abs(frac-0.5) > 0.05 {
		t.Fatalf("burst fraction %.3f, want ~0.5", frac)
	}
	// On-prem full: eligible requests fall back to cloud, others fail.
	on.Alloc.CpuCores = 100
	e = engine(2, on, cl)
	if d, err := e.Pick(req, nil); err != nil || d.Edge.Id != "cl" {
		t.Fatalf("fallback: %v %v", d, err)
	}
	if _, err := e.Pick(notEligible, nil); err == nil {
		t.Fatal("ineligible request must not go to cloud")
	}
}

func TestImageAwarePlacement(t *testing.T) {
	a, b, c := edge("a", ZoneOnprem, 100, 100), edge("b", ZoneOnprem, 100, 100), edge("c", ZoneOnprem, 100, 100)
	a.ImagesByBackend = map[string]*pb.ImageList{"container": {Names: []string{"py:3.12", "node:20"}}}
	b.ImagesByBackend = map[string]*pb.ImageList{"container": {Names: []string{"node:20"}}}
	// c reports no list for "container": it runs any image (shared store).
	e := engine(2, a, b)
	py := Request{Backend: "container", Image: "py:3.12", Res: &pb.Resources{CpuCores: 1}}
	for i := 0; i < 30; i++ {
		d, err := e.Pick(py, nil)
		if err != nil || d.Edge.Id != "a" {
			t.Fatalf("py:3.12 must go to a: %v %v", d, err)
		}
		e.Cancel(d)
	}
	if _, err := e.Pick(Request{Backend: "container", Image: "rust:1", Res: &pb.Resources{}}, nil); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("missing image: want not_found, got %v", err)
	}
	// The only edge with the image is excluded: that is a capacity problem.
	if _, err := e.Pick(py, map[string]bool{"a": true}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("image edge full: want no_capacity, got %v", err)
	}
	// An unrestricted edge can run anything.
	e = engine(2, b, c)
	if d, err := e.Pick(Request{Backend: "container", Image: "rust:1", Res: &pb.Resources{}}, nil); err != nil || d.Edge.Id != "c" {
		t.Fatalf("unrestricted edge: %v %v", d, err)
	}
}

func TestDiskAwarePlacement(t *testing.T) {
	a, b := edge("a", ZoneOnprem, 64, 100), edge("b", ZoneOnprem, 64, 100)
	for _, ed := range []*pb.EdgeState{a, b} {
		ed.Capacity.DiskMb = 1000
		ed.Capacity.DefaultDiskMb = map[string]int64{"sim": 400}
	}
	b.Alloc.DiskMb = 900
	e := engine(2, a, b)
	// Default-sized disks only fit on a, twice (the overlay counts the first).
	for i := 0; i < 2; i++ {
		d, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{}}, nil)
		if err != nil || d.Edge.Id != "a" {
			t.Fatalf("pick %d: %v %v", i, d, err)
		}
	}
	if _, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{}}, nil); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("over disk: %v", err)
	}
	if d, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{DiskMb: 100}}, nil); err != nil || d.Edge.Id != "b" && d.Edge.Id != "a" {
		t.Fatalf("small explicit disk: %v %v", d, err)
	}
	// Pressure is explained in the error.
	a.UnderPressure, a.Pressure = true, "disk"
	b.UnderPressure, b.Pressure = true, "disk"
	e.UpdateSnapshot(&pb.Snapshot{Edges: []*pb.EdgeState{a, b}, TakenAt: 1e12})
	if _, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{}}, nil); !strings.Contains(err.Error(), "2 edge(s) under disk pressure") {
		t.Fatalf("pressure not explained: %v", err)
	}
}

func TestPreferEdge(t *testing.T) {
	a, b, c := edge("a", ZoneOnprem, 64, 100), edge("b", ZoneOnprem, 64, 3), edge("c", ZoneOnprem, 64, 100)
	b.Alloc.CpuCores = 60 // the most loaded edge
	e := engine(2, a, b, c)
	req := Request{Backend: "sim", Res: &pb.Resources{CpuCores: 1}, PreferEdge: "b"}
	// b wins while it has room (3 slots), then placement balances as usual.
	for i := 0; i < 3; i++ {
		if d, err := e.Pick(req, nil); err != nil || d.Edge.Id != "b" {
			t.Fatalf("pick %d: %v %v", i, d, err)
		}
	}
	if d, err := e.Pick(req, nil); err != nil || d.Edge.Id == "b" {
		t.Fatalf("full preferred edge: %v %v", d, err)
	}
	// An excluded (rejecting) or unhealthy preferred edge is skipped.
	e2 := engine(2, edge("a", ZoneOnprem, 64, 100), edge("b", ZoneOnprem, 64, 100))
	if d, err := e2.Pick(req, map[string]bool{"b": true}); err != nil || d.Edge.Id != "a" {
		t.Fatalf("excluded preferred edge: %v %v", d, err)
	}
	u := edge("b", ZoneOnprem, 64, 100)
	u.Healthy = false
	e3 := engine(2, edge("a", ZoneOnprem, 64, 100), u)
	if d, err := e3.Pick(req, nil); err != nil || d.Edge.Id != "a" {
		t.Fatalf("unhealthy preferred edge: %v %v", d, err)
	}
}

func TestSnapshotCachePreference(t *testing.T) {
	a, b, c, d := edge("a", ZoneOnprem, 64, 100), edge("b", ZoneOnprem, 64, 2), edge("c", ZoneOnprem, 64, 100), edge("d", ZoneOnprem, 64, 100)
	b.Snapshots, d.Snapshots = []string{"snap-x"}, []string{"snap-y"}
	b.Alloc.CpuCores = 60 // loaded, but it caches the snapshot
	e := engine(2, a, b, c, d)
	req := Request{Backend: "sim", Res: &pb.Resources{CpuCores: 1}, Snapshot: "snap-x"}
	for i := 0; i < 2; i++ {
		if got, err := e.Pick(req, nil); err != nil || got.Edge.Id != "b" {
			t.Fatalf("pick %d: %v %v", i, got, err)
		}
	}
	// Full: any other edge.
	if got, err := e.Pick(req, nil); err != nil || got.Edge.Id == "b" {
		t.Fatalf("full caching edge: %v %v", got, err)
	}
	// Uncached snapshots and plain creations balance as usual.
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		got, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{}, Snapshot: "snap-z"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[got.Edge.Id] = true
	}
	if len(seen) < 3 {
		t.Fatalf("uncached snapshot not balanced: %v", seen)
	}
}

// TestRuntimeVersions: a sandbox from a memory snapshot only goes to edges
// running the Firecracker that made it (spec §28.12); edges that report no
// version are not excluded.
func TestRuntimeVersions(t *testing.T) {
	old := edge("old", ZoneOnprem, 100, 1000)
	old.RuntimeVersions = map[string]string{"firecracker": "1.15.1"}
	cur := edge("cur", ZoneOnprem, 100, 1000)
	cur.RuntimeVersions = map[string]string{"firecracker": "1.17.0"}
	unknown := edge("unknown", ZoneOnprem, 100, 1000)
	e := engine(2, old, cur, unknown)
	req := small
	req.Runtime = map[string]string{"firecracker": "1.17.0"}
	for i := 0; i < 50; i++ {
		d, err := e.Pick(req, nil)
		if err != nil || d.Edge.Id == "old" {
			t.Fatalf("pick %d: %v %v", i, d, err)
		}
		e.Cancel(d)
	}
	req.PreferEdge = "old"
	if d, err := e.Pick(req, nil); err != nil || d.Edge.Id == "old" {
		t.Fatalf("preferred edge with another version: %v %v", d, err)
	}
	_, err := e.Pick(req, map[string]bool{"cur": true, "unknown": true})
	if rpcutil.Reason(err) != rpcutil.NoCapacity || !strings.Contains(err.Error(), "firecracker 1.17.0") {
		t.Fatalf("only an edge with another version left: %v", err)
	}
}

// TestNonFiniteCPU: NaN passes every capacity comparison, so it used to
// fit, poison the edge's overlay, and make the next pick select no edge
// (a nil dereference that took the apiserver down).
func TestNonFiniteCPU(t *testing.T) {
	e := engine(2, edge("a", ZoneOnprem, 10, 100))
	for _, cpu := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		if _, err := e.Pick(Request{Backend: "sim", Res: &pb.Resources{CpuCores: cpu}}, nil); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Fatalf("cpu %g: %v", cpu, err)
		}
	}
	if d, err := e.Pick(small, nil); err != nil || d.Edge.Id != "a" {
		t.Fatalf("after: %v %v", d, err)
	}
}
