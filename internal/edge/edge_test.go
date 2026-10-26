package edge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/host"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	e        *Edge
	sim      *backend.Sim
	clk      *clock
	mu       sync.Mutex
	released []string
	dead     map[string]bool
}

func newFixture(t *testing.T, maxSb int32) *fixture {
	t.Helper()
	f := &fixture{clk: &clock{t: time.Unix(1000, 0)}, dead: map[string]bool{}}
	f.sim = backend.NewSim("sim", config.Backend{})
	f.sim.Dead = func(id string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.dead[id] }
	cfg := config.Edge{ID: "e1", Capacity: config.Resources{CPUCores: 4, MemoryMB: 8192},
		CPUOvercommit: 2, Backends: map[string]config.Backend{"sim": {MaxSandboxes: maxSb}}}
	f.e = New(cfg, map[string]backend.Backend{"sim": f.sim})
	f.e.now = f.clk.now
	f.e.Release = func(l string) { f.mu.Lock(); f.released = append(f.released, l); f.mu.Unlock() }
	return f
}

func (f *fixture) create(t *testing.T, spec *pb.SandboxSpec) (*pb.Sandbox, error) {
	t.Helper()
	if spec.Backend == "" {
		spec.Backend = "sim"
	}
	return f.e.Create(context.Background(), &pb.EdgeCreateRequest{
		Id: ids.Sandbox("e1", ids.NewLease()), Project: "root/rl", Principal: "p", Spec: spec})
}

func cpu(c float64) *pb.Resources { return &pb.Resources{CpuCores: c, MemoryMb: 1024} }

func TestAdmission(t *testing.T) {
	f := newFixture(t, 100)
	// Allocatable CPU = 4 cores x overcommit 2 = 8.
	for i := 0; i < 4; i++ {
		if _, err := f.create(t, &pb.SandboxSpec{Resources: cpu(2)}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	if rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("want no_capacity, got %v", err)
	}
	st := f.e.Status(false).State
	if st.Alloc.CpuCores != 8 || st.CountByBackend["sim"] != 4 || st.TotalRejected != 1 {
		t.Fatalf("status = %+v", st)
	}
	if _, err := f.create(t, &pb.SandboxSpec{Backend: "microvm"}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("unknown backend: %v", err)
	}
	_, err = f.e.Create(context.Background(), &pb.EdgeCreateRequest{Id: ids.Sandbox("e2", ids.NewLease()), Spec: &pb.SandboxSpec{Backend: "sim"}})
	if rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("foreign id: %v", err)
	}
}

func TestSlotLimitAndDrain(t *testing.T) {
	f := newFixture(t, 2)
	f.create(t, &pb.SandboxSpec{})
	f.create(t, &pb.SandboxSpec{})
	if _, err := f.create(t, &pb.SandboxSpec{}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("slot limit: %v", err)
	}
	f2 := newFixture(t, 10)
	f2.e.SetDraining(true)
	if _, err := f2.create(t, &pb.SandboxSpec{}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("draining: %v", err)
	}
}

func TestIdempotentCreate(t *testing.T) {
	f := newFixture(t, 10)
	req := &pb.EdgeCreateRequest{Id: ids.Sandbox("e1", ids.NewLease()), Project: "root", Spec: &pb.SandboxSpec{Backend: "sim", Resources: cpu(1)}}
	a, err := f.e.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.e.Create(context.Background(), req)
	if err != nil || a.Id != b.Id {
		t.Fatal(err)
	}
	if st := f.e.Status(false).State; st.CountByBackend["sim"] != 1 {
		t.Fatalf("double charged: %v", st.CountByBackend)
	}
}

func TestLifecycleAndRelease(t *testing.T) {
	f := newFixture(t, 10)
	sb, _ := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	ctx := context.Background()
	if s, err := f.e.Pause(ctx, sb.Id); err != nil || s.State != pb.SandboxState_PAUSED {
		t.Fatalf("pause: %v %v", s, err)
	}
	// Transparent resume on any request.
	if s, err := f.e.Touch(ctx, sb.Id); err != nil || s.State != pb.SandboxState_RUNNING {
		t.Fatalf("touch: %v %v", s, err)
	}
	if s, _ := f.e.Stop(ctx, sb.Id); s.State != pb.SandboxState_STOPPED {
		t.Fatalf("stop: %v", s)
	}
	f.e.Stop(ctx, sb.Id) // idempotent
	if _, err := f.e.Pause(ctx, sb.Id); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("pause stopped: %v", err)
	}
	_, lease, _ := ids.Parse(sb.Id)
	if len(f.released) != 1 || f.released[0] != lease {
		t.Fatalf("released = %v", f.released)
	}
	if st := f.e.Status(true); st.State.Alloc.CpuCores != 0 || len(st.Leases) != 0 {
		t.Fatalf("not freed: %+v", st)
	}
}

func TestTTL(t *testing.T) {
	f := newFixture(t, 10)
	ctx := context.Background()
	idle, _ := f.create(t, &pb.SandboxSpec{TtlRunningStopS: 60})
	paused, _ := f.create(t, &pb.SandboxSpec{TtlRunningStopS: 60})
	capped, _ := f.create(t, &pb.SandboxSpec{TtlMaxS: 100})
	f.e.Pause(ctx, paused.Id)

	f.clk.add(50 * time.Second)
	f.e.Touch(ctx, capped.Id)
	f.e.Sweep(ctx)
	f.clk.add(20 * time.Second) // idle 70s > 60s
	f.e.Sweep(ctx)
	waitState(t, f.e, idle.Id, pb.SandboxState_STOPPED)
	// Paused time does not count toward the idle TTL.
	if s, _ := f.e.Get(paused.Id); s.State != pb.SandboxState_PAUSED {
		t.Fatalf("paused sandbox reaped: %v", s.State)
	}
	f.clk.add(40 * time.Second) // capped lives 110s > ttl_max even though touched
	f.e.Sweep(ctx)
	waitState(t, f.e, capped.Id, pb.SandboxState_STOPPED)
	// Ended records are garbage-collected after the retention window.
	f.clk.add(time.Hour)
	f.e.Sweep(ctx)
	if _, err := f.e.Get(idle.Id); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("not gc'd: %v", err)
	}
}

// TestAutoPause: with ttl_paused_s, the timeouts pause instead of stopping
// (spec §37.11); the paused sandbox is kept ttl_paused_s more, then stopped,
// and a call resumes it before that.
func TestAutoPause(t *testing.T) {
	f := newFixture(t, 10)
	ctx := context.Background()
	deadline, _ := f.create(t, &pb.SandboxSpec{TtlMaxS: 100, TtlPausedS: 1000})
	idle, _ := f.create(t, &pb.SandboxSpec{TtlRunningStopS: 60, TtlPausedS: 1000})

	f.clk.add(70 * time.Second)
	f.e.Sweep(ctx)
	waitState(t, f.e, idle.Id, pb.SandboxState_PAUSED)
	f.clk.add(40 * time.Second)
	f.e.Touch(ctx, deadline.Id) // activity does not hold off the deadline
	f.e.Sweep(ctx)
	waitState(t, f.e, deadline.Id, pb.SandboxState_PAUSED)
	if s, _ := f.e.Get(deadline.Id); s.Spec.TtlMaxS != 110+1000 {
		t.Fatalf("kept until %d s", s.Spec.TtlMaxS)
	}

	// A call resumes it; idle again, it pauses again.
	if _, err := f.e.Touch(ctx, idle.Id); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.e.Get(idle.Id); s.State != pb.SandboxState_RUNNING {
		t.Fatalf("touched: %v", s.State)
	}
	f.clk.add(61 * time.Second)
	f.e.Sweep(ctx)
	waitState(t, f.e, idle.Id, pb.SandboxState_PAUSED)

	// Kept paused ttl_paused_s, then stopped.
	f.clk.add(1000 * time.Second)
	f.e.Sweep(ctx)
	waitState(t, f.e, deadline.Id, pb.SandboxState_STOPPED)
}

func TestProbeFailure(t *testing.T) {
	f := newFixture(t, 10)
	sb, _ := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	f.mu.Lock()
	f.dead[sb.Id] = true
	f.mu.Unlock()
	f.e.Sweep(context.Background())
	if s, _ := f.e.Get(sb.Id); s.State != pb.SandboxState_FAILED {
		t.Fatalf("state = %v", s.State)
	}
	if len(f.released) != 1 {
		t.Fatal("lease not released")
	}
}

func TestTaskAction(t *testing.T) {
	f := newFixture(t, 20)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		f.create(t, &pb.SandboxSpec{TaskId: "job-1"})
	}
	other, _ := f.create(t, &pb.SandboxSpec{TaskId: "job-2"})
	res := f.e.TaskAction(ctx, "root", "job-1", pb.TaskAction_TASK_PAUSE)
	if res.Affected != 5 || res.Failed != 0 {
		t.Fatalf("pause: %+v", res)
	}
	if s, _ := f.e.Get(other.Id); s.State != pb.SandboxState_RUNNING {
		t.Fatal("other task affected")
	}
	if res := f.e.TaskAction(ctx, "root/elsewhere", "job-1", pb.TaskAction_TASK_STOP); res.Affected != 0 {
		t.Fatal("project scoping ignored")
	}
	if res := f.e.TaskAction(ctx, "root", "job-1", pb.TaskAction_TASK_STOP); res.Affected != 5 {
		t.Fatalf("stop: %+v", res)
	}
	if st := f.e.Status(false).State; st.ByTask["job-1"] != 0 || st.ByTask["job-2"] != 1 {
		t.Fatalf("by_task = %v", st.ByTask)
	}
}

func waitState(t *testing.T, e *Edge, id string, want pb.SandboxState) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s, _ := e.Get(id); s != nil && s.State == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s, _ := e.Get(id)
	t.Fatalf("%s: state %v, want %v", id, s.GetState(), want)
}

func TestMemoryPressureAdmission(t *testing.T) {
	f := newFixture(t, 10)
	f.e.Pressure = &host.Pressure{ReserveMB: 1 << 40} // always "under pressure"
	_, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	if rpcutil.Reason(err) != rpcutil.NoCapacity || !strings.Contains(err.Error(), "memory pressure") {
		t.Fatalf("want memory-pressure rejection, got %v", err)
	}
	st := f.e.Status(false).State
	if !st.UnderPressure || st.MemAvailableMb <= 0 || st.TotalRejected != 1 || st.Alloc.CpuCores != 0 {
		t.Fatalf("status = %+v", st)
	}
	f.e.Pressure = &host.Pressure{ReserveMB: 1}
	if _, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)}); err != nil {
		t.Fatalf("no pressure: %v", err)
	}
}

func TestCPUPressureAdmission(t *testing.T) {
	f := newFixture(t, 10)
	dir := t.TempDir()
	psi := filepath.Join(dir, "psi")
	os.WriteFile(psi, []byte("some avg10=80.00 avg60=0 avg300=0 total=1\n"), 0o644)
	f.e.Usage = &host.Usage{StatPath: filepath.Join(dir, "absent"), PSIPath: psi, MemPath: filepath.Join(dir, "absent")}
	// Without a limit the pressure is only reported.
	if _, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)}); err != nil {
		t.Fatalf("no limit: %v", err)
	}
	if st := f.e.Status(false).State; st.CpuPressure != 80 || st.UnderPressure {
		t.Fatalf("status without a limit: pressure %v under %v", st.CpuPressure, st.UnderPressure)
	}
	f.e.CPUPressureLimit = 50
	_, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	if rpcutil.Reason(err) != rpcutil.NoCapacity || !strings.Contains(err.Error(), "CPU pressure") {
		t.Fatalf("want CPU-pressure rejection, got %v", err)
	}
	if st := f.e.Status(false).State; !st.UnderPressure || st.Pressure != "cpu" {
		t.Fatalf("status over the limit: under %v %q", st.UnderPressure, st.Pressure)
	}
	f.e.CPUPressureLimit = 90
	if _, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)}); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
}

func TestRecoverFromRecords(t *testing.T) {
	dir := t.TempDir()
	f := newFixture(t, 10)
	if err := f.e.EnableStore(dir); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	running, _ := f.create(t, &pb.SandboxSpec{Resources: cpu(1), TaskId: "job"})
	paused, _ := f.create(t, &pb.SandboxSpec{Resources: cpu(2)})
	f.e.Pause(ctx, paused.Id)
	stopped, _ := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	f.e.Stop(ctx, stopped.Id)
	// A record left mid-creation by a crash.
	crashLease := ids.NewLease()
	st, _ := newStore(dir)
	st.save(crashLease, &pb.Sandbox{Id: ids.Sandbox("e1", crashLease), Project: "root",
		Spec: &pb.SandboxSpec{Backend: "sim", Resources: cpu(1)}, State: pb.SandboxState_CREATING})

	// "Restart": a new Edge over the same records (the old one is abandoned).
	f2 := newFixture(t, 10)
	f2.e.EnableStore(dir)
	stats := f2.e.Recover(ctx)
	if stats.Adopted != 2 || stats.Failed != 1 {
		t.Fatalf("recover: %+v", stats)
	}
	if s, err := f2.e.Get(running.Id); err != nil || s.State != pb.SandboxState_RUNNING || s.Spec.TaskId != "job" {
		t.Fatalf("running: %v %v", s, err)
	}
	if s, _ := f2.e.Get(paused.Id); s.State != pb.SandboxState_PAUSED {
		t.Fatalf("paused: %v", s.State)
	}
	if _, err := f2.e.Get(stopped.Id); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("stopped sandbox resurrected: %v", err)
	}
	// The interrupted creation's lease is released; resources re-charged.
	if len(f2.released) != 1 || f2.released[0] != crashLease {
		t.Fatalf("released = %v", f2.released)
	}
	if a := f2.e.Status(false).State.Alloc.CpuCores; a != 3 {
		t.Fatalf("alloc after recovery = %v, want 3", a)
	}
	// It stays visible as ended (spec §27.7): a retried stop or a retried
	// create's lookup sees FAILED, not not_found.
	crashID := ids.Sandbox("e1", crashLease)
	if s, err := f2.e.Get(crashID); err != nil || s.State != pb.SandboxState_FAILED {
		t.Fatalf("interrupted creation after recovery: %v %v", s, err)
	}
	if s, err := f2.e.Stop(ctx, crashID); err != nil || s.State != pb.SandboxState_FAILED {
		t.Fatalf("stop of the interrupted creation: %v %v", s, err)
	}
	// Adopted sandboxes are fully operational.
	if s, err := f2.e.Touch(ctx, paused.Id); err != nil || s.State != pb.SandboxState_RUNNING {
		t.Fatalf("touch adopted: %v %v", s, err)
	}
	f2.e.Stop(ctx, running.Id)
	recs, _ := st.load()
	if len(recs) != 1 {
		t.Fatalf("records after stop = %d, want 1", len(recs))
	}
}

type imageSim struct {
	*backend.Sim
	images []string
}

func (s imageSim) Images() []string { return s.images }

func TestImageNotOnEdgeIsRetryable(t *testing.T) {
	f := newFixture(t, 10)
	f.e.backends["sim"] = imageSim{Sim: f.sim, images: []string{"py:3.12"}}
	if _, err := f.create(t, &pb.SandboxSpec{Image: "py:3.12"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.create(t, &pb.SandboxSpec{Image: "rust:1"})
	if rpcutil.Reason(err) != rpcutil.NoCapacity || !strings.Contains(err.Error(), "does not have image") {
		t.Fatalf("want retryable no_capacity, got %v", err)
	}
	if st := f.e.Status(false).State; len(st.ImagesByBackend["sim"].GetNames()) != 1 || st.TotalRejected != 0 {
		t.Fatalf("status images = %v", st.ImagesByBackend)
	}
}

func TestDiskAdmission(t *testing.T) {
	f := &fixture{clk: &clock{t: time.Unix(1000, 0)}, dead: map[string]bool{}}
	f.sim = backend.NewSim("sim", config.Backend{})
	cfg := config.Edge{ID: "e1", Capacity: config.Resources{CPUCores: 4, MemoryMB: 8192, DiskMB: 1000},
		DiskOvercommit: 2, Backends: map[string]config.Backend{"sim": {MaxSandboxes: 100, DefaultDiskMB: 500}}}
	f.e = New(cfg, map[string]backend.Backend{"sim": f.sim})
	f.e.now = f.clk.now
	// Capacity 2000 MB: three default (500 MB) disks plus one of 400 MB fit.
	for i := 0; i < 3; i++ {
		sb, err := f.create(t, &pb.SandboxSpec{})
		if err != nil {
			t.Fatal(err)
		}
		if sb.Spec.Resources.DiskMb != 500 {
			t.Fatalf("effective disk not recorded: %v", sb.Spec.Resources)
		}
	}
	big, _ := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{DiskMb: 400}})
	if _, err := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{DiskMb: 200}}); rpcutil.Reason(err) != rpcutil.NoCapacity ||
		!strings.Contains(err.Error(), "disk") {
		t.Fatalf("over disk capacity: %v", err)
	}
	st := f.e.Status(false).State
	if st.Alloc.DiskMb != 1900 || st.Capacity.DiskMb != 2000 || st.Capacity.DefaultDiskMb["sim"] != 500 {
		t.Fatalf("status: alloc %v capacity %v", st.Alloc, st.Capacity)
	}
	f.e.Stop(context.Background(), big.Id)
	if _, err := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{DiskMb: 100}}); err != nil {
		t.Fatalf("disk not released on stop: %v", err)
	}

	// Free space below the reserve rejects creations and is reported.
	f.e.DiskPressure = &host.DiskPressure{Path: t.TempDir(), ReserveMB: 1 << 40}
	if _, err := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{DiskMb: 1}}); rpcutil.Reason(err) != rpcutil.NoCapacity ||
		!strings.Contains(err.Error(), "disk pressure") {
		t.Fatalf("under disk pressure: %v", err)
	}
	if st := f.e.Status(false).State; !st.UnderPressure || st.Pressure != "disk" || st.DiskAvailableMb <= 0 {
		t.Fatalf("pressure not reported: %v %q %d", st.UnderPressure, st.Pressure, st.DiskAvailableMb)
	}
}

// TestPausedMemCharge (spec §24): with paused_mem_charge 0.25, a paused
// sandbox whose pause frees its memory counts a quarter of it; resuming
// charges it all again.
func TestPausedMemCharge(t *testing.T) {
	f := newFixture(t, 100)
	quarter := 0.25
	f.e.cfg.PausedMemCharge = &quarter
	mem := &pb.Resources{CpuCores: 0.1, MemoryMb: 4096}
	a, err := f.create(t, &pb.SandboxSpec{Resources: mem})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.create(t, &pb.SandboxSpec{Resources: mem}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.create(t, &pb.SandboxSpec{Resources: mem}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("third 4 GB sandbox on 8 GB: %v", err)
	}
	ctx := context.Background()
	if _, err := f.e.Pause(ctx, a.Id); err != nil {
		t.Fatal(err)
	}
	if got := f.e.Status(false).State.Alloc.MemoryMb; got != 4096+1024 {
		t.Fatalf("allocated with one paused: %d MB", got)
	}
	// Not enough for another 4 GB (5 GB + 4 GB > 8 GB); 2 GB fits.
	if _, err := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 0.1, MemoryMb: 2048}}); err != nil {
		t.Fatal(err)
	}
	// Resuming overcommits for a while: no new sandboxes until it drops.
	if _, err := f.e.Resume(ctx, a.Id); err != nil {
		t.Fatal(err)
	}
	if got := f.e.Status(false).State.Alloc.MemoryMb; got != 4096*2+2048 {
		t.Fatalf("allocated after resume: %d MB", got)
	}
	if _, err := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 128}}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("over budget: %v", err)
	}
	// A sandbox ending while paused gives back what it was charged.
	f.e.Pause(ctx, a.Id)
	f.e.Stop(ctx, a.Id)
	if got := f.e.Status(false).State.Alloc.MemoryMb; got != 4096+2048 {
		t.Fatalf("allocated after stopping the paused one: %d MB", got)
	}
}

// TestSqueeze (spec §24): under node memory pressure balloons inflate, BE
// and idle sandboxes first, a quarter of their memory per pass, up to
// half; with room again they deflate.
func TestSqueeze(t *testing.T) {
	f := newFixture(t, 100)
	ctx := context.Background()
	mem := func(qos string) *pb.SandboxSpec {
		return &pb.SandboxSpec{Qos: qos, Resources: &pb.Resources{CpuCores: 0.1, MemoryMb: 1024}}
	}
	ls, _ := f.create(t, mem("LS"))
	f.clk.add(time.Minute)
	busy, _ := f.create(t, mem("LS"))
	be, _ := f.create(t, mem("BE"))
	// Reserve 1000 MB, 1300 available: 200 MB to find.
	f.e.balance(ctx, 1300, 1000)
	if got := f.sim.SqueezedMB(be.Id); got != 256 {
		t.Fatalf("BE balloon %d MB, want 256", got)
	}
	if f.sim.SqueezedMB(ls.Id) != 0 || f.sim.SqueezedMB(busy.Id) != 0 {
		t.Fatal("LS squeezed while BE had enough")
	}
	// Tighter: BE to half, then the longest idle LS.
	f.e.balance(ctx, 600, 1000)
	f.e.balance(ctx, 600, 1000)
	if got := f.sim.SqueezedMB(be.Id); got != 512 {
		t.Fatalf("BE balloon %d MB, want the 512 cap", got)
	}
	if f.sim.SqueezedMB(ls.Id) == 0 || f.sim.SqueezedMB(busy.Id) > f.sim.SqueezedMB(ls.Id) {
		t.Fatalf("idle LS %d MB, busy LS %d MB", f.sim.SqueezedMB(ls.Id), f.sim.SqueezedMB(busy.Id))
	}
	// Room again: everything back.
	f.e.balance(ctx, 5000, 1000)
	for _, sb := range []*pb.Sandbox{ls, busy, be} {
		if got := f.sim.SqueezedMB(sb.Id); got != 0 {
			t.Errorf("%s still squeezed: %d MB", sb.Id, got)
		}
	}
}

// TestAbandonedCreation (spec §36): a sandbox whose caller gave up while it
// was being created, and placed it elsewhere or released the lease, is
// dropped when its creation ends; its lease goes back to IAM, which keeps it
// when it is bound elsewhere. Unknown (IAM unreachable) or still ours: kept.
func TestAbandonedCreation(t *testing.T) {
	for name, c := range map[string]struct {
		held bool
		edge string
		err  error
		kept bool
	}{
		"moved":       {held: true, edge: "e2"},
		"released":    {},
		"ours":        {held: true, edge: "e1", kept: true},
		"unbound":     {held: true, kept: true},
		"unreachable": {err: errors.New("iam down"), kept: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 100)
			f.e.LeaseEdge = func(context.Context, string) (bool, string, error) { return c.held, c.edge, c.err }
			id := ids.Sandbox("e1", ids.NewLease())
			_, lease, _ := ids.Parse(id)
			sb, err := f.e.Create(context.Background(), &pb.EdgeCreateRequest{Id: id, Project: "root/rl", Principal: "p",
				Spec: &pb.SandboxSpec{Backend: "sim", Resources: cpu(1)}})
			live := len(f.e.Status(true).Leases)
			if c.kept {
				if err != nil || sb.State != pb.SandboxState_RUNNING || live != 1 {
					t.Fatalf("kept: %v %v, %d live", sb, err, live)
				}
				return
			}
			if rpcutil.Reason(err) != rpcutil.Unavailable || !strings.Contains(err.Error(), "abandoned") || live != 0 {
				t.Fatalf("dropped: %v, %d live", err, live)
			}
			if got, _ := f.e.Get(id); got.GetState() != pb.SandboxState_FAILED {
				t.Fatalf("state %v", got.GetState())
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.released) != 1 || f.released[0] != lease {
				t.Fatalf("released %v", f.released)
			}
			if st := f.e.Status(false).State; st.Alloc.CpuCores != 0 {
				t.Fatalf("resources still charged: %+v", st.Alloc)
			}
		})
	}
}

// TestUnsavedRecord: a creation whose RUNNING record cannot be written is
// not reported (a restart would find it CREATING and remove it); a record
// that falls behind later is written again by the sweep.
func TestUnsavedRecord(t *testing.T) {
	dir := t.TempDir()
	f := newFixture(t, 10)
	if err := f.e.EnableStore(dir); err != nil {
		t.Fatal(err)
	}
	f.e.backends["sim"] = backend.NewSim("sim", config.Backend{CreateLatencyMs: 300})
	lease := ids.NewLease()
	path := filepath.Join(dir, lease+".json")
	broke := make(chan error, 1)
	go func() { // while the backend creates: the record can no longer be replaced
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if _, err := os.Stat(path); err == nil {
				os.Remove(path)
				os.MkdirAll(filepath.Join(path, "x"), 0o755)
				broke <- nil
				return
			}
		}
		broke <- os.ErrNotExist
	}()
	_, err := f.e.Create(context.Background(), &pb.EdgeCreateRequest{
		Id: ids.Sandbox("e1", lease), Project: "root/rl", Principal: "p", Spec: &pb.SandboxSpec{Backend: "sim", Resources: cpu(1)}})
	if err := <-broke; err != nil {
		t.Fatal("no CREATING record was written")
	}
	if rpcutil.Reason(err) != rpcutil.Internal {
		t.Fatalf("create with an unwritable record: %v, want internal", err)
	}
	if s, _ := f.e.Get(ids.Sandbox("e1", lease)); s == nil || s.State != pb.SandboxState_FAILED {
		t.Fatalf("sandbox %v, want failed", s)
	}
	os.RemoveAll(path)

	// Later: a failed write is retried by the sweep.
	f.e.backends["sim"] = f.sim
	sb, err := f.create(t, &pb.SandboxSpec{Resources: cpu(1)})
	if err != nil {
		t.Fatal(err)
	}
	_, l, _ := ids.Parse(sb.Id)
	path = filepath.Join(dir, l+".json")
	os.Remove(path)
	os.MkdirAll(filepath.Join(path, "x"), 0o755)
	if _, err := f.e.Pause(context.Background(), sb.Id); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(path)
	f.e.Sweep(context.Background())
	st, _ := newStore(dir)
	recs, _ := st.load()
	if r := recs[l]; r == nil || r.State != pb.SandboxState_PAUSED {
		t.Fatalf("record after the sweep: %v", r)
	}
}
