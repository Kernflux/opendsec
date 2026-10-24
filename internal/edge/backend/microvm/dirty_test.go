package microvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/images"
)

// TestDirtyTracking (OPENDSEC_BENCH=1; OPENDSEC_BENCH_ROUNDS, default 3):
// spec §19.14, what KVM dirty page logging costs the guest, and how much
// larger mincore makes diff snapshots, with tracking on and off in turns.
func TestDirtyTracking(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	rounds := 3
	if n, err := strconv.Atoi(os.Getenv("OPENDSEC_BENCH_ROUNDS")); err == nil && n > 0 {
		rounds = n
	}
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", dir, "./testdata/memwork")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build memwork: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(filepath.Join(dir, "memwork"))
	if err != nil {
		t.Fatal(err)
	}
	res := map[bool]map[string][]float64{false: {}, true: {}}
	for r := 0; r < rounds; r++ {
		for _, off := range []bool{false, true} {
			if r%2 == 1 {
				off = !off // alternate which goes first
			}
			m := dirtyRound(t, bin, off)
			for k, v := range m {
				res[off][k] = append(res[off][k], v)
			}
			t.Logf("round %d tracking=%v: %v", r, !off, m)
		}
	}
	var keys []string
	for k := range res[false] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "medians of %d rounds\n%-28s %12s %12s %8s\n", rounds, "metric", "tracking", "no tracking", "diff")
	for _, k := range keys {
		on, off := median(res[false][k]), median(res[true][k])
		fmt.Fprintf(&b, "%-28s %12.2f %12.2f %+7.1f%%\n", k, on, off, (on-off)/off*100)
	}
	t.Log("\n" + b.String())
}

const dirtyMB = 1024

// dirtyRound measures one backend: a cold-booted VM, then copies restored
// from its snapshot.
func dirtyRound(t *testing.T, bin []byte, off bool) map[string]float64 {
	f := newBackendWith(t, func(o *Options) { o.NoDirtyTracking = off })
	ctx := context.Background()
	// /dev/shm holds up to half of the memory.
	res := &pb.Resources{CpuCores: 2, MemoryMb: 3072}
	m := map[string]float64{}
	var vms []*backend.Sandbox
	defer func() {
		for _, v := range vms {
			f.b.Stop(context.Background(), v)
		}
	}()
	create := func(spec *pb.SandboxSpec) *backend.Sandbox {
		t.Helper()
		sb, err := f.tryCreate(spec)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		vms = append(vms, sb)
		return sb
	}
	run := func(sb *backend.Sandbox, args string) float64 {
		t.Helper()
		return memwork(t, f.b, sb, args)
	}
	mb := strconv.Itoa(dirtyMB)

	cold := create(&pb.SandboxSpec{Resources: res})
	rt := mustRT(t, f.b, cold)
	if _, err := rt.WriteFile(ctx, &pb.WriteFileRequest{Path: "/tmp/memwork", Data: bin, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	m["cold.touch_ms"] = run(cold, "touch "+mb)
	m["cold.anon_huge_mb"] = float64(anonHugeMB(t, f.b, cold))
	m["cold.rewrite_ms"] = run(cold, "rewrite "+mb)
	m["cold.rand_mops"] = run(cold, "rand "+mb+" 10")
	m["cold.alloc_mops"] = run(cold, "alloc 10")
	t0 := time.Now()
	snap, err := f.b.Snapshot(ctx, cold, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	m["cold.snapshot_ms"] = float64(time.Since(t0).Milliseconds())
	// The snapshot reset the dirty log: the next writes fault again.
	m["cold.rewrite_after_snap_ms"] = run(cold, "rewrite "+mb)
	// What a first pause costs an untracked VM: a full snapshot.
	s, _ := f.b.get(cold.ID)
	v := s.vm()
	if err := v.api.setState(ctx, "Paused"); err != nil {
		t.Fatal(err)
	}
	t0 = time.Now()
	if err := v.api.call(ctx, "PUT", "/snapshot/create", map[string]string{"snapshot_type": "Full",
		"snapshot_path": "/full.vmstate", "mem_file_path": "/full.mem"}, nil); err != nil {
		t.Fatal(err)
	}
	m["cold.full_snapshot_ms"] = float64(time.Since(t0).Milliseconds())
	m["cold.full_snapshot_mb"] = float64(allocatedFile(filepath.Join(s.root, "full.mem")) >> 20)
	f.b.Stop(ctx, cold)

	spec := &pb.SandboxSpec{Snapshot: snap.ID, Resources: res}
	reader, writer, worker := create(spec), create(spec), create(spec)
	m["copy.rand_mops"] = run(worker, "rand "+mb+" 10")
	m["copy.rewrite_ms"] = run(worker, "rewrite "+mb)
	m["copy.rewrite2_ms"] = run(worker, "rewrite "+mb)
	m["copy.alloc_mops"] = run(worker, "alloc 10")
	// A sibling reads all of the buffer; this copy writes 16 MB and pauses.
	run(reader, "read "+mb)
	sh(t, f.b, writer, `dd if=/dev/urandom of=/dev/shm/new bs=1M count=16 status=none`)
	t0 = time.Now()
	if err := f.b.Pause(ctx, writer); err != nil {
		t.Fatal(err)
	}
	m["copy.pause_ms"] = float64(time.Since(t0).Milliseconds())
	s, _ = f.b.get(writer.ID)
	m["copy.pause_merged_mb"] = float64(s.lastPause.Merged >> 20)
	return m
}

// memwork runs the workload and returns the number it prints.
func memwork(t *testing.T, b *Backend, sb *backend.Sandbox, args string) float64 {
	t.Helper()
	rt := mustRT(t, b, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, err := rt.Exec(ctx, &pb.ExecRequest{Cmd: "/tmp/memwork " + args})
	if err != nil {
		t.Fatalf("memwork %s: %v", args, err)
	}
	o := out(r)
	_, v, ok := strings.Cut(o, "=")
	n, err := strconv.ParseFloat(v, 64)
	if r.ExitCode != 0 || !ok || err != nil {
		t.Fatalf("memwork %s: %q %q", args, r.Stdout, r.Stderr)
	}
	return n
}

// anonHugeMB is the VM's guest memory the host backs with transparent huge
// pages.
func anonHugeMB(t *testing.T, b *Backend, sb *backend.Sandbox) int64 {
	s, err := b.get(sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/smaps_rollup", s.vm().pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "AnonHugePages:" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n >> 10
		}
	}
	return 0
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s) == 0 {
		return 0
	}
	return s[len(s)/2]
}

// TestFirstPauseCost (OPENDSEC_BENCH=1): spec §19.14, what running
// cold-booted VMs without a dirty page log (UntrackedBoot) costs: their
// first pause and their snapshots write all memory instead of the pages
// touched. VMs of several sizes, each holding 256 MB of data.
func TestFirstPauseCost(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	ctx := context.Background()
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-8s %-10s %10s %10s %12s %10s %10s\n", "mem MB", "boot", "1st pause", "kept MB", "snapshot", "snap MB", "2nd pause")
	for _, mem := range []int64{1024, 4096, 8192} {
		for _, untracked := range []bool{false, true} {
			f := newBackendWith(t, func(o *Options) { o.UntrackedBoot = untracked })
			sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 2, MemoryMb: mem}})
			s, _ := f.b.get(sb.ID)
			sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/a bs=1M count=256 status=none`)
			t0 := time.Now()
			if err := f.b.Pause(ctx, sb); err != nil {
				t.Fatal(err)
			}
			first := time.Since(t0)
			s.digMu.Lock()
			dig := s.dig
			s.digMu.Unlock()
			if dig != nil {
				<-dig // zero pages punched out
			}
			kept := allocatedFile(filepath.Join(s.root, pauseMem))
			if err := f.b.Resume(ctx, sb); err != nil {
				t.Fatal(err)
			}
			// A fresh VM for the snapshot: its first one, as a fork source's.
			sb2 := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 2, MemoryMb: mem}})
			sh(t, f.b, sb2, `dd if=/dev/urandom of=/dev/shm/a bs=1M count=256 status=none`)
			t0 = time.Now()
			sn, err := f.b.Snapshot(ctx, sb2, images.NewSnapshotID(), true)
			if err != nil {
				t.Fatal(err)
			}
			snap := time.Since(t0)
			dir, _ := f.opt.Store.SnapshotDir(sn.ID)
			snapMB := allocatedFile(filepath.Join(dir, images.VMMemFile)) >> 20
			sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/b bs=1M count=16 status=none`)
			t0 = time.Now()
			if err := f.b.Pause(ctx, sb); err != nil {
				t.Fatal(err)
			}
			second := time.Since(t0)
			boot := "tracked"
			if untracked {
				boot = "untracked"
			}
			fmt.Fprintf(&b, "%-8d %-10s %10v %10d %12v %10d %10v\n", mem, boot, first.Round(time.Millisecond), kept>>20,
				snap.Round(time.Millisecond), snapMB, second.Round(time.Millisecond))
			f.b.Stop(ctx, sb)
			f.b.Stop(ctx, sb2)
		}
	}
	t.Log(b.String())
}
