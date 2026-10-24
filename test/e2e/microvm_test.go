package e2e

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge"
	"github.com/kernflux/opendsec/internal/edge/backend/microvm"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

func fcKernel() string {
	if k := os.Getenv("OPENDSEC_FC_KERNEL"); k != "" {
		return k
	}
	return "/data/opendsec-vm/vmlinux-6.1.155"
}

// opendsecKernel is the guest kernel built by deploy/guest-kernel, if present.
func opendsecKernel() string {
	k := os.Getenv("OPENDSEC_FC_OPENDSEC_KERNEL")
	if k == "" {
		k = "/data/opendsec-vm/vmlinux-6.1.167-opendsec"
	}
	if _, err := os.Stat(k); err != nil {
		return ""
	}
	return k
}

// TestMicroVMEndToEnd runs Firecracker sandboxes through the whole stack
// (spec §19.6 F1): a store image, the runtime API over vsock, transparent
// resume, quota, and a VM surviving an edge restart.
func TestMicroVMEndToEnd(t *testing.T) {
	opt := microvm.Options{Kernel: fcKernel(), Firecracker: "firecracker", Jailer: "jailer"}
	if err := microvm.Check(&opt); agentDir == "" || err != nil {
		t.Skipf("microvm runtime unavailable: %v", err)
	}
	storeRoot := t.TempDir()
	st, _ := images.NewStore(storeRoot)
	w, _, err := st.BeginLayer(layerID("vm-base"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	os.WriteFile(filepath.Join(w.Rootfs, "etc/base-marker"), []byte("base\n"), 0o644)
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	state, _ := os.MkdirTemp("", "opendsec")
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(2, 1, 8, 16*1024, 64)
	cfg.ImageStore.Root = storeRoot
	// OPENDSEC_TEST_XSTATE puts the second edge's state on another filesystem
	// than the store: it pulls snapshots into its node cache (spec §19.12).
	xstate := state
	if xs := os.Getenv("OPENDSEC_TEST_XSTATE"); xs != "" {
		xstate, _ = os.MkdirTemp(xs, "opendsec")
		t.Cleanup(func() { os.RemoveAll(xstate) })
	}
	for i := range cfg.Edges {
		e := &cfg.Edges[i]
		e.StateDir, e.AgentDir = state, agentDir // real backends persist edge state by default
		if i == 1 {
			e.StateDir = xstate
		}
		e.Capacity.DiskMB, e.DiskReserveMB = 64*256, 64
		mb := config.Backend{Runtime: "firecracker", MaxSandboxes: 64, DefaultDiskMB: 256, Kernel: fcKernel()}
		if k := opendsecKernel(); k != "" {
			// The whole stack with the memory optimizations (spec §19.13).
			mb.Kernel, mb.ImagePmem, mb.FreePageReporting, mb.ColdAgeS = k, true, true, 30
		}
		e.Backends["microvm"] = mb
		e.Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer c.Close()
	cx := ctx(t)
	if _, err := c.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/vm:1",
		Layers: []string{layerID("vm-base")}, Env: map[string]string{"GREETING": "hi"}, Workdir: "/srv"}}); err != nil {
		t.Fatal(err)
	}
	spec := &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:1", TaskId: "job-vm",
		Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}}
	start := time.Now()
	sb, err := c.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("microvm sandbox created in %v (opendsec kernel: %v)", time.Since(start).Round(time.Millisecond), opendsecKernel() != "")
	if opendsecKernel() != "" {
		if r := shell(t, c, sb.Id, "", `test -e /sys/block/pmem0 && echo pmem; cat /sys/module/damon_reclaim/parameters/enabled; n=0; while read -r l; do n=$((n+1)); done </proc/swaps; echo $n`); string(r.Stdout) != "pmem\nY\n2\n" {
			t.Fatalf("memory optimizations in the guest: %q %q", r.Stdout, r.Stderr)
		}
	}
	// A different kernel from the host's, image defaults applied.
	if r := shell(t, c, sb.Id, "", `n=0; while read -r l; do [[ $l == processor* ]] && n=$((n+1)); done </proc/cpuinfo; echo "$GREETING $PWD $n"; cat /etc/base-marker; cat /proc/version`); !strings.HasPrefix(string(r.Stdout), "hi /srv 2\nbase\nLinux version 6.1.") {
		t.Fatalf("guest: %q %q", r.Stdout, r.Stderr)
	}
	// Files and background commands through the same runtime API as containers.
	if _, err := c.WriteFile(cx, &pb.WriteFileRequest{SandboxId: sb.Id, Path: "/srv/in.txt", Data: []byte("payload")}); err != nil {
		t.Fatal(err)
	}
	if f, err := c.ReadFile(cx, &pb.FileRequest{SandboxId: sb.Id, Path: "/srv/in.txt"}); err != nil || string(f.Data) != "payload" {
		t.Fatalf("read file: %v %v", f, err)
	}
	shell(t, c, sb.Id, "", "export X=survives && cd /tmp && echo before > /tmp/f")
	bg, err := c.Exec(cx, &pb.ExecRequest{SandboxId: sb.Id, Session: "job", Cmd: "sleep 1.5; echo finished", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	// Pause stops the vCPUs; any call resumes transparently.
	if s, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.State != pb.SandboxState_PAUSED {
		t.Fatalf("pause: %v %v", s, err)
	}
	if r := shell(t, c, sb.Id, "", "echo $X"); string(r.Stdout) != "survives\n" {
		t.Fatalf("after transparent resume: %q", r.Stdout)
	}
	// The VM outlives an edge restart and is adopted, background command included.
	ec, _ := l.Cfg.Edge(sb.EdgeId)
	ec.KeepSandboxesOnExit = true
	t.Cleanup(func() { ec.KeepSandboxesOnExit = false })
	if err := l.RestartEdge(sb.EdgeId, nil); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 5*time.Second, func() bool {
		l.Settle()
		s, err := c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id})
		return err == nil && s.State == pb.SandboxState_RUNNING
	})
	if r := shell(t, c, sb.Id, "", "echo $X $PWD; cat /tmp/f"); string(r.Stdout) != "survives /tmp\nbefore\n" {
		t.Fatalf("session after edge restart: %q", r.Stdout)
	}
	o, err := c.GetOutput(cx, &pb.OutputRequest{SandboxId: sb.Id, Session: "job", CmdId: bg.CmdId, WaitS: 5})
	if err != nil || !o.Done || string(o.Stdout) != "finished\n" {
		t.Fatalf("command running across the restart: %v %v", o, err)
	}
	// Containers and microVMs share the edge.
	ctr, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/vm:1", Resources: &pb.Resources{MemoryMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	if r := shell(t, c, ctr.Id, "", "cat /etc/base-marker"); string(r.Stdout) != "base\n" {
		t.Fatalf("container next to microvm: %q", r.Stdout)
	}
	testMicroVMSnapshots(t, l, c, sb, state)
	testMicroVMCrossNode(t, l, c, cfg.Edges[0].ID, xstate != state)
	testMicroVMMove(t, l, c, cfg.Edges[0].ID)
	if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:1", Resources: &pb.Resources{MemoryMb: 64}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("microvm below the memory minimum: %v", err)
	}
	// Task stop ends the VM and releases quota.
	if r, err := c.ApplyTaskAction(cx, &pb.TaskActionRequest{Project: "root", TaskId: "job-vm", Action: pb.TaskAction_TASK_STOP}); err != nil || r.Affected != 1 {
		t.Fatalf("task stop: %v %v", r, err)
	}
	c.Stop(cx, ctr.Id)
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 0 })
	jails, _ := filepath.Glob(filepath.Join(state, "*", "microvm", "jail", "firecracker", "*"))
	more, _ := filepath.Glob(filepath.Join(xstate, "*", "microvm", "jail", "firecracker", "*"))
	jails = append(jails, more...)
	if len(jails) != 0 {
		t.Fatalf("jails left behind: %v", jails)
	}
}

// testMicroVMSnapshots covers memory snapshots through the API (spec §19.6
// F2): fork copies with the source's memory, images made by CreateSnapshot
// that new sandboxes resume from, and a paused (snapshotted) VM surviving an
// edge restart.
func testMicroVMSnapshots(t *testing.T, l *cluster.Local, c *client.Client, sb *pb.Sandbox, state string) {
	cx := ctx(t)
	shell(t, c, sb.Id, "", "export STEP=forked; echo mem > /dev/shm/m")
	start := time.Now()
	forks, err := c.Fork(cx, &pb.ForkSandboxRequest{SandboxId: sb.Id, Count: 3, Labels: map[string]string{"gen": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("forked 3 microVMs in %v", time.Since(start).Round(time.Millisecond))
	hosts := map[string]bool{}
	for _, r := range forks {
		if r.ErrorReason != "" {
			t.Fatalf("fork copy %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
		if r.Sandbox.EdgeId != sb.EdgeId {
			t.Errorf("copy on %s, source on %s", r.Sandbox.EdgeId, sb.EdgeId)
		}
		out := shell(t, c, r.Sandbox.Id, "", "echo $STEP $X; cat /dev/shm/m; cat /proc/sys/kernel/hostname")
		lines := strings.Split(strings.TrimSpace(string(out.Stdout)), "\n")
		if len(lines) != 3 || lines[0] != "forked survives" || lines[1] != "mem" || hosts[lines[2]] {
			t.Fatalf("fork copy: %q %q", out.Stdout, out.Stderr)
		}
		hosts[lines[2]] = true
	}
	// The fork's memory snapshot is dropped once the copies run.
	if snaps, _ := filepath.Glob(filepath.Join(l.Cfg.ImageStore.Root, "snapshots", forks[0].Sandbox.Spec.Snapshot)); len(snaps) != 0 {
		t.Errorf("fork snapshot kept: %v", snaps)
	}
	if r := shell(t, c, sb.Id, "", "echo $STEP"); string(r.Stdout) != "forked\n" {
		t.Fatalf("source after fork: %q", r.Stdout)
	}

	// A snapshot image: new sandboxes resume from it (memory size included).
	img, err := c.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: sb.Id, Image: "root/vm:warm", Memory: true})
	if err != nil || !img.Memory || img.Snapshot == "" {
		t.Fatalf("create_snapshot: %v %v", img, err)
	}
	start = time.Now()
	warm, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:warm", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sandbox resumed from a snapshot image in %v", time.Since(start).Round(time.Millisecond))
	if r := shell(t, c, warm.Id, "", "echo $STEP; cat /dev/shm/m"); string(r.Stdout) != "forked\nmem\n" {
		t.Fatalf("from snapshot image: %q %q", r.Stdout, r.Stderr)
	}
	if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:warm", Resources: &pb.Resources{MemoryMb: 256}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("snapshot image with another memory size: %v", err)
	}
	if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/vm:warm", Resources: &pb.Resources{MemoryMb: 256}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("container from a microvm snapshot image: %v", err)
	}

	// A paused microVM is a snapshot without a process; it survives an edge
	// restart and resumes transparently.
	if s, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: warm.Id}); err != nil || s.State != pb.SandboxState_PAUSED {
		t.Fatalf("pause: %v %v", s, err)
	}
	ec, _ := l.Cfg.Edge(warm.EdgeId)
	ec.KeepSandboxesOnExit = true
	if err := l.RestartEdge(warm.EdgeId, nil); err != nil {
		t.Fatal(err)
	}
	ec.KeepSandboxesOnExit = false
	eventuallyFor(t, 5*time.Second, func() bool {
		l.Settle()
		s, err := c.GetSandbox(cx, &pb.SandboxRef{Id: warm.Id})
		return err == nil && s.State == pb.SandboxState_PAUSED
	})
	if r := shell(t, c, warm.Id, "", "echo $STEP"); string(r.Stdout) != "forked\n" {
		t.Fatalf("resume after edge restart: %q", r.Stdout)
	}
	for _, r := range forks {
		c.Stop(cx, r.Sandbox.Id)
	}
	c.Stop(cx, warm.Id)
}

// testMicroVMCrossNode: copies on another edge than the snapshot's (spec
// §19.12). The source runs on edge srcID, whose state shares the store's
// filesystem; with pulled set, the other edge's state is on another one: it
// pulls the snapshot into its node cache, and placement then prefers it for
// more sandboxes from the same snapshot.
func testMicroVMCrossNode(t *testing.T, l *cluster.Local, c *client.Client, srcID string, pulled bool) {
	cx := ctx(t)
	var src, other *edge.Edge
	for _, e := range l.Edges {
		if e.Status(false).State.Id == srcID {
			src = e
		} else {
			other = e
		}
	}
	otherID := other.Status(false).State.Id
	other.SetDraining(true)
	l.Settle()
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:1", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
	other.SetDraining(false)
	if err != nil || sb.EdgeId != srcID {
		t.Fatalf("source on %s: %v %v", srcID, sb, err)
	}
	defer c.Stop(cx, sb.Id)
	shell(t, c, sb.Id, "", "echo far > /dev/shm/x")
	img, err := c.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: sb.Id, Image: "root/vm:far", Memory: true})
	if err != nil {
		t.Fatal(err)
	}
	src.SetDraining(true)
	l.Settle()
	start := time.Now()
	forks, err := c.Fork(cx, &pb.ForkSandboxRequest{SandboxId: sb.Id, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("forked 2 microVMs onto another edge in %v (pulled: %v)", time.Since(start).Round(time.Millisecond), pulled)
	// The fork's snapshot stayed on the source's edge, the copies' edge
	// fetched it from there (spec §26.1), keeping the image disk by content.
	if peerDisks, _ := filepath.Glob(filepath.Join(l.Cfg.Edges[1].StateDir, otherID, "microvm", "cache", "peer-ext4-*.ext4")); len(peerDisks) == 0 {
		t.Errorf("no disk fetched from the source's edge")
	}
	var stop []string
	for _, r := range forks {
		if r.ErrorReason != "" {
			t.Fatalf("copy %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
		stop = append(stop, r.Sandbox.Id)
		if r.Sandbox.EdgeId != otherID {
			t.Errorf("copy on %s with the source's edge draining", r.Sandbox.EdgeId)
		}
		if out := shell(t, c, r.Sandbox.Id, "", "cat /dev/shm/x"); string(out.Stdout) != "far\n" {
			t.Fatalf("cross-node copy: %q %q", out.Stdout, out.Stderr)
		}
	}
	first, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:far", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
	if err != nil || first.EdgeId != otherID {
		t.Fatalf("from the snapshot image: %v %v", first, err)
	}
	stop = append(stop, first.Id)
	src.SetDraining(false)
	if pulled {
		if got := other.Status(false).State.Snapshots; !slices.Contains(got, img.Snapshot) {
			t.Fatalf("edge reports cached snapshots %v, want %s", got, img.Snapshot)
		}
		// Both edges fit: the one caching the snapshot is chosen.
		l.Settle()
		for i := 0; i < 4; i++ {
			s, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:far", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
			if err != nil {
				t.Fatal(err)
			}
			stop = append(stop, s.Id)
			if s.EdgeId != otherID {
				t.Errorf("sandbox %d from a cached snapshot placed on %s", i, s.EdgeId)
			}
		}
	}
	for _, id := range stop {
		c.Stop(cx, id)
	}
}

// testMicroVMMove: a paused microVM resumes on another edge when its own is
// draining (spec §26.2), memory, disk and identity intact.
func testMicroVMMove(t *testing.T, l *cluster.Local, c *client.Client, srcID string) {
	cx := ctx(t)
	src, other := l.Edges[srcID], (*edge.Edge)(nil)
	for id, e := range l.Edges {
		if id != srcID {
			other = e
		}
	}
	otherID := other.ID()
	other.SetDraining(true)
	l.Settle()
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "microvm", Image: "root/vm:1", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
	other.SetDraining(false)
	if err != nil || sb.EdgeId != srcID {
		t.Fatalf("source on %s: %v %v", srcID, sb, err)
	}
	defer c.Stop(cx, sb.Id)
	shell(t, c, sb.Id, "", "export M=kept; echo mem > /dev/shm/y; echo disk > /srv/d; sync")
	host := shell(t, c, sb.Id, "", "cat /proc/sys/kernel/hostname").Stdout
	if _, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil {
		t.Fatal(err)
	}
	src.SetDraining(true)
	l.Settle()
	start := time.Now()
	moved, err := c.ResumeSandbox(cx, &pb.SandboxRef{Id: sb.Id})
	src.SetDraining(false)
	if err != nil || moved.EdgeId != otherID || moved.State != pb.SandboxState_RUNNING {
		t.Fatalf("resume with its edge draining: %v %v", moved, err)
	}
	t.Logf("paused microVM moved to another edge in %v", time.Since(start).Round(time.Millisecond))
	want := "kept\nmem\ndisk\n" + string(host)
	if r := shell(t, c, sb.Id, "", "echo $M; cat /dev/shm/y /srv/d /proc/sys/kernel/hostname"); string(r.Stdout) != want {
		t.Fatalf("after the move: %q %q, want %q", r.Stdout, r.Stderr, want)
	}
	if _, err := src.Get(sb.Id); rpcutil.MovedTo(err) != otherID {
		t.Fatalf("edge it left: %v", err)
	}
}
