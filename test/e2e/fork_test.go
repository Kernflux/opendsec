package e2e

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestForkControlPlane covers the fork flow on sim edges (spec §19.4):
// placement next to the source, spill-over, per-copy quota, inherited spec,
// and the argument and permission checks.
func TestForkControlPlane(t *testing.T) {
	l, admin := start(t, 4, 1000)
	cx := ctx(t)
	src, err := admin.Create(cx, &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 1024},
		TaskId: "job-1", Labels: map[string]string{"role": "src"}})
	if err != nil {
		t.Fatal(err)
	}
	// 64 GB edges hold 64 such sandboxes: 63 copies fit next to the source,
	// the rest spill over to the other edges.
	res, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 70, TtlMaxS: 600,
		Labels: map[string]string{"step": "3"}})
	if err != nil {
		t.Fatal(err)
	}
	perEdge := map[string]int{}
	snapshot := ""
	for _, r := range res {
		if r.ErrorReason != "" {
			t.Fatalf("copy %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
		sp := r.Sandbox.Spec
		perEdge[r.Sandbox.EdgeId]++
		if snapshot == "" {
			snapshot = sp.Snapshot
		}
		if sp.Snapshot == "" || sp.Snapshot != snapshot || sp.TaskId != "job-1" || sp.Labels["role"] != "src" || sp.Labels["step"] != "3" ||
			sp.TtlMaxS != 600 || sp.TtlRunningStopS != 3600 || sp.Resources.GetMemoryMb() != 1024 {
			t.Fatalf("copy spec: %+v", sp)
		}
		if r.Sandbox.Project != "root" || r.Sandbox.State != pb.SandboxState_RUNNING {
			t.Fatalf("copy: %+v", r.Sandbox)
		}
	}
	if len(res) != 70 || perEdge[src.EdgeId] != 63 {
		t.Fatalf("copies per edge: %v (source on %s)", perEdge, src.EdgeId)
	}
	// The source keeps running, with its own id and spec.
	if s, err := admin.GetSandbox(cx, &pb.SandboxRef{Id: src.Id}); err != nil || s.State != pb.SandboxState_RUNNING || s.Spec.Snapshot != "" {
		t.Fatalf("source after fork: %v %v", s, err)
	}

	// Each copy is a creation: quota applies per copy.
	admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "q", Quota: map[string]float64{"sandboxes": 4}})
	pr, _ := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/q", Id: "agent"})
	admin.Grant(cx, &pb.GrantRequest{Project: "root/q", Principal: "agent", Perms: []string{"sandbox.create", "sandbox.operate"}})
	agent, _ := client.Dial(l.Cfg.APIServers[1].Addr, pr.Token, "root/q")
	defer agent.Close()
	qsrc, err := agent.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	res, err = agent.Fork(cx, &pb.ForkSandboxRequest{SandboxId: qsrc.Id, Count: 5})
	if err != nil {
		t.Fatal(err)
	}
	ok, over := 0, 0
	for _, r := range res {
		switch r.ErrorReason {
		case "":
			ok++
		case rpcutil.QuotaExceeded:
			over++
		default:
			t.Fatalf("copy %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
	}
	if ok != 3 || over != 2 {
		t.Fatalf("fork under quota: %d ok, %d over", ok, over)
	}

	// Forking needs sandbox.operate on the source and sandbox.create.
	pr2, _ := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/q", Id: "watcher"})
	admin.Grant(cx, &pb.GrantRequest{Project: "root/q", Principal: "watcher", Perms: []string{"sandbox.operate"}})
	op, _ := client.Dial(l.Cfg.APIServers[0].Addr, pr2.Token, "root/q")
	defer op.Close()
	if _, err := op.Fork(cx, &pb.ForkSandboxRequest{SandboxId: qsrc.Id, Count: 1}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("fork without sandbox.create: %v", err)
	}
	if _, err := agent.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 1}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("fork of another project's sandbox: %v", err)
	}
	// Bad arguments.
	for _, n := range []int32{0, 257} {
		if _, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: n}); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Fatalf("count %d: %v", n, err)
		}
	}
	admin.Stop(cx, qsrc.Id)
	if _, err := agent.Fork(cx, &pb.ForkSandboxRequest{SandboxId: qsrc.Id, Count: 1}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("fork of a stopped sandbox: %v", err)
	}
	// Callers cannot claim a snapshot themselves.
	if _, err := admin.Create(cx, &pb.SandboxSpec{Backend: "sim", Snapshot: snapshot}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("create with spec.snapshot: %v", err)
	}
	// Snapshot images live in the image store.
	if _, err := admin.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: src.Id, Image: "root/x:1"}); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("snapshot without a store: %v", err)
	}
}

// TestForkContainer forks real containers (filesystem-only, spec §19.6 F0):
// copies start from the source's files at the fork, diverge independently,
// fork again, pack_diff, and CreateSnapshot names a snapshot as an image.
func TestForkContainer(t *testing.T) {
	if agentDir == "" {
		t.Skip("container runtime unavailable")
	}
	storeRoot := ownFilesystem(t) // the "host" image stacks / under the store's layers
	st, _ := images.NewStore(storeRoot)
	w, _, err := st.BeginLayer(layerID("fork-base"))
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
	for i := range cfg.Edges {
		cfg.Edges[i].StateDir, cfg.Edges[i].AgentDir = state, agentDir
		cfg.Edges[i].Capacity.DiskMB, cfg.Edges[i].DiskReserveMB = 64*256, 64
		cfg.Edges[i].Images = map[string][]string{"host": {"/"}}
		cfg.Edges[i].Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	admin, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer admin.Close()
	cx := ctx(t)
	if _, err := admin.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/env:1",
		Layers: []string{layerID("fork-base")}, Env: map[string]string{"GREETING": "hi"}, Workdir: "/srv"}}); err != nil {
		t.Fatal(err)
	}
	res := &pb.Resources{CpuCores: 0.5, MemoryMb: 256}
	src, err := admin.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/env:1", Resources: res})
	if err != nil {
		t.Fatal(err)
	}
	shell(t, admin, src.Id, "", `echo step1 > /srv/state && echo tmp > /tmp/scratch && rm /etc/base-marker`)

	forks, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(forks) != 3 {
		t.Fatalf("%d results", len(forks))
	}
	for _, r := range forks {
		if r.ErrorReason != "" {
			t.Fatalf("copy %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
	}
	a, b := forks[0].Sandbox.Id, forks[1].Sandbox.Id
	// Copies see the source's files at the fork, /tmp included (nothing is
	// scrubbed), plus the image defaults and the deletion.
	for _, r := range forks {
		out := shell(t, admin, r.Sandbox.Id, "", `echo "$GREETING $PWD"; cat state /tmp/scratch; test -e /etc/base-marker || echo deleted`)
		if string(out.Stdout) != "hi /srv\nstep1\ntmp\ndeleted\n" {
			t.Fatalf("copy %s: %q %q", r.Sandbox.Id, out.Stdout, out.Stderr)
		}
	}
	// They diverge independently of each other and of the source.
	shell(t, admin, src.Id, "", `echo src-later > /srv/state`)
	shell(t, admin, a, "", `echo a > /srv/state`)
	for id, want := range map[string]string{src.Id: "src-later\n", a: "a\n", b: "step1\n"} {
		if out := shell(t, admin, id, "", `cat /srv/state`); string(out.Stdout) != want {
			t.Fatalf("%s state = %q, want %q", id, out.Stdout, want)
		}
	}
	// A copy forks again, on top of its snapshot.
	again, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: a, Count: 1})
	if err != nil || again[0].ErrorReason != "" {
		t.Fatalf("fork of a copy: %v %v", again, err)
	}
	if out := shell(t, admin, again[0].Sandbox.Id, "", `cat /srv/state /tmp/scratch`); string(out.Stdout) != "a\ntmp\n" {
		t.Fatalf("second-generation copy: %q", out.Stdout)
	}
	// A long fork chain: past 8 snapshot layers they are merged into one
	// (spec §19.12), deletions and overwrites included.
	cur := again[0].Sandbox.Id
	for g := 2; g <= 12; g++ {
		shell(t, admin, cur, "", fmt.Sprintf(`echo g%d > /srv/state; rm -f /srv/gen%d; echo %d > /srv/gen%d`, g, g-1, g, g))
		next, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: cur, Count: 1})
		if err != nil || next[0].ErrorReason != "" {
			t.Fatalf("fork generation %d: %v %v", g, next, err)
		}
		admin.Stop(cx, cur)
		cur = next[0].Sandbox.Id
	}
	if out := shell(t, admin, cur, "", `cat /srv/state /srv/gen12 /tmp/scratch; echo $(ls /srv); test -e /etc/base-marker || echo deleted`); string(out.Stdout) != "g12\n12\ntmp\ngen12 state\ndeleted\n" {
		t.Fatalf("end of the fork chain: %q %q", out.Stdout, out.Stderr)
	}
	if chain, err := admin.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: cur, Image: "root/env:chain"}); err != nil || len(chain.Layers) > 1+8 {
		t.Fatalf("fork chain image: %v %v", chain, err)
	}
	admin.Stop(cx, cur)
	// pack_diff of a copy stacks on its snapshot's layers.
	packed, err := admin.PackDiff(cx, &pb.PackDiffRequest{SandboxId: b, Image: "root/env:packed"})
	if err != nil || len(packed.Layers) != 3 || packed.Parent != "root/env:1" {
		t.Fatalf("pack_diff of a copy: %+v %v", packed, err)
	}
	// CreateSnapshot names a snapshot as an image; nothing is scrubbed.
	img, err := admin.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: src.Id, Image: "root/env:snap"})
	if err != nil || img.Snapshot == "" || img.Memory || len(img.Layers) != 2 {
		t.Fatalf("create_snapshot: %+v %v", img, err)
	}
	sb, err := admin.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/env:snap", Resources: res})
	if err != nil {
		t.Fatal(err)
	}
	if out := shell(t, admin, sb.Id, "", `cat /srv/state /tmp/scratch`); string(out.Stdout) != "src-later\ntmp\n" {
		t.Fatalf("sandbox from a snapshot image: %q", out.Stdout)
	}
	if _, err := admin.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: src.Id, Image: "root/env:mem", Memory: true}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("memory snapshot of a container: %v", err)
	}
	// Sandboxes on an edge-local image fork too (the snapshot keeps the base
	// by name), but cannot be published as images.
	hsb, err := admin.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "host", Resources: res})
	if err != nil {
		t.Fatal(err)
	}
	shell(t, admin, hsb.Id, "", `echo host-state > /etc/opendsec-fork-marker`)
	hf, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: hsb.Id, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range hf {
		if r.ErrorReason != "" {
			t.Fatalf("host copy: %s %s", r.ErrorReason, r.ErrorMessage)
		}
		if out := shell(t, admin, r.Sandbox.Id, "", `cat /etc/opendsec-fork-marker`); string(out.Stdout) != "host-state\n" {
			t.Fatalf("host copy: %q", out.Stdout)
		}
	}
	if _, err := admin.CreateSnapshot(cx, &pb.CreateSnapshotRequest{SandboxId: hf[0].Sandbox.Id, Image: "root/env:host"}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("snapshot image of an edge-local image: %v", err)
	}
	if _, err := os.Stat("/etc/opendsec-fork-marker"); err == nil {
		os.Remove("/etc/opendsec-fork-marker")
		t.Fatal("sandbox write leaked to the host")
	}
}

// ownFilesystem returns a temporary directory on a tmpfs of its own. A
// sandbox on the "host" image (lowerdir /) whose fork or snapshot stacks
// store layers over it needs the store outside /'s filesystem: newer
// kernels refuse overlapping lowerdirs ("overlapping lowerdir path"; 6.8
// still allowed it), and a store on the root filesystem lies inside /.
func ownFilesystem(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "size=4g"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	return dir
}
