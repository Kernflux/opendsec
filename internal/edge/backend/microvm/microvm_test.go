package microvm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

var agentDir, imageDir, kernel string

// TestMain needs KVM, firecracker + jailer and a guest kernel
// (OPENDSEC_FC_KERNEL); it builds the agents and a small image from host tools.
func TestMain(m *testing.M) {
	kernel = os.Getenv("OPENDSEC_FC_KERNEL")
	if kernel == "" {
		kernel = "/data/opendsec-vm/vmlinux-6.1.155"
	}
	opt := Options{Kernel: kernel, Firecracker: "firecracker", Jailer: "jailer"}
	if err := Check(&opt); err != nil {
		os.Stdout.WriteString("skipping microvm backend tests: " + err.Error() + "\n")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "opendsec-agents")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command("go", "build", "-o", dir, "github.com/kernflux/opendsec/cmd/opendsec-aether", "github.com/kernflux/opendsec/cmd/opendsec-chronus")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("build agents: " + err.Error() + "\n" + string(out))
	}
	agentDir = dir
	imageDir, _ = os.MkdirTemp("", "opendsec-vmimg")
	if err := MiniRootfs(imageDir); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.RemoveAll(imageDir)
	os.Exit(code)
}

// MiniRootfs copies a shell, some tools and their libraries from the host.
func MiniRootfs(dir string) error {
	tools := []string{"bash", "sh", "cat", "ls", "rm", "mkdir", "touch", "test", "env", "uname", "nproc", "grep",
		"dd", "head", "hostname", "sleep", "sync", "id", "df", "date", "od", "cut", "tr", "wc", "cksum", "yes"}
	libs := map[string]bool{}
	os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755)
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			return fmt.Errorf("host tool %s: %w", tool, err)
		}
		real, _ := filepath.EvalSymlinks(p)
		if err := copyFile(real, filepath.Join(dir, "usr/bin", tool), 0o755); err != nil {
			return err
		}
		out, _ := exec.Command("ldd", real).Output()
		for _, line := range strings.Split(string(out), "\n") {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "/") {
					libs[f] = true
				}
			}
		}
	}
	for l := range libs {
		real, _ := filepath.EvalSymlinks(l)
		dst := filepath.Join(dir, strings.TrimPrefix(l, "/"))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if err := copyFile(real, dst, 0o755); err != nil {
			return err
		}
	}
	os.Symlink("usr/bin", filepath.Join(dir, "bin"))
	for _, d := range []string{"etc", "srv", "tmp", "root"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "etc/machine-id"), []byte("00000000000000000000000000000000\n"), 0o444)
	return os.WriteFile(filepath.Join(dir, "etc/image-marker"), []byte("mini\n"), 0o644)
}

type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

type fixture struct {
	b    *Backend
	opt  Options
	mu   sync.Mutex
	lost map[string]string
}

func newBackend(t *testing.T) *fixture {
	t.Helper()
	return newBackendAt(t, os.Getenv("OPENDSEC_TEST_STATE"), nil)
}

// newBackendWith makes a backend with its options changed by edit.
func newBackendWith(t *testing.T, edit func(*Options)) *fixture {
	t.Helper()
	return newBackendOpt(t, os.Getenv("OPENDSEC_TEST_STATE"), nil, edit)
}

// newBackendAt makes a backend with its state under parent (short: unix
// socket paths are limited to 108 bytes; OPENDSEC_TEST_STATE puts it on another
// filesystem, XFS for reflinks) and store st, else a store of its own.
func newBackendAt(t *testing.T, parent string, st *images.Store) *fixture {
	t.Helper()
	return newBackendOpt(t, parent, st, nil)
}

func newBackendOpt(t *testing.T, parent string, st *images.Store, edit func(*Options)) *fixture {
	t.Helper()
	state, err := os.MkdirTemp(parent, "opendsec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	if st == nil {
		if st, err = images.NewStore(filepath.Join(state, "store")); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{lost: map[string]string{}, opt: Options{
		Store: st, Name: "microvm", EdgeID: "t" + strings.ToLower(ids.NewLease()[:6]), StateDir: state, AgentDir: agentDir,
		Images: map[string][]string{"mini": {imageDir}}, DefaultDiskMB: 256, Kernel: kernel,
		Firecracker: "firecracker", Jailer: "jailer", UIDBase: 1000000000, OverheadMB: 64,
		Log: slog.New(slog.NewTextHandler(testLog{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}}
	if edit != nil {
		edit(&f.opt)
	}
	f.b, err = New(f.opt)
	if err != nil {
		t.Fatal(err)
	}
	f.watchLoss(f.b)
	t.Cleanup(f.b.Close)
	return f
}

func (f *fixture) watchLoss(b *Backend) {
	b.OnLost(func(id, reason string) { f.mu.Lock(); f.lost[id] = reason; f.mu.Unlock() })
}

func (f *fixture) create(t *testing.T, spec *pb.SandboxSpec) *backend.Sandbox {
	t.Helper()
	sb, err := f.tryCreate(spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { f.b.Stop(context.Background(), sb) })
	return sb
}

func (f *fixture) tryCreate(spec *pb.SandboxSpec) (*backend.Sandbox, error) {
	if spec.Image == "" {
		spec.Image = "mini"
	}
	sb := &backend.Sandbox{ID: ids.Sandbox(f.opt.EdgeID, ids.NewLease()), Project: "root", Spec: spec}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return sb, f.b.Create(ctx, sb)
}

func sh(t *testing.T, b *Backend, sb *backend.Sandbox, cmd string) *pb.ExecResult {
	t.Helper()
	rt, err := b.Runtime(sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := rt.Exec(ctx, &pb.ExecRequest{Cmd: cmd})
	if err != nil {
		t.Fatalf("%q: %v", cmd, err)
	}
	return r
}

func out(r *pb.ExecResult) string { return strings.TrimSpace(string(r.Stdout)) }

func TestBootAndIsolation(t *testing.T) {
	f := newBackend(t)
	start := time.Now()
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1.5, MemoryMb: 256}})
	t.Logf("cold boot (incl. image flattening) in %v", time.Since(start).Round(time.Millisecond))
	lease := strings.SplitN(sb.ID, ".", 2)[1]

	host, _ := exec.Command("uname", "-r").Output()
	r := sh(t, f.b, sb, `uname -r; nproc; hostname; cat /etc/image-marker; ls /sys/class/net; id -u`)
	lines := strings.Split(out(r), "\n")
	if len(lines) != 6 || lines[0] == strings.TrimSpace(string(host)) || lines[1] != "2" || lines[2] != "sb-"+lease[:12] ||
		lines[3] != "mini" || lines[4] != "lo" || lines[5] != "0" {
		t.Fatalf("guest: %q (stderr %q)", r.Stdout, r.Stderr)
	}
	if r := sh(t, f.b, sb, `grep MemTotal /proc/meminfo`); !strings.Contains(out(r), "kB") {
		t.Fatalf("meminfo: %q", r.Stdout)
	}
	// Sessions persist shell state; agents are read-only.
	sh(t, f.b, sb, `cd /srv && export GREETING=hi`)
	if r := sh(t, f.b, sb, `echo "$GREETING $PWD"`); out(r) != "hi /srv" {
		t.Fatalf("session state: %q", r.Stdout)
	}
	if r := sh(t, f.b, sb, `touch /.opendsec/bin/x`); r.ExitCode == 0 {
		t.Error("/.opendsec/bin is writable")
	}
	// Writes stay in the VM's own disk.
	sh(t, f.b, sb, `echo data > /etc/image-marker && sync`)
	if b, _ := os.ReadFile(filepath.Join(imageDir, "etc/image-marker")); string(b) != "mini\n" {
		t.Fatal("guest write reached the image")
	}
	// Limits: vCPUs = ceil(cores) capped by cpu.max; memory = guest RAM + overhead.
	cg := filepath.Join(linuxrt.CgroupRoot, f.b.cgRel, lease)
	for file, want := range map[string]string{"memory.max": fmt.Sprint((256 + 64) << 20), "cpu.max": "150000 100000"} {
		if b, _ := os.ReadFile(filepath.Join(cg, file)); strings.TrimSpace(string(b)) != want {
			t.Errorf("%s = %q, want %q", file, b, want)
		}
	}
	// The VMM runs jailed, as its own unprivileged uid.
	s, _ := f.b.get(sb.ID)
	pid := s.vm().pid
	st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if !strings.Contains(string(st), fmt.Sprintf("Uid:\t%d\t", s.uid)) || s.uid < f.opt.UIDBase {
		t.Errorf("firecracker uid: %d: %s", s.uid, st)
	}
	// Its / is the jail: the VM's files, nothing of the host.
	proot := fmt.Sprintf("/proc/%d/root", pid)
	if _, err := os.Stat(proot + "/vm.json"); err != nil {
		t.Errorf("firecracker root is not its jail: %v", err)
	}
	if _, err := os.Stat(proot + "/etc"); err == nil {
		t.Error("firecracker sees the host filesystem")
	}
}

func TestRejectsHostImage(t *testing.T) {
	f := newBackend(t)
	f.b.opt.Images["host"] = []string{"/"}
	if _, err := f.tryCreate(&pb.SandboxSpec{Image: "host", Resources: &pb.Resources{MemoryMb: 256}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("host image: %v", err)
	}
}

func TestDiskQuota(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256, DiskMb: 64}})
	r := sh(t, f.b, sb, "dd if=/dev/zero of=/big bs=1M count=100 2>&1; echo rc=$?")
	if !strings.Contains(out(r), "No space left") {
		t.Errorf("disk quota not enforced: %q", out(r))
	}
}

// TestPauseToSnapshot: pausing ends the VM process after a memory
// snapshot, so its memory is freed; resuming restores it in a new process
// with everything in memory intact and the clock set right.
func TestPauseToSnapshot(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
	ctx := context.Background()
	sh(t, f.b, sb, `export STATE=kept; echo in-memory > /dev/shm/f; head -c 64m /dev/zero > /dev/shm/ballast`)
	bg, err := mustRT(t, f.b, sb).Exec(ctx, &pb.ExecRequest{Session: "bg", Background: true,
		Cmd: `i=0; while true; do i=$((i+1)); echo $i > /dev/shm/counter; sleep 0.1; done`})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	s, _ := f.b.get(sb.ID)
	before := s.cg.MemoryCurrent()
	oldPid := s.vm().pid
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", oldPid)); err == nil {
		t.Fatal("VM process still running after pause")
	}
	if after := s.cg.MemoryCurrent(); after > before/4 {
		t.Errorf("memory not released by pause: %d -> %d bytes", before, after)
	}
	t.Logf("cgroup memory %d MB running, %d MB paused", before>>20, s.cg.MemoryCurrent()>>20)
	if _, err := f.b.Runtime(sb.ID); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("runtime of a paused VM: %v", err)
	}
	if !f.b.Probe(ctx, sb) {
		t.Fatal("paused VM probed as dead")
	}
	time.Sleep(time.Second) // the guest must not see this second pass
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	r := sh(t, f.b, sb, `echo "$STATE $(cat /dev/shm/f) $(date +%s)"; a=$(cat /dev/shm/counter); sleep 0.5; b=$(cat /dev/shm/counter); echo $((b-a))`)
	lines := strings.Split(out(r), "\n")
	fields := strings.Fields(lines[0])
	if len(lines) != 2 || len(fields) != 3 || fields[0] != "kept" || fields[1] != "in-memory" {
		t.Fatalf("after resume: %q %q", r.Stdout, r.Stderr)
	}
	if guest, _ := strconv.ParseInt(fields[2], 10, 64); abs(guest-time.Now().Unix()) > 2 {
		t.Errorf("guest clock %d, host %d", guest, time.Now().Unix())
	}
	if n, _ := strconv.Atoi(lines[1]); n < 2 {
		t.Errorf("background command not running after resume: +%d", n)
	}
	if o, err := mustRT(t, f.b, sb).GetOutput(ctx, &pb.OutputRequest{Session: "bg", CmdId: bg.CmdId}); err != nil || o.Done {
		t.Fatalf("background command: %v %v", o, err)
	}
	if s.hasPauseSnapshot() {
		t.Error("pause snapshot kept after resume")
	}
	// Pause and resume again: the restored VM snapshots like any other.
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if r := sh(t, f.b, sb, `echo $STATE`); out(r) != "kept" {
		t.Fatalf("second resume: %q", r.Stdout)
	}
	// Killing the VMM is detected as a loss; Stop removes everything.
	s.vm()
	s.cg.Kill()
	eventually(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lost[sb.ID] != "" })
	f.b.Stop(ctx, sb)
	for _, p := range []string{s.dir, f.b.jailDir(s.lease), s.cg.Path} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
}

// TestRestoreCopies: copies restored from one memory snapshot start with
// the source's memory and processes, then diverge, each with its own
// identity, randomness and clock.
func TestRestoreCopies(t *testing.T) {
	f := newBackend(t)
	ctx := context.Background()
	src := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 2, MemoryMb: 256}})
	sh(t, f.b, src, `export STATE=step1; echo shm > /dev/shm/f; echo disk > /root/f`)
	start := time.Now()
	snap, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("snapshot of a 256 MB VM in %v (%d MB)", time.Since(start).Round(time.Millisecond), snap.Size>>20)
	if snap.VM == nil || snap.VM.MemMB != 256 || snap.VM.VCPUs != 2 || !snap.Memory {
		t.Fatalf("snapshot: %+v", snap)
	}
	// The source keeps running.
	sh(t, f.b, src, `export STATE=src-later; echo src > /root/f`)

	const n = 4
	copies := make([]*backend.Sandbox, n)
	errs := make([]error, n)
	start = time.Now()
	var wg sync.WaitGroup
	for i := range copies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			copies[i], errs[i] = f.tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: &pb.Resources{CpuCores: 2, MemoryMb: 256}})
		}(i)
	}
	wg.Wait()
	t.Logf("%d copies restored in %v", n, time.Since(start).Round(time.Millisecond))
	seen := map[string]bool{}
	for i, c := range copies {
		if errs[i] != nil {
			t.Fatalf("copy %d: %v", i, errs[i])
		}
		t.Cleanup(func() { f.b.Stop(context.Background(), c) })
		r := sh(t, f.b, c, `echo $STATE; cat /dev/shm/f /root/f; hostname; cat /etc/machine-id; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; date +%s`)
		l := strings.Split(out(r), "\n")
		if len(l) != 7 || l[0] != "step1" || l[1] != "shm" || l[2] != "disk" {
			t.Fatalf("copy %d: %q %q", i, r.Stdout, r.Stderr)
		}
		lease := strings.SplitN(c.ID, ".", 2)[1]
		if l[3] != "sb-"+lease[:12] {
			t.Errorf("copy %d hostname %q", i, l[3])
		}
		for _, id := range l[4:6] {
			if seen[id] || len(id) != 32 {
				t.Errorf("copy %d: identity or randomness %q repeats", i, id)
			}
			seen[id] = true
		}
		if guest, _ := strconv.ParseInt(l[6], 10, 64); abs(guest-time.Now().Unix()) > 2 {
			t.Errorf("copy %d clock %d", i, guest)
		}
	}
	// Copies diverge from each other.
	sh(t, f.b, copies[0], `echo zero > /root/f`)
	if r := sh(t, f.b, copies[1], `cat /root/f`); out(r) != "disk" {
		t.Fatalf("copies share their disk: %q", r.Stdout)
	}
	if r := sh(t, f.b, src, `echo $STATE; cat /root/f`); out(r) != "src-later\nsrc" {
		t.Fatalf("source after the copies: %q", r.Stdout)
	}
	// The memory size is the snapshot's.
	if _, err := f.tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: &pb.Resources{MemoryMb: 512}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("restore with another memory size: %v", err)
	}
	// Snapshots of a paused VM come from its pause snapshot; memory=false is refused.
	if err := f.b.Pause(ctx, copies[2]); err != nil {
		t.Fatal(err)
	}
	snap2, err := f.b.Snapshot(ctx, copies[2], images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := f.tryCreate(&pb.SandboxSpec{Snapshot: snap2.ID, Resources: &pb.Resources{MemoryMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.b.Stop(context.Background(), c2) })
	if r := sh(t, f.b, c2, `echo $STATE`); out(r) != "step1" {
		t.Fatalf("copy of a paused copy: %q", r.Stdout)
	}
	if _, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), false); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("disk-only microvm snapshot: %v", err)
	}
}

// TestDiffPause: pauses after the first write only the pages dirtied since,
// merged into the base; a base shared with a snapshot is never written.
func TestDiffPause(t *testing.T) {
	f := newBackend(t)
	ctx := context.Background()
	res := &pb.Resources{CpuCores: 2, MemoryMb: 512}
	sb := f.create(t, &pb.SandboxSpec{Resources: res})
	s, _ := f.b.get(sb.ID)
	sums := `cksum /dev/shm/* | cut -d' ' -f1,2 | tr '\n' ' '`
	sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/a bs=1M count=200 status=none`)
	pause := func(sb *backend.Sandbox, want string) pauseStats {
		t.Helper()
		s, _ := f.b.get(sb.ID)
		start := time.Now()
		if err := f.b.Pause(ctx, sb); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		if err := f.b.Resume(ctx, sb); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s pause in %v, %d MB merged", s.lastPause.Type, took.Round(time.Millisecond), s.lastPause.Merged>>20)
		if s.lastPause.Type != want {
			t.Fatalf("pause type %s, want %s", s.lastPause.Type, want)
		}
		return s.lastPause
	}
	// A cold-booted VM's first pause writes its dirty pages: all it holds.
	if st := pause(sb, "Diff"); st.Merged > 400<<20 {
		t.Errorf("first pause of a 512 MB VM holding 200 MB wrote %d MB", st.Merged>>20)
	}
	sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/b bs=1M count=8 status=none`)
	want := out(sh(t, f.b, sb, sums))
	if st := pause(sb, "Diff"); st.Merged > 64<<20 {
		t.Errorf("diff pause merged %d MB after writing 8 MB", st.Merged>>20)
	}
	if got := out(sh(t, f.b, sb, sums)); got != want {
		t.Fatalf("memory after a diff pause: %q, want %q", got, want)
	}
	// A snapshot (running) makes its memory the shared base: pausing the
	// source or a copy then merges into a copy of it, never into it.
	snap, err := f.b.Snapshot(ctx, sb, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := f.opt.Store.SnapshotDir(snap.ID)
	snapSum := func() string {
		o, err := exec.Command("cksum", filepath.Join(dir, images.VMMemFile)).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.Fields(string(o))[0]
	}
	mem0 := snapSum()
	cp := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
	for i, v := range []*backend.Sandbox{sb, cp, sb, cp} {
		sh(t, f.b, v, fmt.Sprintf(`dd if=/dev/urandom of=/dev/shm/c%d bs=1M count=4 status=none`, i))
		want := out(sh(t, f.b, v, sums))
		pause(v, "Diff")
		if got := out(sh(t, f.b, v, sums)); got != want {
			t.Fatalf("memory after diff pause %d: %q, want %q", i, got, want)
		}
	}
	if snapSum() != mem0 {
		t.Fatal("a pause wrote into the snapshot's memory")
	}
	// A snapshot of a paused VM shares its pause memory the same way.
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	snap2, err := f.b.Snapshot(ctx, sb, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ = f.opt.Store.SnapshotDir(snap2.ID)
	mem0 = snapSum()
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/d bs=1M count=4 status=none`)
	want = out(sh(t, f.b, sb, sums))
	pause(sb, "Diff")
	if got := out(sh(t, f.b, sb, sums)); got != want {
		t.Fatalf("memory after diff pause: %q, want %q", got, want)
	}
	if snapSum() != mem0 {
		t.Fatal("a pause wrote into the paused snapshot's memory")
	}
	cp2 := f.create(t, &pb.SandboxSpec{Snapshot: snap2.ID, Resources: res})
	if got := out(sh(t, f.b, cp2, `test -e /dev/shm/d || echo none`)); got != "none" {
		t.Fatalf("copy of the paused snapshot: %q", got)
	}
	if s.st.Base != pauseMem || !s.st.BaseOwned {
		t.Errorf("base %q owned=%v", s.st.Base, s.st.BaseOwned)
	}
}

// TestUntrackedBoot: with UntrackedBoot a cold-booted VM runs without a
// dirty page log, so its snapshots and first pause write all memory; once
// restored (resumed) it has the log again and pauses write diffs.
func TestUntrackedBoot(t *testing.T) {
	f := newBackendWith(t, func(o *Options) { o.UntrackedBoot = true })
	ctx := context.Background()
	res := &pb.Resources{CpuCores: 2, MemoryMb: 512}
	sb := f.create(t, &pb.SandboxSpec{Resources: res})
	s, _ := f.b.get(sb.ID)
	var vc struct {
		Machine struct {
			Track bool `json:"track_dirty_pages"`
		} `json:"machine-config"`
	}
	if err := linuxrt.ReadJSON(filepath.Join(s.root, "vm.json"), &vc); err != nil {
		t.Fatal(err)
	}
	if vc.Machine.Track || !s.st.Untracked || s.st.Base != "" {
		t.Fatalf("cold boot: track %v untracked %v base %q", vc.Machine.Track, s.st.Untracked, s.st.Base)
	}
	sums := `cksum /dev/shm/* | cut -d' ' -f1,2 | tr '\n' ' '`
	sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/a bs=1M count=200 status=none`)
	// A snapshot of the running VM is full and does not become a Base.
	snap, err := f.b.Snapshot(ctx, sb, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if s.st.Base != "" {
		t.Fatalf("base %q after a snapshot of an untracked VM", s.st.Base)
	}
	pause := func(want string) pauseStats {
		t.Helper()
		sh(t, f.b, sb, `dd if=/dev/urandom of=/dev/shm/b bs=1M count=8 status=none`)
		sum := out(sh(t, f.b, sb, sums))
		start := time.Now()
		if err := f.b.Pause(ctx, sb); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		if err := f.b.Resume(ctx, sb); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s pause in %v, %d MB merged", s.lastPause.Type, took.Round(time.Millisecond), s.lastPause.Merged>>20)
		if s.lastPause.Type != want {
			t.Fatalf("pause type %s, want %s", s.lastPause.Type, want)
		}
		if got := out(sh(t, f.b, sb, sums)); got != sum {
			t.Fatalf("memory after a %s pause: %q, want %q", want, got, sum)
		}
		return s.lastPause
	}
	pause("Full")
	if s.st.Untracked {
		t.Fatal("still untracked after a restore")
	}
	if st := pause("Diff"); st.Merged > 64<<20 {
		t.Errorf("diff pause merged %d MB after writing 8 MB", st.Merged>>20)
	}
	// Copies of the snapshot are restored, so they track.
	cp := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
	c, _ := f.b.get(cp.ID)
	if c.st.Untracked || c.st.Base != baseMem {
		t.Fatalf("copy: untracked %v base %q", c.st.Untracked, c.st.Base)
	}
}

// TestSnapshotOtherFS restores copies on a node whose state is on another
// filesystem than the store (OPENDSEC_TEST_XSTATE, e.g. an XFS mount): the
// snapshot is pulled once into the node cache, shared by its copies there,
// and dropped once the store no longer has it.
func TestSnapshotOtherFS(t *testing.T) {
	other := os.Getenv("OPENDSEC_TEST_XSTATE")
	if other == "" {
		t.Skip("set OPENDSEC_TEST_XSTATE to a directory on another filesystem")
	}
	f := newBackend(t)
	if sameFS(other, f.opt.StateDir) {
		t.Skip("OPENDSEC_TEST_XSTATE is on the same filesystem")
	}
	g := newBackendAt(t, other, f.opt.Store)
	ctx := context.Background()
	res := &pb.Resources{MemoryMb: 256}
	src := f.create(t, &pb.SandboxSpec{Resources: res})
	sh(t, f.b, src, `echo far > /dev/shm/f`)
	snap, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.b.CachedSnapshots(); len(got) != 0 {
		t.Fatalf("same-filesystem node caches %v", got)
	}
	var copies []*backend.Sandbox
	for i := 0; i < 3; i++ {
		start := time.Now()
		c, err := (&fixture{b: g.b, opt: g.opt}).tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { g.b.Stop(context.Background(), c) })
		t.Logf("copy %d on the other node in %v", i, time.Since(start).Round(time.Millisecond))
		if r := sh(t, g.b, c, `cat /dev/shm/f`); out(r) != "far" {
			t.Fatalf("copy %d: %q %q", i, r.Stdout, r.Stderr)
		}
		copies = append(copies, c)
	}
	if got := g.b.CachedSnapshots(); len(got) != 1 || got[0] != snap.ID {
		t.Fatalf("node cache: %v", got)
	}
	f.opt.Store.DeleteSnapshot(snap.ID)
	g.b.snaps.gc()
	if got := g.b.CachedSnapshots(); len(got) != 1 {
		t.Fatalf("a young snapshot missing from the store may be on its way in: cache %v", got)
	}
	old := time.Now().Add(-snapGCGrace - time.Minute)
	os.Chtimes(filepath.Join(g.b.snaps.dir, snap.ID), old, old)
	g.b.snaps.gc()
	if got := g.b.CachedSnapshots(); len(got) != 0 {
		t.Fatalf("node cache after the snapshot's deletion: %v", got)
	}
	for _, c := range copies {
		if err := g.b.Pause(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := g.b.Resume(ctx, c); err != nil {
			t.Fatal(err)
		}
		if r := sh(t, g.b, c, `cat /dev/shm/f`); out(r) != "far" {
			t.Fatalf("copy after the cache went: %q", r.Stdout)
		}
	}
}

// TestSnapshotPublish (spec §19.14): a node whose state is not on the
// store's filesystem writes its snapshots locally, where its copies start
// at once, and publishes them to the store in the background; other nodes
// restore once published. A snapshot deleted while publishing stops it.
func TestSnapshotPublish(t *testing.T) {
	other := os.Getenv("OPENDSEC_TEST_XSTATE")
	if other == "" {
		t.Skip("set OPENDSEC_TEST_XSTATE to a directory on another filesystem")
	}
	f := newBackend(t) // shares the store's filesystem
	if sameFS(other, f.opt.StateDir) {
		t.Skip("OPENDSEC_TEST_XSTATE is on the same filesystem")
	}
	g := newBackendAt(t, other, f.opt.Store)
	gf := &fixture{b: g.b, opt: g.opt}
	ctx := context.Background()
	res := &pb.Resources{MemoryMb: 512}
	src := gf.create(t, &pb.SandboxSpec{Resources: res})
	sh(t, g.b, src, `head -c 200m /dev/urandom > /dev/shm/blob; echo near > /dev/shm/f`)
	start := time.Now()
	snap, err := g.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("snapshot in %v, publishing: %q", time.Since(start).Round(time.Millisecond), snap.Publishing)
	if snap.Publishing != g.opt.EdgeID {
		t.Fatalf("snapshot of a node off the store's filesystem not published in the background: %+v", snap)
	}
	start = time.Now()
	near := gf.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
	t.Logf("copy on the snapshot's node in %v", time.Since(start).Round(time.Millisecond))
	start = time.Now()
	far := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
	t.Logf("copy on another node in %v (waits for publishing)", time.Since(start).Round(time.Millisecond))
	for _, c := range []struct {
		b  *Backend
		sb *backend.Sandbox
	}{{g.b, near}, {f.b, far}} {
		if got := out(sh(t, c.b, c.sb, `cat /dev/shm/f; wc -c < /dev/shm/blob`)); got != "near\n209715200" {
			t.Fatalf("copy: %q", got)
		}
	}
	if rec, err := f.opt.Store.GetSnapshot(snap.ID); err != nil || rec.Publishing != "" {
		t.Fatalf("after publishing: %+v %v", rec, err)
	}
	// Deleted while publishing (a fork's snapshot once its copies run).
	snap2, err := g.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	f.opt.Store.DeleteSnapshot(snap2.ID)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(filepath.Join(f.opt.Store.Root, "snapshots", snap2.ID)); err == nil {
		t.Error("publishing recreated a deleted snapshot")
	}
}

func mustRT(t *testing.T, b *Backend, sb *backend.Sandbox) pb.RuntimeClient {
	t.Helper()
	rt, err := b.Runtime(sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatal("condition not met")
}

// TestAdopt restarts the backend with VMs running: they are re-adopted (a
// paused one, which has no process, stays paused), the rest is cleaned up.
func TestAdopt(t *testing.T) {
	f := newBackend(t)
	ctx := context.Background()
	a := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
	p := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
	gone := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
	sh(t, f.b, a, "echo kept > /root/state")
	if err := f.b.Pause(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.b.Detach()

	b2, err := New(f.opt)
	if err != nil {
		t.Fatal(err)
	}
	f.watchLoss(b2)
	f.b = b2 // cleanups now stop through the new instance
	if paused, err := b2.Adopt(ctx, a); err != nil || paused {
		t.Fatalf("adopt running: %v %v", paused, err)
	}
	if paused, err := b2.Adopt(ctx, p); err != nil || !paused {
		t.Fatalf("adopt paused: %v %v", paused, err)
	}
	if r := sh(t, b2, a, "cat /root/state"); out(r) != "kept" {
		t.Fatalf("adopted VM: %q", r.Stdout)
	}
	b2.CleanupExcept(map[string]bool{strings.SplitN(a.ID, ".", 2)[1]: true, strings.SplitN(p.ID, ".", 2)[1]: true})
	lease := strings.SplitN(gone.ID, ".", 2)[1]
	if _, err := os.Stat(b2.jailDir(lease)); err == nil {
		t.Error("leftover VM not cleaned up")
	}
	if err := b2.Resume(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := sh(t, b2, p, "echo resumed"); out(r) != "resumed" {
		t.Fatalf("adopted paused VM: %q", r.Stdout)
	}
	b2.Close()
}

// TestConcurrentBoot boots VMs in parallel from one image: it is flattened
// once and shared.
func TestConcurrentBoot(t *testing.T) {
	f := newBackend(t)
	const n = 8
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, n)
	sbs := make([]*backend.Sandbox, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sbs[i], errs[i] = f.tryCreate(&pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
		}(i)
	}
	wg.Wait()
	t.Logf("%d VMs booted in %v", n, time.Since(start).Round(time.Millisecond))
	for i, err := range errs {
		if err != nil {
			t.Fatalf("vm %d: %v", i, err)
		}
		t.Cleanup(func() { f.b.Stop(context.Background(), sbs[i]) })
		if r := sh(t, f.b, sbs[i], "echo ok"); out(r) != "ok" {
			t.Fatalf("vm %d: %q", i, r.Stdout)
		}
	}
	imgs, _ := filepath.Glob(filepath.Join(f.b.cacheDir(), "img-*.ext4"))
	if len(imgs) != 1 {
		t.Fatalf("image disks: %v", imgs)
	}
}

// TestMemorySharing measures how much host memory copies of one snapshot
// share (spec §19.7). Run with OPENDSEC_BENCH=1.
func TestMemorySharing(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	f := newBackend(t)
	ctx := context.Background()
	src := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 512}})
	sh(t, f.b, src, `head -c 128m /dev/urandom > /dev/shm/data`)
	snap, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	f.b.Stop(ctx, src)
	const n = 8
	before := memAvailableMB()
	start := time.Now()
	for i := 0; i < n; i++ {
		c, err := f.tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: &pb.Resources{MemoryMb: 512}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.b.Stop(context.Background(), c) })
		// Each copy reads all of the data (faulting its pages in).
		if r := sh(t, f.b, c, `cat /dev/shm/data | wc -c`); out(r) != "134217728" {
			t.Fatalf("copy %d: %q %q", i, r.Stdout, r.Stderr)
		}
	}
	used := before - memAvailableMB()
	t.Logf("%d copies of a VM holding 128 MB: %d MB of host memory (%d MB each; %d MB if nothing were shared), restored+read in %v",
		n, used, used/n, n*(128+50), time.Since(start).Round(time.Millisecond))
}

// TestFork64 (OPENDSEC_BENCH=1): spec §19.7, a snapshot of a running VM and 64
// copies restored at once; host memory with every copy reading its data.
func TestFork64(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	f := newBackend(t)
	ctx := context.Background()
	res := &pb.Resources{CpuCores: 1, MemoryMb: 512}
	src := f.create(t, &pb.SandboxSpec{Resources: res})
	sh(t, f.b, src, `head -c 128m /dev/urandom > /dev/shm/data`)
	f.b.Pause(ctx, src) // gives it a base: the fork snapshot is a diff
	f.b.Resume(ctx, src)
	sh(t, f.b, src, `echo forked > /dev/shm/mark`)
	start := time.Now()
	snap, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	const n = 64
	before := memAvailableMB()
	lat := make([]time.Duration, n)
	copies := make([]*backend.Sandbox, n)
	errs := make([]error, n)
	start = time.Now()
	var wg sync.WaitGroup
	for i := range copies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			copies[i], errs[i] = f.tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
			lat[i] = time.Since(t0)
		}(i)
	}
	wg.Wait()
	all := time.Since(start)
	for i, c := range copies {
		if errs[i] != nil {
			t.Fatalf("copy %d: %v", i, errs[i])
		}
		t.Cleanup(func() { f.b.Stop(context.Background(), c) })
	}
	for i, c := range copies {
		if r := sh(t, f.b, c, `cat /dev/shm/mark; cat /dev/shm/data | wc -c`); out(r) != "forked\n134217728" {
			t.Fatalf("copy %d: %q %q", i, r.Stdout, r.Stderr)
		}
	}
	used := before - memAvailableMB()
	slices.Sort(lat)
	t.Logf("snapshot %v; %d copies in %v (p50 %v, max %v); host memory with each copy reading 128 MB: %d MB (%d MB if nothing were shared)",
		took.Round(time.Millisecond), n, all.Round(time.Millisecond), lat[n/2].Round(time.Millisecond),
		lat[n-1].Round(time.Millisecond), used, n*(128+50))
	if r := sh(t, f.b, src, `cat /dev/shm/mark`); out(r) != "forked" {
		t.Fatalf("source after the fork: %q", r.Stdout)
	}
}

func memAvailableMB() int64 {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			n, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			return n >> 10
		}
	}
	return 0
}

// vmCookies maps each core scheduling cookie of the VM's threads to the
// names of the threads that have it.
func vmCookies(t *testing.T, f *fixture, sb *backend.Sandbox) map[uint64][]string {
	t.Helper()
	s, err := f.b.get(sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][]string{}
	for _, tid := range s.cg.Threads() {
		// KVM attaches its per-VM kernel thread (kvm-nx-lpage-recovery,
		// spec §19.15) to the VM's cgroup: kernel threads are not ours.
		if _, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", tid)); err != nil {
			continue
		}
		c, err := linuxrt.CoreSchedCookie(tid)
		if err != nil {
			continue
		}
		name, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", tid))
		out[c] = append(out[c], strings.TrimSpace(string(name)))
	}
	return out
}

// TestCoreSched (spec §29.1): every thread of a VM, its vCPUs included,
// shares one cookie of its own, also after a pause and resume (a new
// Firecracker process).
func TestCoreSched(t *testing.T) {
	if linuxrt.CoreSchedSupported() != nil {
		t.Skip("no core scheduling in this kernel")
	}
	f := newBackendWith(t, func(o *Options) { o.CoreSched = true })
	ctx := context.Background()
	check := func(sb *backend.Sandbox, when string) uint64 {
		c := vmCookies(t, f, sb)
		if len(c) != 1 || c[0] != nil {
			t.Fatalf("%s: threads by cookie %v, want one non-zero cookie", when, c)
		}
		for k, names := range c {
			if !slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, "fc_vcpu") }) {
				t.Fatalf("%s: no vCPU thread among %v", when, names)
			}
			return k
		}
		return 0
	}
	res := &pb.Resources{CpuCores: 2, MemoryMb: 256}
	a, b := f.create(t, &pb.SandboxSpec{Resources: res}), f.create(t, &pb.SandboxSpec{Resources: res})
	if check(a, "first VM") == check(b, "second VM") {
		t.Fatal("two VMs share a cookie")
	}
	if err := f.b.Pause(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Resume(ctx, a); err != nil {
		t.Fatal(err)
	}
	check(a, "after resume")
}

// TestSessionUsers (spec §29.3): an agent's session of an unprivileged user
// cannot read what a root session made, talk to the sessions' sockets, see
// their records or change system binaries; a session keeps its user.
func TestSessionUsers(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	exec := func(session, user, cmd string) (*pb.ExecResult, error) {
		rt, err := f.b.Runtime(sb.ID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return rt.Exec(ctx, &pb.ExecRequest{Session: session, User: user, Cmd: cmd})
	}
	must := func(session, user, cmd string) string {
		t.Helper()
		r, err := exec(session, user, cmd)
		if err != nil {
			t.Fatalf("%s as %q: %q: %v", session, user, cmd, err)
		}
		if len(r.Stderr) > 0 || r.ExitCode != 0 {
			t.Logf("%s as %q: exit %d, stderr %q", session, user, r.ExitCode, r.Stderr)
		}
		return strings.TrimSpace(string(r.Stdout))
	}
	// What the grader keeps from the agent it writes for root only: file
	// modes are the caller's part.
	if got := must("grade", "", `(umask 077; echo 42 > /root/answer); echo graded; id -u`); got != "graded\n0" {
		t.Fatalf("grading session: %q", got)
	}
	if got := must("agent", "1000", `id -u; echo $HOME`); got != "1000\n/tmp/home-1000" {
		t.Fatalf("agent session: %q", got)
	}
	probe := `cat /root/answer 2>/dev/null && echo READ-ANSWER
cat /.opendsec/run/sessions/grade/*.out 2>/dev/null && echo READ-RECORDS
ls /.opendsec/run/sessions/grade >/dev/null 2>&1 && echo LISTED-RECORDS
for s in /.opendsec/run/*.sock; do test -w "$s" && echo "CAN-CONNECT $s"; done
test -w /usr/bin/bash && echo CAN-WRITE-BASH
test -w /bin/sh && echo CAN-WRITE-SH
echo probed`
	if got := must("agent", "1000", probe); got != "probed" {
		t.Fatalf("the agent session got through:\n%s", got)
	}
	// A session keeps its user.
	for _, c := range [][2]string{{"agent", "root"}, {"grade", "1000"}} {
		if _, err := exec(c[0], c[1], "id -u"); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Errorf("session %s as %s: %v", c[0], c[1], err)
		}
	}
	if got := must("grade", "root", "cat /root/answer"); got != "42" {
		t.Fatalf("grading session afterwards: %q", got)
	}
}

// TestInUseLayers (spec §24): a VM keeps the store layers it runs on while
// it runs, as a container does: after its image is deleted and GC runs, it
// can still be snapshotted. Stopped, it lets them go.
func TestInUseLayers(t *testing.T) {
	f := newBackend(t)
	const img = "root/inuse:1"
	storeImage(t, f.opt.Store, img)
	ctx := context.Background()
	a := f.create(t, &pb.SandboxSpec{Image: img, Resources: &pb.Resources{MemoryMb: 256}})
	if err := f.opt.Store.DeleteManifest(img); err != nil {
		t.Fatal(err)
	}
	res, err := f.opt.Store.GC(0, false)
	if err != nil || len(res.Layers) != 0 {
		t.Fatalf("GC removed the running VM's layers: %v %v", res, err)
	}
	if _, err := f.b.Snapshot(ctx, a, images.NewSnapshotID(), true); err != nil {
		t.Fatalf("snapshot after its image went: %v", err)
	}
	f.b.Stop(ctx, a)
	if h := f.opt.Store.InUseHolders(f.opt.EdgeID + ".microvm."); len(h) != 0 {
		t.Fatalf("markers after the stop: %v", h)
	}
}
