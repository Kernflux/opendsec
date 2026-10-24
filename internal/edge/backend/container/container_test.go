package container

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

var agentDir string

// TestMain builds the static in-sandbox agents once. The test binary itself
// doubles as the sandbox init (see init.go).
func TestMain(m *testing.M) {
	if err := Check(); err != nil {
		os.Stdout.WriteString("skipping container backend tests: " + err.Error() + "\n")
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
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type fixture struct {
	b     *Backend
	state string
	mu    sync.Mutex
	lost  map[string]string
}

func newBackend(t *testing.T) *fixture {
	t.Helper()
	return newBackendWith(t, nil)
}

func newBackendWith(t *testing.T, edit func(*Options)) *fixture {
	t.Helper()
	state, err := os.MkdirTemp("", "opendsec") // short: unix socket paths are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	f := &fixture{state: state, lost: map[string]string{}}
	opt := Options{
		Name: "container", EdgeID: "t" + strings.ToLower(ids.NewLease()[:6]), StateDir: state, AgentDir: agentDir,
		Images:        map[string][]string{"host": {"/"}},
		DefaultDiskMB: 256, PidsMax: 512, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if edit != nil {
		edit(&opt)
	}
	f.b, err = New(opt)
	if err != nil {
		t.Fatal(err)
	}
	f.b.OnLost(func(id, reason string) { f.mu.Lock(); f.lost[id] = reason; f.mu.Unlock() })
	t.Cleanup(f.b.Close)
	return f
}

func (f *fixture) create(t *testing.T, spec *pb.SandboxSpec) *backend.Sandbox {
	t.Helper()
	if spec.Image == "" {
		spec.Image = "host"
	}
	sb := &backend.Sandbox{ID: ids.Sandbox(f.b.opt.EdgeID, ids.NewLease()), Project: "root", Spec: spec}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.b.Create(ctx, sb); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("sandbox %s created in %v", sb.ID, time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { f.b.Stop(context.Background(), sb) })
	return sb
}

func sh(t *testing.T, f *fixture, sb *backend.Sandbox, cmd string) *pb.ExecResult {
	t.Helper()
	rt, err := f.b.Runtime(sb.ID)
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

func TestIsolation(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	lease := strings.SplitN(sb.ID, ".", 2)[1]

	if got := out(sh(t, f, sb, "tr '\\0' ' ' </proc/1/cmdline")); !strings.HasPrefix(got, "/.opendsec/bin/opendsec-aether --init") {
		t.Errorf("PID 1 = %q", got)
	}
	if got := out(sh(t, f, sb, "hostname")); got != "sb-"+lease[:12] {
		t.Errorf("hostname = %q", got)
	}
	// Only loopback in the network namespace, and it is up.
	if got := out(sh(t, f, sb, "tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '")); got != "lo" {
		t.Errorf("interfaces = %q", got)
	}
	if got := out(sh(t, f, sb, "cat /sys/class/net/lo/operstate")); got != "unknown" && got != "up" {
		t.Errorf("lo operstate = %q", got)
	}
	// PID namespace: only the sandbox's own processes are visible.
	if n := out(sh(t, f, sb, "ls -d /proc/[0-9]* | wc -l")); n == "" || len(n) > 2 {
		t.Errorf("visible processes = %s", n)
	}
	// Writes go to the sandbox's own writable layer, not the host.
	sh(t, f, sb, "echo sandbox-data > /etc/opendsec-test-marker")
	if _, err := os.Stat("/etc/opendsec-test-marker"); err == nil {
		os.Remove("/etc/opendsec-test-marker")
		t.Fatal("sandbox write leaked to the host rootfs")
	}
	s, _ := f.b.get(sb.ID)
	upper := filepath.Join(s.diskDir(), "upper/etc/opendsec-test-marker")
	if b, err := os.ReadFile(upper); err != nil || string(b) != "sandbox-data\n" {
		t.Errorf("upper layer: %q %v", b, err)
	}
	// Nothing of the sandbox is mounted on the host: every new mount
	// namespace copies the host's mounts.
	if mi, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(mi), lease) {
		t.Errorf("sandbox mounts on the host: %s", mi)
	}
	// The agents are read-only inside the sandbox.
	if r := sh(t, f, sb, "touch /.opendsec/bin/x"); r.ExitCode == 0 {
		t.Error("/.opendsec/bin is writable")
	}
}

func TestLimits(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 0.5, MemoryMb: 64, DiskMb: 64}})
	lease := strings.SplitN(sb.ID, ".", 2)[1]
	cg := filepath.Join(linuxrt.CgroupRoot, "opendsec", f.b.opt.EdgeID, lease)
	for file, want := range map[string]string{"memory.max": "67108864", "cpu.max": "50000 100000", "pids.max": "512"} {
		if b, _ := os.ReadFile(filepath.Join(cg, file)); strings.TrimSpace(string(b)) != want {
			t.Errorf("%s = %q, want %q", file, b, want)
		}
	}
	// The sandbox sees its own cgroup, so runtimes inside size to its limits.
	if got := out(sh(t, f, sb, "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max")); got != "67108864\n50000 100000" {
		t.Errorf("in-sandbox cgroup = %q", got)
	}
	// Memory: allocating past memory.max gets the process OOM-killed.
	r := sh(t, f, sb, "python3 -c 'b = bytearray(200 << 20); print(len(b))' 2>/dev/null; echo rc=$?")
	if strings.Contains(out(r), "209715200") {
		t.Errorf("allocated past the memory limit: %q", out(r))
	}
	// Disk: the writable layer is a 64 MiB filesystem.
	r = sh(t, f, sb, "dd if=/dev/zero of=/big bs=1M count=100 2>&1; echo rc=$?")
	if !strings.Contains(out(r), "No space left") {
		t.Errorf("disk quota not enforced: %q", out(r))
	}
}

func TestPauseResumeStop(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 128}})
	lease := strings.SplitN(sb.ID, ".", 2)[1]
	ctx := context.Background()
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.b.Runtime(sb.ID)
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	_, err := rt.Exec(cctx, &pb.ExecRequest{Cmd: "echo hi"})
	cancel()
	if err == nil {
		t.Fatal("exec succeeded while frozen")
	}
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got := out(sh(t, f, sb, "echo back")); got != "back" {
		t.Fatalf("after resume: %q", got)
	}
	// Losing the sandbox while frozen is not reported as a failure.
	f.mu.Lock()
	lost := len(f.lost)
	f.mu.Unlock()
	if lost != 0 {
		t.Fatalf("spurious loss: %v", f.lost)
	}
	if err := f.b.Stop(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.state, f.b.opt.EdgeID, "sb", lease)); !os.IsNotExist(err) {
		t.Errorf("sandbox dir not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(linuxrt.CgroupRoot, "opendsec", f.b.opt.EdgeID, lease)); !os.IsNotExist(err) {
		t.Errorf("cgroup not removed: %v", err)
	}
	mounts, _ := os.ReadFile("/proc/self/mountinfo")
	if strings.Contains(string(mounts), lease) {
		t.Error("writable disk still mounted")
	}
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lost) != 0 {
		t.Fatalf("stop reported as loss: %v", f.lost)
	}
}

func TestAetherDeathIsReported(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{})
	rt, _ := f.b.Runtime(sb.ID)
	// PID 1 ignores SIGKILL from inside its namespace (the kernel protects
	// it), so a crashing aether server is the realistic failure: init then
	// exits and the whole sandbox goes with it. The edge must notice.
	if r := sh(t, f, sb, "kill -9 1; echo $?"); out(r) != "0" {
		t.Logf("kill -9 1: %q", out(r))
	}
	if !f.b.Probe(context.Background(), sb) {
		t.Fatal("PID 1 should survive SIGKILL from inside the sandbox")
	}
	rt.Exec(context.Background(), &pb.ExecRequest{Background: true, Cmd: `for p in /proc/[0-9]*; do
	  if tr '\0' ' ' <$p/cmdline 2>/dev/null | grep -q '^/.opendsec/bin/opendsec-aether --socket'; then kill -9 ${p#/proc/}; fi
	done`})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		reason, ok := f.lost[sb.ID]
		f.mu.Unlock()
		if ok {
			t.Logf("loss reported: %s", reason)
			if f.b.Probe(context.Background(), sb) {
				t.Error("probe still reports alive")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("sandbox death not reported")
}

func TestCleanupLeftovers(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{})
	lease := strings.SplitN(sb.ID, ".", 2)[1]
	// A new backend for the same edge (edge restart) removes sandboxes the
	// edge has no record of.
	f.b.Detach()
	b2, err := New(f.b.opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b2.Close)
	b2.CleanupExcept(nil)
	if _, err := os.Stat(filepath.Join(f.state, f.b.opt.EdgeID, "sb", lease)); !os.IsNotExist(err) {
		t.Errorf("leftover sandbox dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(linuxrt.CgroupRoot, "opendsec", f.b.opt.EdgeID, lease)); !os.IsNotExist(err) {
		t.Errorf("leftover cgroup: %v", err)
	}
}

func TestAdoptAfterEdgeRestart(t *testing.T) {
	f := newBackend(t)
	ctx := context.Background()
	live := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 128}})
	paused := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 128}})
	dead := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 128}})

	sh(t, f, live, "export X=kept; cd /tmp")
	rt, _ := f.b.Runtime(live.ID)
	bg, err := rt.Exec(ctx, &pb.ExecRequest{Cmd: "sleep 0.8; echo bg-done", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.Pause(ctx, paused); err != nil {
		t.Fatal(err)
	}
	// The edge process goes away (crash/upgrade): connections drop, sandboxes stay.
	f.b.Detach()
	// While no edge is watching, one sandbox dies.
	(&linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, "opendsec", f.b.opt.EdgeID, strings.SplitN(dead.ID, ".", 2)[1])}).Kill()

	b2, err := New(f.b.opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b2.Close)
	lost := map[string]string{}
	var mu sync.Mutex
	b2.OnLost(func(id, r string) { mu.Lock(); lost[id] = r; mu.Unlock() })

	start := time.Now()
	if p, err := b2.Adopt(ctx, live); err != nil || p {
		t.Fatalf("adopt live: paused=%v err=%v", p, err)
	}
	t.Logf("adopted in %v", time.Since(start).Round(time.Millisecond))
	if p, err := b2.Adopt(ctx, paused); err != nil || !p {
		t.Fatalf("adopt paused: paused=%v err=%v", p, err)
	}
	if _, err := b2.Adopt(ctx, dead); err == nil {
		t.Fatal("adopted a dead sandbox")
	}
	b2.CleanupExcept(map[string]bool{
		strings.SplitN(live.ID, ".", 2)[1]: true, strings.SplitN(paused.ID, ".", 2)[1]: true})

	// The shell session survived the edge restart, and so did the command
	// that was running across it.
	rt2, _ := b2.Runtime(live.ID)
	r, err := rt2.Exec(ctx, &pb.ExecRequest{Cmd: "echo $X $PWD"})
	if err != nil || string(r.Stdout) != "kept /tmp\n" {
		t.Fatalf("session after adopt: %q %v", r.GetStdout(), err)
	}
	o, err := rt2.GetOutput(ctx, &pb.OutputRequest{CmdId: bg.CmdId, WaitS: 5})
	if err != nil || !o.Done || string(o.Stdout) != "bg-done\n" {
		t.Fatalf("background command across restart: %+v %v", o, err)
	}
	// The paused sandbox is still frozen and resumes normally.
	pcg := &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, "opendsec", f.b.opt.EdgeID, strings.SplitN(paused.ID, ".", 2)[1])}
	if !pcg.Frozen() {
		t.Fatal("paused sandbox thawed by adoption")
	}
	if err := b2.Resume(ctx, paused); err != nil {
		t.Fatal(err)
	}
	if rp, _ := b2.Runtime(paused.ID); rp != nil {
		if r, err := rp.Exec(ctx, &pb.ExecRequest{Cmd: "echo ok"}); err != nil || string(r.Stdout) != "ok\n" {
			t.Fatalf("resumed adopted sandbox: %v", err)
		}
	}
	// The dead sandbox's leftovers are gone.
	if _, err := os.Stat(filepath.Join(f.state, f.b.opt.EdgeID, "sb", strings.SplitN(dead.ID, ".", 2)[1])); !os.IsNotExist(err) {
		t.Errorf("dead sandbox not cleaned: %v", err)
	}
	// Loss detection works for adopted sandboxes (not children of this process).
	rt2.Exec(ctx, &pb.ExecRequest{Background: true, Cmd: `for p in /proc/[0-9]*; do
	  if tr '\0' ' ' <$p/cmdline 2>/dev/null | grep -q '^/.opendsec/bin/opendsec-aether --socket'; then kill -9 ${p#/proc/}; fi
	done`})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, ok := lost[live.ID]
		mu.Unlock()
		if ok {
			if b2.Probe(ctx, live) {
				t.Error("probe reports a dead adopted sandbox alive")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("loss of adopted sandbox not reported")
}

// TestHardening (spec §21): the sandbox's root cannot mount, enter or make
// namespaces, write kernel settings, read kernel memory or make device
// nodes; the caller's read-only and masked paths hold; ordinary work is
// unaffected.
func TestHardening(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256},
		ReadonlyPaths: []string{"/etc", "/no/such/path"}, MaskedPaths: []string{"/usr/share", "/etc/hostname"}})
	var want uint64
	for _, c := range keptCaps {
		want |= 1 << c
	}
	if got := out(sh(t, f, sb, `grep -E '^Cap(Eff|Bnd):' /proc/self/status | awk '{print $2}' | sort -u`)); got != fmt.Sprintf("%016x", want) {
		t.Errorf("capabilities %q, want %016x", got, want)
	}
	for cmd, what := range map[string]string{
		`mount -t tmpfs x /mnt`: "mount",
		`umount /proc`:          "umount",
		`echo '|/bin/true' > /proc/sys/kernel/core_pattern`: "kernel setting",
		`echo 1 > /proc/sysrq-trigger`:                      "sysrq",
		`unshare -U true`:                                   "user namespace",
		`unshare -m true`:                                   "mount namespace",
		`mknod /tmp/sda b 8 0`:                              "device node",
		`touch /etc/opendsec-test`:                          "read-only path",
		`nsenter -t 1 -m true`:                              "setns",
	} {
		if r := sh(t, f, sb, cmd); r.ExitCode == 0 {
			t.Errorf("%s allowed: %q", what, cmd)
		}
	}
	if got := out(sh(t, f, sb, `head -c 16 /proc/kcore | wc -c; ls /usr/share | wc -l; wc -c < /etc/hostname`)); got != "0\n0\n0" {
		t.Errorf("masked paths readable: %q", got)
	}
	r := sh(t, f, sb, `echo ok > /tmp/f && cat /tmp/f && chown nobody /tmp/f && cat /proc/sys/kernel/ostype && python3 -c 'import threading; t = threading.Thread(target=print, args=("thread",)); t.start(); t.join()'`)
	if out(r) != "ok\nLinux\nthread" {
		t.Errorf("ordinary work: %q %q", r.Stdout, r.Stderr)
	}
}

// TestGPUs (spec §22.2) with stand-in device nodes: exclusive sandboxes get
// whole devices, shared ones slots on the others; the devices, the extra
// nodes and the driver mounts appear inside, with CUDA's variables.
func TestGPUs(t *testing.T) {
	dir := t.TempDir()
	var devs []string
	for _, n := range []string{"nvidia0", "nvidia1", "nvidiactl"} {
		p := filepath.Join(dir, n)
		if err := unix.Mknod(p, unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))); err != nil {
			t.Fatal(err)
		}
		devs = append(devs, p)
	}
	lib := filepath.Join(dir, "libcuda.so.1")
	os.WriteFile(lib, []byte("driver"), 0o644)
	f := newBackendWith(t, func(o *Options) { o.GPUs = linuxrt.NewGPUs(devs[:2], devs[2:], []string{lib}, 2) })
	res := &pb.Resources{CpuCores: 1, MemoryMb: 256}
	try := func(spec *pb.SandboxSpec) (*backend.Sandbox, error) {
		spec.Image, spec.Resources = "host", res
		sb := &backend.Sandbox{ID: ids.Sandbox(f.b.opt.EdgeID, ids.NewLease()), Project: "root", Spec: spec}
		err := f.b.Create(context.Background(), sb)
		if err == nil {
			t.Cleanup(func() { f.b.Stop(context.Background(), sb) })
		}
		return sb, err
	}
	res = &pb.Resources{CpuCores: 1, MemoryMb: 256, Gpus: 1}
	excl, err := try(&pb.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	r := sh(t, f, excl, `echo $(ls /dev | grep nvidia); echo $CUDA_VISIBLE_DEVICES; cat `+lib)
	lines := strings.Split(out(r), "\n")
	if len(lines) != 3 || len(strings.Fields(lines[0])) != 2 || lines[1] != "0" || lines[2] != "driver" {
		t.Fatalf("exclusive GPU sandbox: %q %q", r.Stdout, r.Stderr)
	}
	res = &pb.Resources{CpuCores: 1, MemoryMb: 256}
	var sharedDev string
	for i := 0; i < 2; i++ {
		sb, err := try(&pb.SandboxSpec{GpuMode: "shared"})
		if err != nil {
			t.Fatalf("shared %d: %v", i, err)
		}
		d := out(sh(t, f, sb, `ls /dev | grep -E 'nvidia[0-9]'`))
		if sharedDev != "" && d != sharedDev || strings.Contains(lines[0], d) {
			t.Fatalf("shared sandbox %d on %q (exclusive holds %q, first shared %q)", i, d, lines[0], sharedDev)
		}
		sharedDev = d
	}
	if _, err := try(&pb.SandboxSpec{GpuMode: "shared"}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("third shared sandbox (2 slots, one device exclusive): %v", err)
	}
	res = &pb.Resources{CpuCores: 1, MemoryMb: 256, Gpus: 1}
	if _, err := try(&pb.SandboxSpec{}); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("second exclusive sandbox: %v", err)
	}
	f.b.Stop(context.Background(), excl)
	if _, err := try(&pb.SandboxSpec{}); err != nil {
		t.Fatalf("exclusive after release: %v", err)
	}
}

// TestPauseReclaim (spec §22.1; needs host swap): a paused sandbox's memory
// goes out to swap; on resume it is read back and the data is intact.
func TestPauseReclaim(t *testing.T) {
	if b, _ := os.ReadFile("/proc/swaps"); len(strings.Split(strings.TrimSpace(string(b)), "\n")) < 2 || linuxrt.Swappiness() == 0 {
		t.Skip("needs host swap and vm.swappiness > 0")
	}
	f := newBackendWith(t, func(o *Options) { o.PauseReclaim = true })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 512}})
	s, _ := f.b.get(sb.ID)
	rt, _ := f.b.Runtime(sb.ID)
	ctx := context.Background()
	// A process holding 200 MB, answering with its checksum on each line read.
	if _, err := rt.Exec(ctx, &pb.ExecRequest{Session: "hold", Background: true, Cmd: `mkfifo /tmp/q /tmp/a; python3 -c '
import hashlib, os
data = bytearray(os.urandom(1 << 20)) * 200
while True:
    open("/tmp/q").read()
    open("/tmp/a", "w").write(hashlib.sha256(data).hexdigest())
'`}); err != nil {
		t.Fatal(err)
	}
	ask := func() string { return out(sh(t, f, sb, `echo > /tmp/q; cat /tmp/a`)) }
	eventually(t, func() bool { return s.cg.MemoryCurrent() > 200<<20 })
	sum := ask()
	before := s.cg.MemoryCurrent()
	start := time.Now()
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	paused := s.cg.MemoryCurrent()
	t.Logf("pause reclaimed %d MB in %v: %d MB -> %d MB", s.reclaimed>>20, time.Since(start).Round(time.Millisecond), before>>20, paused>>20)
	if paused > before/3 {
		t.Errorf("paused sandbox still holds %d of %d MB", paused>>20, before>>20)
	}
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return s.cg.MemoryCurrent() > before*3/4 }) // read back ahead of use
	if got := ask(); got != sum {
		t.Fatalf("data after pause/resume: %s, want %s", got, sum)
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not met")
}

// TestQoS (paper §4.3): on a contended CPU a best-effort sandbox (cpu.idle)
// yields to a latency-sensitive one.
func TestQoS(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs 2+ CPUs (on the 1-vCPU dev VM cgroup CPU weights showed no effect)")
	}
	f := newBackend(t)
	res := &pb.Resources{CpuCores: 2, MemoryMb: 256}
	ls := f.create(t, &pb.SandboxSpec{Resources: res, Qos: "LS"})
	be := f.create(t, &pb.SandboxSpec{Resources: res, Qos: "BE"})
	cpu := runtime.NumCPU() - 1
	loop := fmt.Sprintf(`taskset -c %d bash -c 'n=0; end=$((SECONDS+3)); while ((SECONDS<end)); do n=$((n+1)); done; echo $n'`, cpu)
	counts := make([]int, 2)
	var wg sync.WaitGroup
	for i, sb := range []*backend.Sandbox{ls, be} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Sscan(out(sh(t, f, sb, loop)), &counts[i])
		}()
	}
	wg.Wait()
	t.Logf("iterations on one CPU: LS %d, BE %d", counts[0], counts[1])
	if counts[0] == 0 || counts[1]*5 > counts[0] {
		t.Errorf("best-effort sandbox not yielding: LS %d, BE %d", counts[0], counts[1])
	}
}

// TestWarmPool (FnCall, spec §22.3): requests for a pooled image take a
// started sandbox and get their own limits; the pool refills; such
// sandboxes survive an edge restart like any other.
func TestWarmPool(t *testing.T) {
	f := newBackendWith(t, func(o *Options) { o.WarmPool = map[string]int{"host": 2} })
	ready := func() int { f.b.pool.mu.Lock(); defer f.b.pool.mu.Unlock(); return len(f.b.pool.ready["host"]) }
	eventually(t, func() bool { return ready() == 2 })
	var lat []time.Duration
	var sbs []*backend.Sandbox
	for i := 0; i < 2; i++ {
		start := time.Now()
		sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 0.5, MemoryMb: 300}})
		lat = append(lat, time.Since(start))
		sbs = append(sbs, sb)
	}
	t.Logf("sandboxes from the warm pool in %v", lat)
	for _, d := range lat {
		if d > 50*time.Millisecond {
			t.Errorf("warm creation took %v", d)
		}
	}
	if got := out(sh(t, f, sbs[0], `cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max; echo hi > /tmp/x; cat /tmp/x`)); got != "314572800\n50000 100000\nhi" {
		t.Errorf("warm sandbox: %q", got)
	}
	eventually(t, func() bool { return ready() == 2 })
	// A non-poolable request starts cold.
	start := time.Now()
	cold := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}, InitUser: "nobody"})
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Errorf("custom request served from the pool? (%v)", d)
	}
	if r := sh(t, f, cold, `id -un`); out(r) != "nobody" {
		t.Errorf("cold sandbox user %q %q exit %d", r.Stdout, r.Stderr, r.ExitCode)
	}
	// Edge restart: the second backend adopts the pooled sandboxes by their
	// own ids; unassigned members do not survive.
	f.b.Detach()
	g, err := New(f.b.opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	keep := map[string]bool{}
	for _, sb := range append(sbs, cold) {
		if _, err := g.Adopt(context.Background(), sb); err != nil {
			t.Fatalf("adopt %s: %v", sb.ID, err)
		}
		keep[strings.SplitN(sb.ID, ".", 2)[1]] = true
	}
	g.CleanupExcept(keep)
	f.b = g
	if got := out(sh(t, f, sbs[1], `echo still`)); got != "still" {
		t.Errorf("adopted warm sandbox: %q", got)
	}
	g.Stop(context.Background(), sbs[1])
	ents, _ := os.ReadDir(g.sbRoot())
	if len(ents) != 4 { // 2 sandboxes (one a member + its symlink), the cold one, g's refilled members don't count yet
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Logf("state dir after stop: %v", names)
	}
	if _, err := os.Lstat(filepath.Join(g.sbRoot(), strings.SplitN(sbs[1].ID, ".", 2)[1])); err == nil {
		t.Error("stopped warm sandbox's symlink left")
	}
}

// TestOOMSparesAgents: at its memory limit the sandbox loses the hungry
// process, not aether or chronus.
func TestOOMSparesAgents(t *testing.T) {
	f := newBackend(t)
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 128}})
	if got := out(sh(t, f, sb, `cat /proc/1/oom_score_adj /proc/$PPID/oom_score_adj /proc/self/oom_score_adj`)); got != "-1000\n-1000\n0" {
		t.Errorf("oom_score_adj of aether, chronus, a command: %q", got)
	}
	r := sh(t, f, sb, `python3 -c 'x = bytearray(512 << 20); print(len(x))'`)
	if r.ExitCode == 0 {
		t.Fatalf("512 MB in a 128 MB sandbox: %q", r.Stdout)
	}
	if got := out(sh(t, f, sb, `echo alive`)); got != "alive" {
		t.Fatalf("after the OOM kill: %q", got)
	}
}

// TestDiskIOLimit (spec §24): writes to the writable disk are throttled.
func TestDiskIOLimit(t *testing.T) {
	f := newBackendWith(t, func(o *Options) { o.DiskIO = linuxrt.IOLimit{WriteMBps: 8} })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	start := time.Now()
	if r := sh(t, f, sb, `dd if=/dev/zero of=/tmp/f bs=1M count=24 conv=fsync status=none`); r.ExitCode != 0 {
		t.Fatalf("dd: %q", r.Stderr)
	}
	took := time.Since(start)
	t.Logf("24 MB at 8 MB/s in %v", took.Round(time.Millisecond))
	if took < 2*time.Second {
		t.Errorf("write not throttled: %v", took)
	}
}

// cookies maps each core scheduling cookie of the sandbox's threads to how
// many threads have it.
func cookies(t *testing.T, f *fixture, sb *backend.Sandbox) map[uint64]int {
	t.Helper()
	s, err := f.b.get(sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64]int{}
	for _, tid := range s.cg.Threads() {
		if c, err := linuxrt.CoreSchedCookie(tid); err == nil {
			out[c]++
		}
	}
	return out
}

// TestCoreSched (spec §29.1): with core_sched every thread of a sandbox,
// commands included, shares one cookie of its own; without, none has one.
func TestCoreSched(t *testing.T) {
	if linuxrt.CoreSchedSupported() != nil {
		t.Skip("no core scheduling in this kernel")
	}
	f := newBackendWith(t, func(o *Options) { o.CoreSched = true })
	var seen []uint64
	for i := 0; i < 2; i++ {
		sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
		sh(t, f, sb, `sleep 30 >/dev/null 2>&1 &`)
		c := cookies(t, f, sb)
		if len(c) != 1 || c[0] != 0 {
			t.Fatalf("sandbox %d: threads by cookie %v, want one non-zero cookie", i, c)
		}
		for k, n := range c {
			if n < 3 {
				t.Fatalf("sandbox %d: only %d threads", i, n)
			}
			seen = append(seen, k)
		}
	}
	if seen[0] == seen[1] {
		t.Fatal("two sandboxes share a cookie")
	}
	plain := newBackend(t)
	sb := plain.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	if c := cookies(t, plain, sb); len(c) != 1 || c[0] == 0 {
		t.Fatalf("without core_sched: %v, want no cookie", c)
	}
}

// TestCoreSchedQoS (OPENDSEC_BENCH=1; spec §29.1, paper §8.5): how a
// latency-sensitive sandbox fares next to best-effort ones keeping half the
// host's hardware threads busy, unprotected, with SCHED_IDLE (qos BE), and
// with core scheduling on top; and what core scheduling costs the
// best-effort side. OPENDSEC_BENCH_LS_THREADS (default 32),
// OPENDSEC_BENCH_LOAD_PCT (share of the hardware threads the load keeps busy,
// default 50) and OPENDSEC_BENCH_SECONDS (default 15) tune it.
func TestCoreSchedQoS(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	if linuxrt.CoreSchedSupported() != nil {
		t.Skip("no core scheduling in this kernel")
	}
	lsThreads, secs := 32, 15
	if n, err := strconv.Atoi(os.Getenv("OPENDSEC_BENCH_LS_THREADS")); err == nil && n > 0 {
		lsThreads = n
	}
	if n, err := strconv.Atoi(os.Getenv("OPENDSEC_BENCH_SECONDS")); err == nil && n > 0 {
		secs = n
	}
	// The probe lives under the host root, which these sandboxes see as
	// their image.
	dir, err := os.MkdirTemp("/var/tmp", "cpuwork")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	work := filepath.Join(dir, "cpuwork")
	if out, err := exec.Command("go", "build", "-o", work, "./testdata/cpuwork").CombinedOutput(); err != nil {
		t.Fatalf("build cpuwork: %v %s", err, out)
	}
	loadPct := 50
	if n, err := strconv.Atoi(os.Getenv("OPENDSEC_BENCH_LOAD_PCT")); err == nil && n > 0 {
		loadPct = n
	}
	beThreads := runtime.NumCPU() * loadPct / 100
	const beSandboxes = 4
	run := func(f *fixture, sb *backend.Sandbox, cmd string, timeout time.Duration) string {
		rt, err := f.b.Runtime(sb.ID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		r, err := rt.Exec(ctx, &pb.ExecRequest{Cmd: cmd})
		if err != nil {
			t.Fatalf("%q: %v", cmd, err)
		}
		return out(r)
	}
	field := func(s, k string) float64 {
		for _, kv := range strings.Fields(s) {
			if v, ok := strings.CutPrefix(kv, k+"="); ok {
				x, _ := strconv.ParseFloat(v, 64)
				return x
			}
		}
		return 0
	}
	type result struct{ name, ls, be string }
	var rows []result
	phase := func(name string, coreSched bool, beQoS string) {
		f := newBackendWith(t, func(o *Options) { o.CoreSched = coreSched })
		ls := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: float64(lsThreads), MemoryMb: 1024}, Qos: "LS"})
		var bes []*backend.Sandbox
		if beQoS != "" {
			per := beThreads / beSandboxes
			for i := 0; i < beSandboxes; i++ {
				be := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: float64(per), MemoryMb: 1024}, Qos: beQoS})
				run(f, be, fmt.Sprintf("%s -threads %d -d %ds >/tmp/be.out 2>&1 &", work, per, secs+6), 10*time.Second)
				bes = append(bes, be)
			}
			time.Sleep(3 * time.Second) // the best-effort load is up
		}
		r := result{name: name, ls: run(f, ls, fmt.Sprintf("%s -threads %d -d %ds", work, lsThreads, secs), time.Duration(secs+30)*time.Second)}
		var beRate float64
		for _, be := range bes {
			for i := 0; i < 30; i++ { // until its run ends
				o := run(f, be, "cat /tmp/be.out", 10*time.Second)
				if strings.Contains(o, "per_s=") {
					beRate += field(o, "per_s")
					break
				}
				time.Sleep(time.Second)
			}
		}
		if len(bes) > 0 {
			r.be = fmt.Sprintf("%.0f units/s", beRate)
		}
		rows = append(rows, r)
		for _, sb := range append(bes, ls) {
			f.b.Stop(context.Background(), sb)
		}
	}
	phase("LS alone", false, "")
	phase("+ load, unprotected", false, "LS")
	phase("+ load, SCHED_IDLE (qos BE)", false, "BE")
	phase("+ load, SCHED_IDLE + core sched", true, "BE")
	base := field(rows[0].ls, "mean_us")
	var b strings.Builder
	fmt.Fprintf(&b, "\nLS %d threads; load %d threads in %d sandboxes (%d%% of %d); %ds each\n", lsThreads, beThreads, beSandboxes,
		loadPct, runtime.NumCPU(), secs)
	fmt.Fprintf(&b, "%-34s %9s %9s %9s %10s %s\n", "case", "p50_us", "p99_us", "mean_us", "vs alone", "load throughput")
	for _, r := range rows {
		m := field(r.ls, "mean_us")
		fmt.Fprintf(&b, "%-34s %9.0f %9.0f %9.0f %+9.1f%% %s\n", r.name, field(r.ls, "p50_us"), field(r.ls, "p99_us"), m,
			100*(m/base-1), r.be)
	}
	t.Log(b.String())
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

// TestPackDiffOpaque (spec §29.5): a directory a sandbox deletes and
// recreates (opaque in its upper dir) keeps hiding what lay beneath once
// packed into the store, even on a store that keeps no xattrs (NFS: point
// OPENDSEC_TEST_STORE at one).
func TestPackDiffOpaque(t *testing.T) {
	dir := os.Getenv("OPENDSEC_TEST_STORE")
	if dir == "" {
		dir = t.TempDir()
	} else {
		var err error
		if dir, err = os.MkdirTemp(dir, "store"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	st, err := images.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := newBackendWith(t, func(o *Options) { o.Store = st })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	before := out(sh(t, f, sb, `ls /usr/share/doc | wc -l`))
	if before == "0" {
		t.Skip("the host's /usr/share/doc is empty")
	}
	if r := sh(t, f, sb, `rm -rf /usr/share/doc && mkdir /usr/share/doc && echo n > /usr/share/doc/new && ls /usr/share/doc`); out(r) != "new" {
		t.Fatalf("in the sandbox: %q %q", r.Stdout, r.Stderr)
	}
	layer, err := f.b.PackDiff(context.Background(), sb, images.NewDiffLayerID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The layer over a base showing what the sandbox's base (the host's /)
	// showed in /usr/share/doc. Not over / itself: / contains the store's
	// layer, and newer kernels refuse overlapping lowerdirs (6.8 allowed it).
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "usr/share/doc"), 0o755); err != nil {
		t.Fatal(err)
	}
	hostDoc, err := os.ReadDir("/usr/share/doc")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range hostDoc {
		if err := os.WriteFile(filepath.Join(base, "usr/share/doc", e.Name()), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mnt := t.TempDir()
	if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+st.LayerRootfs(layer.ID)+":"+base); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(mnt, "usr/share/doc"))
	unix.Unmount(mnt, unix.MNT_DETACH)
	if len(ents) != 1 || ents[0].Name() != "new" {
		t.Fatalf("packed layer over its base shows %d entries in /usr/share/doc (had %s before), want only new", len(ents), before)
	}
}
