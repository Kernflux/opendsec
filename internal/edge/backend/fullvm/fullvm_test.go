package fullvm

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
)

var agentDir, imageDir, initImageDir, kernel string

func TestMain(m *testing.M) {
	kernel = os.Getenv("OPENDSEC_FC_OPENDSEC_KERNEL")
	if kernel == "" {
		kernel = "/data/opendsec-vm/vmlinux-6.1.167-opendsec"
	}
	opt := Options{Kernel: kernel, QEMU: "qemu-system-x86_64"}
	if err := Check(&opt); err != nil {
		fmt.Println("skipping fullvm backend tests:", err)
		os.Exit(0)
	}
	dir, _ := os.MkdirTemp("", "opendsec-agents")
	cmd := exec.Command("go", "build", "-o", dir, "github.com/kernflux/opendsec/cmd/opendsec-aether", "github.com/kernflux/opendsec/cmd/opendsec-chronus")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("build agents: " + err.Error() + "\n" + string(out))
	}
	agentDir = dir
	imageDir, _ = os.MkdirTemp("", "opendsec-vmimg")
	if err := miniRootfs(imageDir); err != nil {
		panic(err)
	}
	// An image with its own init (as systemd would be): PID 1 of the VM.
	initImageDir, _ = os.MkdirTemp("", "opendsec-vminit")
	os.MkdirAll(filepath.Join(initImageDir, "sbin"), 0o755)
	os.WriteFile(filepath.Join(initImageDir, "sbin/init"), []byte("#!/bin/sh\necho booted > /tmp/init-ran\nwhile :; do sleep 3600; done\n"), 0o755)
	code := m.Run()
	for _, d := range []string{dir, imageDir, initImageDir} {
		os.RemoveAll(d)
	}
	os.Exit(code)
}

func miniRootfs(dir string) error {
	tools := []string{"bash", "sh", "cat", "ls", "grep", "wc", "sleep", "echo", "tr", "head", "dd", "sync"}
	os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755)
	libs := map[string]bool{}
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			return err
		}
		real, _ := filepath.EvalSymlinks(p)
		b, err := os.ReadFile(real)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "usr/bin", tool), b, 0o755); err != nil {
			return err
		}
		out, _ := exec.Command("ldd", real).Output()
		for _, f := range strings.Fields(string(out)) {
			if strings.HasPrefix(f, "/") {
				libs[f] = true
			}
		}
	}
	for l := range libs {
		real, _ := filepath.EvalSymlinks(l)
		b, err := os.ReadFile(real)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, strings.TrimPrefix(l, "/"))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			return err
		}
	}
	os.Symlink("usr/bin", filepath.Join(dir, "bin"))
	for _, d := range []string{"etc", "tmp", "root", "proc", "sys", "dev"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	return nil
}

type fixture struct {
	b   *Backend
	opt Options
}

func newBackend(t *testing.T, edit func(*Options)) *fixture {
	t.Helper()
	state, err := os.MkdirTemp("", "opendsec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	opt := Options{Name: "fullvm", EdgeID: "t" + strings.ToLower(ids.NewLease()[:6]), StateDir: state, AgentDir: agentDir,
		Images: map[string][]string{"mini": {imageDir}, "init": {initImageDir, imageDir}}, DefaultDiskMB: 256,
		Kernel: kernel, QEMU: "qemu-system-x86_64", UIDBase: 1100000000, OverheadMB: 160,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if edit != nil {
		edit(&opt)
	}
	b, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return &fixture{b: b, opt: opt}
}

func (f *fixture) create(t *testing.T, spec *pb.SandboxSpec) *backend.Sandbox {
	t.Helper()
	sb := &backend.Sandbox{ID: ids.Sandbox(f.opt.EdgeID, ids.NewLease()), Spec: spec}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.b.Create(ctx, sb); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("full vm booted in %v", time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { f.b.Stop(context.Background(), sb) })
	return sb
}

func sh(t *testing.T, b *Backend, sb *backend.Sandbox, cmd string) string {
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
	return strings.TrimSpace(string(r.Stdout))
}

func TestBootPauseAdopt(t *testing.T) {
	f := newBackend(t, nil)
	sb := f.create(t, &pb.SandboxSpec{Image: "mini", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 512}})
	if got := sh(t, f.b, sb, `grep -c ^processor /proc/cpuinfo; ls /sys/bus/pci/devices | wc -l; cat /proc/1/cmdline | tr '\0' ' '`); !strings.HasPrefix(got, "2\n") ||
		!strings.Contains(got, "opendsec-aether --init") {
		t.Fatalf("guest: %q", got)
	} else if n := strings.Split(got, "\n")[1]; n == "0" {
		t.Fatalf("no PCI devices in the guest: %q", got)
	}
	ctx := context.Background()
	s, _ := f.b.get(sb.ID)
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if st, err := qmpStatus(ctx, filepath.Join(s.dir, "qmp.sock")); err != nil || st != "paused" {
		t.Fatalf("after pause: %q %v", st, err)
	}
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, f.b, sb, `echo back`); got != "back" {
		t.Fatalf("after resume: %q", got)
	}
	// An edge restart: a paused VM is adopted as paused.
	f.b.Pause(ctx, sb)
	f.b.Detach()
	g, err := New(f.opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	paused, err := g.Adopt(ctx, sb)
	if err != nil || !paused {
		t.Fatalf("adopt: %v %v", paused, err)
	}
	g.Resume(ctx, sb)
	if got := sh(t, g, sb, `echo adopted`); got != "adopted" {
		t.Fatalf("after adopt: %q", got)
	}
	g.Stop(ctx, sb)
	if _, err := os.Stat(s.dir); err == nil {
		t.Error("state dir left")
	}
	if _, err := os.Stat(s.cg.Path); err == nil {
		t.Error("cgroup left")
	}
}

func TestFullInit(t *testing.T) {
	f := newBackend(t, func(o *Options) { o.FullInit = true })
	sb := f.create(t, &pb.SandboxSpec{Image: "init", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	var got string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if got = sh(t, f.b, sb, `cat /proc/1/cmdline | tr '\0' ' '; cat /tmp/init-ran 2>/dev/null`); strings.Contains(got, "booted") {
			break
		}
	}
	if !strings.Contains(got, "/sbin/init") || !strings.Contains(got, "booted") {
		t.Fatalf("PID 1 should be the image's init: %q", got)
	}
	// Images without an init fall back to aether as PID 1.
	sb2 := f.create(t, &pb.SandboxSpec{Image: "mini", Resources: &pb.Resources{MemoryMb: 256}})
	if got := sh(t, f.b, sb2, `cat /proc/1/cmdline | tr '\0' ' '`); !strings.Contains(got, "opendsec-aether --init") {
		t.Fatalf("without /sbin/init: %q", got)
	}
}

func TestDiskIOLimit(t *testing.T) {
	f := newBackend(t, func(o *Options) { o.DiskIO = linuxrt.IOLimit{WriteMBps: 8} })
	sb := f.create(t, &pb.SandboxSpec{Image: "mini", Resources: &pb.Resources{MemoryMb: 256}})
	start := time.Now()
	sh(t, f.b, sb, `dd if=/dev/zero of=/root/f bs=1M count=24 conv=fsync status=none`)
	took := time.Since(start)
	t.Logf("24 MB at 8 MB/s in %v", took.Round(time.Millisecond))
	if took < 2500*time.Millisecond {
		t.Errorf("write not throttled: %v", took)
	}
}
