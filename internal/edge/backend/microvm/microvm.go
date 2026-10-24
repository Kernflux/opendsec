// Package microvm is the Firecracker microVM backend (spec §19.3). Each
// sandbox is one Firecracker process started by the jailer (own chroot, own
// uid, fresh network/IPC/UTS namespaces, the sandbox's cgroup), booting a
// shared guest kernel from four drives: a read-only agent disk, the image
// flattened into a read-only ext4 disk shared by all its sandboxes, the
// sandbox's own sparse writable disk, and a small config disk. Inside,
// aether is PID 1 as in a container and serves the same Runtime API over
// vsock.
//
// Memory snapshots (phase F2): pausing snapshots the VM and ends its
// process, releasing its memory; resuming restores it in a new process.
// Snapshots in the image store start new sandboxes by restoring them
// (CreateSnapshot images, fork copies), each given its own identity.
package microvm

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const (
	imageCacheTTL = 24 * time.Hour // unused image disks kept this long
	startTimeout  = 30 * time.Second
	maxVCPUs      = 32 // Firecracker's limit
	uidRange      = 65536
	minMemoryMB   = 128
)

type Options struct {
	Store         *images.Store
	Name          string // backend name ("microvm")
	EdgeID        string
	StateDir      string
	AgentDir      string
	Images        map[string][]string
	DefaultDiskMB int64
	Kernel        string
	Firecracker   string
	Jailer        string
	UIDBase       int
	OverheadMB    int64
	// Memory optimizations (spec §19.13), from config.Backend.
	ImagePmem         bool
	FreePageReporting bool
	ColdAgeS          int
	ZramPct           int
	DiskIO            linuxrt.IOLimit // per VM, on the state filesystem's device (spec §24)
	// NoDirtyTracking turns KVM dirty page logging off: diff snapshots then
	// hold the pages mincore finds resident (spec §19.14; for measuring).
	NoDirtyTracking bool
	// UntrackedBoot: cold-booted VMs run without a dirty page log
	// (config cold_boot_dirty_tracking false; spec §19.14).
	UntrackedBoot bool
	CoreSched     bool // a core scheduling cookie per VM (spec §29.1)
	ErofsImages   bool // EROFS image disks, built once in the store (spec §29.4)
	Log           *slog.Logger
}

// FromConfig builds Options from an edge's config.
func FromConfig(name string, ec config.Edge, bc config.Backend, store *images.Store, log *slog.Logger) Options {
	o := Options{Name: name, EdgeID: ec.ID, StateDir: ec.StateDir, AgentDir: ec.AgentDir, Images: ec.Images, Store: store,
		DefaultDiskMB: bc.DefaultDiskMB, Kernel: bc.Kernel, Firecracker: bc.Firecracker, Jailer: bc.Jailer,
		UIDBase: bc.UIDBase, OverheadMB: bc.VMOverheadMB, ImagePmem: bc.ImagePmem, FreePageReporting: bc.FreePageReporting,
		ColdAgeS: bc.ColdAgeS, ZramPct: bc.ZramPct, CoreSched: linuxrt.CoreSchedDefault(bc.CoreSched), ErofsImages: bc.ErofsImages, Log: log,
		UntrackedBoot: bc.ColdBootDirtyTracking != nil && !*bc.ColdBootDirtyTracking,
		DiskIO:        linuxrt.IOLimit{ReadMBps: bc.DiskIO.ReadMBps, WriteMBps: bc.DiskIO.WriteMBps, ReadIOPS: bc.DiskIO.ReadIOPS, WriteIOPS: bc.DiskIO.WriteIOPS}}
	if o.AgentDir == "" {
		if self, err := os.Executable(); err == nil {
			o.AgentDir = filepath.Dir(self)
		}
	}
	if o.DefaultDiskMB == 0 {
		o.DefaultDiskMB = 10240
	}
	if o.Firecracker == "" {
		o.Firecracker = "firecracker"
	}
	if o.Jailer == "" {
		o.Jailer = "jailer"
	}
	if o.UIDBase == 0 {
		o.UIDBase = 1000000000
	}
	if o.OverheadMB == 0 {
		o.OverheadMB = 64
	}
	return o
}

// Check reports whether this host can run microVMs with these options,
// resolving the binaries on PATH.
func Check(o *Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("microvm backend needs root")
	}
	if o.CoreSched {
		if err := linuxrt.CoreSchedSupported(); err != nil {
			return err
		}
	}
	if o.ErofsImages {
		if _, err := exec.LookPath("mkfs.erofs"); err != nil {
			return fmt.Errorf("erofs_images needs mkfs.erofs (erofs-utils): %w", err)
		}
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("no usable /dev/kvm: %w", err)
	}
	f.Close()
	if _, err := os.Stat(filepath.Join(linuxrt.CgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 not mounted at %s", linuxrt.CgroupRoot)
	}
	if o.Kernel == "" {
		return fmt.Errorf("no guest kernel configured (backend \"kernel\")")
	}
	if _, err := os.Stat(o.Kernel); err != nil {
		return fmt.Errorf("guest kernel: %w", err)
	}
	for _, p := range []*string{&o.Firecracker, &o.Jailer} {
		abs, err := exec.LookPath(*p)
		if err != nil {
			return err
		}
		*p = abs
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		return fmt.Errorf("mkfs.ext4 not found")
	}
	return nil
}

type Backend struct {
	fcVersion string // `firecracker --version`, spec §28.12
	opt       Options
	cgRel     string
	kernel    string // the guest kernel, on the state filesystem (hard-linkable)
	agents    string // the agent disk
	imgs      *ImageCache
	snaps     *snapCache      // nil without a store
	netCG     *linuxrt.Cgroup // the sandboxes' network namespace holders
	done      chan struct{}
	close     sync.Once

	mu     sync.Mutex
	sbs    map[string]*sandbox
	uids   map[int]bool
	onLost func(id, reason string)
}

// probeVersion runs `firecracker --version` ("Firecracker v1.17.0") and
// returns "1.17.0" ("" if it cannot tell).
func probeVersion(bin string) string {
	if bin == "" {
		bin = "firecracker"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return strings.TrimPrefix(f[len(f)-1], "v")
}

// RuntimeVersions reports the Firecracker version the backend runs.
func (b *Backend) RuntimeVersions() map[string]string {
	if b.fcVersion == "" {
		return nil
	}
	return map[string]string{"firecracker": b.fcVersion}
}

// New prepares the backend: the agent disk and the guest kernel are staged
// in the node-local cache next to the jails, so they can be hard-linked in.
func New(opt Options) (*Backend, error) {
	if err := Check(&opt); err != nil {
		return nil, err
	}
	b := &Backend{opt: opt, cgRel: filepath.Join("opendsec", opt.EdgeID+"-"+opt.Name),
		sbs: map[string]*sandbox{}, uids: map[int]bool{}, onLost: func(string, string) {}, done: make(chan struct{})}
	for _, d := range []string{b.sbRoot(), b.jailBase(), b.cacheDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	os.Chmod(b.jailBase(), 0o711) // the jailed uids traverse it to their chroot
	b.imgs = &ImageCache{dir: b.cacheDir(), Store: opt.Store, Erofs: opt.ErofsImages, building: map[string]*build{}}
	if opt.Store != nil {
		b.snaps = &snapCache{dir: filepath.Join(b.cacheDir(), "snapshots"), disks: b.cacheDir(), store: opt.Store, log: opt.Log, pulling: map[string]*build{}}
		if err := os.MkdirAll(b.snaps.dir, 0o700); err != nil {
			return nil, err
		}
		b.snaps.resumePublishing(opt.EdgeID, opt.Log)
	}
	go b.gcLoop()
	var err error
	if b.agents, err = BuildAgentDisk(b.cacheDir(), opt.AgentDir); err != nil {
		return nil, fmt.Errorf("agent disk: %w", err)
	}
	b.kernel = filepath.Join(b.cacheDir(), "vmlinux-"+filepath.Base(opt.Kernel))
	if fi, err := os.Stat(b.kernel); err != nil || !sameFile(fi, opt.Kernel) {
		os.Remove(b.kernel)
		if err := LinkOrCopy(opt.Kernel, b.kernel); err != nil {
			return nil, fmt.Errorf("stage kernel: %w", err)
		}
	}
	if err := linuxrt.EnsureParent(b.cgRel, !opt.DiskIO.Zero()); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	b.fcVersion = probeVersion(opt.Firecracker)
	if b.netCG, err = linuxrt.NewCgroup(b.cgRel, "netns", linuxrt.Limits{}); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	return b, nil
}

func sameFile(fi os.FileInfo, path string) bool {
	o, err := os.Stat(path)
	return err == nil && (os.SameFile(fi, o) || fi.Size() == o.Size() && fi.ModTime().Equal(o.ModTime()))
}

func (b *Backend) Name() string { return b.opt.Name }

func (b *Backend) sbRoot() string {
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "sb")
}
func (b *Backend) jailBase() string {
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "jail")
}
func (b *Backend) cacheDir() string {
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "cache")
}

// jailDir is the jailer's per-VM directory (<base>/<exec name>/<id>).
func (b *Backend) jailDir(lease string) string {
	return filepath.Join(b.jailBase(), filepath.Base(b.opt.Firecracker), lease)
}

// Images: as for containers, a shared store makes every image runnable.
func (b *Backend) Images() []string {
	if b.opt.Store != nil {
		return nil
	}
	out := make([]string, 0, len(b.opt.Images))
	for name := range b.opt.Images {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (b *Backend) OnLost(f func(id, reason string)) { b.onLost = f }

func (b *Backend) get(id string) (*sandbox, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sbs[id]
	if s == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "microvm %s", id)
	}
	return s, nil
}

// allocUID picks a free uid for a VM, starting from a lease-derived slot.
func (b *Backend) allocUID(lease string) (int, error) {
	h := fnv.New32a()
	h.Write([]byte(lease))
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := 0; i < uidRange; i++ {
		uid := b.opt.UIDBase + int((h.Sum32()+uint32(i))%uidRange)
		if !b.uids[uid] {
			b.uids[uid] = true
			return uid, nil
		}
	}
	return 0, rpcutil.Err(rpcutil.NoCapacity, "no free microvm uid")
}

func (b *Backend) freeUID(uid int) {
	b.mu.Lock()
	delete(b.uids, uid)
	b.mu.Unlock()
}

// CleanupExcept removes every VM, jail and cgroup of this backend whose
// lease is not in keep.
func (b *Backend) CleanupExcept(keep map[string]bool) {
	leases := map[string]bool{}
	for _, dir := range []string{b.sbRoot(), filepath.Dir(b.jailDir("x")), filepath.Join(linuxrt.CgroupRoot, b.cgRel)} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() && !keep[e.Name()] && ids.ValidLease(e.Name()) {
				leases[e.Name()] = true
			}
		}
	}
	// Network namespace holders no kept sandbox owns.
	owned := map[int]bool{}
	b.mu.Lock()
	for _, s := range b.sbs {
		if s.st.Holder != nil {
			owned[s.st.Holder.Pid] = true
		}
	}
	b.mu.Unlock()
	for _, pid := range b.netCG.Procs() {
		if !owned[pid] {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	for lease := range leases {
		cg := &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, lease)}
		cg.Kill()
		cg.Remove()
		os.RemoveAll(b.jailDir(lease))
		os.RemoveAll(filepath.Join(b.sbRoot(), lease))
		b.opt.Log.Info("removed leftover microvm", "lease", lease)
	}
}

func (b *Backend) gcLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if b.snaps != nil {
			b.snaps.gc()
		}
		for _, p := range b.imgs.GC(imageCacheTTL) {
			b.opt.Log.Info("removed unused image disk", "path", p)
		}
		select {
		case <-t.C:
		case <-b.done:
			return
		}
	}
}

func (b *Backend) stopLoops() { b.close.Do(func() { close(b.done) }) }

// Close tears down every VM and removes this backend's cgroup.
func (b *Backend) Close() {
	b.stopLoops()
	b.mu.Lock()
	ss := b.sbs
	b.sbs = map[string]*sandbox{}
	b.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range ss {
		wg.Add(1)
		go func(s *sandbox) { defer wg.Done(); b.teardown(s) }(s)
	}
	wg.Wait()
	b.netCG.Kill()
	b.netCG.Remove()
	(&linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel)}).Remove()
}

// Detach drops connections without stopping the VMs (edge restart with
// keep_sandboxes_on_exit).
func (b *Backend) Detach() {
	b.stopLoops()
	b.mu.Lock()
	ss := b.sbs
	b.sbs = map[string]*sandbox{}
	b.mu.Unlock()
	for _, s := range ss {
		s.once.Do(func() { close(s.stopped) })
		if v := s.vm(); v != nil {
			v.disconnect()
		}
	}
}

// tail returns the last lines of a log file, for error messages.
func tail(path string) string {
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return strings.Join(lines, " | ")
}

func cmpOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
