// Package container is the Linux container backend (spec §11.2): overlayfs
// rootfs over the image's layers, a per-sandbox ext4 writable disk, cgroup v2
// limits, fresh mount/pid/uts/ipc/net/cgroup namespaces, aether as PID 1, and
// cgroup freeze for pause/resume.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const startTimeout = 15 * time.Second

type Options struct {
	Store         *images.Store // shared image store; nil = static images only
	Name          string        // backend name ("container")
	EdgeID        string
	StateDir      string // <state_dir>; sandboxes live in <state_dir>/<edge>/sb/<lease>
	AgentDir      string
	Images        map[string][]string
	DefaultDiskMB int64
	PidsMax       int
	GPUs          *linuxrt.GPUs   // the node's GPUs (spec §22.2); nil = none
	PauseReclaim  bool            // spec §22.1
	WarmPool      map[string]int  // image -> sandboxes kept started (FnCall, spec §22.3)
	DiskIO        linuxrt.IOLimit // per sandbox, on its writable disk (spec §24)
	CoreSched     bool            // a core scheduling cookie per sandbox (spec §29.1)
	LayerCache    bool            // run on node-local copies of store layers (spec §33.1)
	Log           *slog.Logger
}

// FromConfig builds Options from an edge's config.
func FromConfig(name string, ec config.Edge, bc config.Backend, store *images.Store, log *slog.Logger) Options {
	o := Options{Name: name, EdgeID: ec.ID, StateDir: ec.StateDir, AgentDir: ec.AgentDir, Images: ec.Images,
		DefaultDiskMB: bc.DefaultDiskMB, PidsMax: bc.PidsMax, PauseReclaim: bc.PauseReclaim, WarmPool: bc.WarmPool, CoreSched: linuxrt.CoreSchedDefault(bc.CoreSched), Log: log, Store: store,
		LayerCache: bc.LayerCache == nil || *bc.LayerCache,
		DiskIO:     linuxrt.IOLimit{ReadMBps: bc.DiskIO.ReadMBps, WriteMBps: bc.DiskIO.WriteMBps, ReadIOPS: bc.DiskIO.ReadIOPS, WriteIOPS: bc.DiskIO.WriteIOPS}}
	if o.AgentDir == "" {
		if self, err := os.Executable(); err == nil {
			o.AgentDir = filepath.Dir(self)
		}
	}
	if o.DefaultDiskMB == 0 {
		o.DefaultDiskMB = 10240
	}
	if o.PidsMax == 0 {
		o.PidsMax = 4096
	}
	return o
}

type sandbox struct {
	mu      sync.Mutex // id, alias: set when a warm member is assigned
	id, dir string
	lease   string // the state dir's and cgroup's name
	alias   string // the sandbox's own lease, when it is a warm member's (a symlink to lease)
	cg      *linuxrt.Cgroup
	proc    *exec.Cmd // nil for adopted sandboxes (not our child)
	pid     int       // host pid of the sandbox init
	start   uint64    // its /proc starttime, guarding against pid reuse
	exited  chan struct{}
	exitMu  sync.Once
	conn    *grpc.ClientConn
	rt      pb.RuntimeClient
	stopped chan struct{} // closed when Stop/Detach begins: losses after this are expected
	once    sync.Once

	reclaimed int64 // by the last pause (spec §22.1)
}

func (s *sandbox) markExited() { s.exitMu.Do(func() { close(s.exited) }) }

// diskDir is where the edge reaches the sandbox's writable disk: inside the
// sandbox's mount namespace, or on the host for sandboxes of earlier
// versions that mounted it there.
func (s *sandbox) diskDir() string {
	if host := filepath.Join(s.dir, "disk"); linuxrt.Mounted(host) {
		return host
	}
	return fmt.Sprintf("/proc/%d/root/.opendsec/disk", s.pid)
}

// runtimeState is persisted in the sandbox dir so a restarted edge can
// re-adopt the sandbox (spec §13.3).
type runtimeState struct {
	Pid       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
	GPUs      []int  `json:"gpus,omitempty"` // device indices (spec §22.2)
	SharedGPU bool   `json:"shared_gpu,omitempty"`
}

type Backend struct {
	opt    Options
	cgRel  string // cgroup parent, relative to /sys/fs/cgroup
	mu     sync.Mutex
	sbs    map[string]*sandbox
	onLost func(id, reason string)
	pool   *warmPool   // FnCall (spec §22.3); nil without warm_pool
	layers *layerCache // nil without a store or with layer_cache off
	done   chan struct{}
	close  sync.Once
}

// Check reports whether this host can run the backend.
func Check() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("container backend needs root")
	}
	if _, err := os.Stat(filepath.Join(linuxrt.CgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 not mounted at %s", linuxrt.CgroupRoot)
	}
	b, _ := os.ReadFile("/proc/filesystems")
	if !strings.Contains(string(b), "overlay") {
		return fmt.Errorf("kernel lacks overlayfs")
	}
	if !haveMkfs() {
		return fmt.Errorf("mkfs.ext4 not found")
	}
	return nil
}

// New prepares the backend. Sandboxes left by a previous edge process are
// untouched until the edge calls Adopt for the ones it has records of and
// CleanupExcept for the rest.
func New(opt Options) (*Backend, error) {
	if err := Check(); err != nil {
		return nil, err
	}
	if opt.CoreSched {
		if err := linuxrt.CoreSchedSupported(); err != nil {
			return nil, err
		}
	}
	for _, bin := range []string{"opendsec-aether", "opendsec-chronus"} {
		if _, err := os.Stat(filepath.Join(opt.AgentDir, bin)); err != nil {
			return nil, fmt.Errorf("agent binary %s not found in %s (set agent_dir)", bin, opt.AgentDir)
		}
	}
	if opt.PauseReclaim && linuxrt.Swappiness() == 0 {
		return nil, fmt.Errorf("pause_reclaim needs vm.swappiness > 0 (cgroup reclaim takes no anonymous memory at 0): e.g. sysctl vm.swappiness=10")
	}
	b := &Backend{opt: opt, cgRel: filepath.Join("opendsec", opt.EdgeID), sbs: map[string]*sandbox{}, onLost: func(string, string) {},
		done: make(chan struct{})}
	if opt.Name != "" && opt.Name != "container" {
		// Each container-runtime backend of an edge (container, fncall, ...)
		// keeps its own sandboxes: cleaning up after a restart, one must not
		// take another's for leftovers. "container" keeps the original paths.
		b.cgRel = filepath.Join("opendsec", opt.EdgeID+"-"+opt.Name)
	}
	if err := linuxrt.EnsureParent(b.cgRel, !opt.DiskIO.Zero()); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	if err := os.MkdirAll(b.sbRoot(), 0o700); err != nil {
		return nil, err
	}
	if opt.Store != nil && opt.LayerCache {
		var err error
		if b.layers, err = newLayerCache(filepath.Join(opt.StateDir, opt.EdgeID, "layers"), opt.Store); err != nil {
			return nil, err
		}
		go b.gcLoop()
	}
	if len(opt.WarmPool) > 0 {
		b.pool = newWarmPool(b, opt.WarmPool)
	}
	return b, nil
}

// gcLoop removes cached layers nothing uses any more.
func (b *Backend) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-b.done:
			return
		}
		for _, id := range b.layers.gc(filepath.Join(b.opt.StateDir, b.opt.EdgeID), layerCacheTTL) {
			b.opt.Log.Info("removed unused cached layer", "layer", id)
		}
	}
}

func (b *Backend) Name() string { return b.opt.Name }

// Images lists the locally configured images (spec §17.1). With a shared
// image store every edge runs every image, so it reports no restriction
// (static images must then be configured identically on all edges).
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

// Close tears down any remaining sandboxes and removes this edge's cgroup.
func (b *Backend) Close() {
	b.close.Do(func() { close(b.done) })
	b.pool.close()
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
	(&linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel)}).Remove()
}

func (b *Backend) OnLost(f func(id, reason string)) { b.onLost = f }

func (b *Backend) sbRoot() string {
	if b.opt.Name != "" && b.opt.Name != "container" {
		return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "sb")
	}
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, "sb")
}

// CleanupExcept removes every sandbox directory, cgroup and disk mount of this
// edge whose lease is not in keep (leftovers that could not be adopted).
func (b *Backend) CleanupExcept(keep map[string]bool) {
	// Kept sandboxes made from warm members: keep what their symlink names.
	keep = maps.Clone(keep)
	ents, _ := os.ReadDir(b.sbRoot())
	for _, e := range ents {
		if target, err := os.Readlink(filepath.Join(b.sbRoot(), e.Name())); err == nil {
			if keep[e.Name()] {
				keep[target] = true
			} else {
				os.Remove(filepath.Join(b.sbRoot(), e.Name()))
			}
		}
	}
	ents, _ = os.ReadDir(b.sbRoot())
	for _, e := range ents {
		if keep[e.Name()] || e.Type()&os.ModeSymlink != 0 || b.pool.owns(e.Name()) {
			continue
		}
		cg := &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, e.Name())}
		cg.Kill()
		cg.Remove()
		dir := filepath.Join(b.sbRoot(), e.Name())
		unmount(filepath.Join(dir, "disk"))
		os.RemoveAll(dir)
		b.opt.Log.Info("removed leftover sandbox", "lease", e.Name())
	}
	if b.opt.Store != nil {
		prefix := b.holder("")
		for _, h := range b.opt.Store.InUseHolders(prefix) {
			if l := strings.TrimPrefix(h, prefix); !keep[l] && !b.pool.owns(l) {
				b.opt.Store.ReleaseInUse(h)
			}
		}
	}
	cgs, _ := os.ReadDir(filepath.Join(linuxrt.CgroupRoot, b.cgRel))
	for _, e := range cgs {
		if e.IsDir() && !keep[e.Name()] && !b.pool.owns(e.Name()) {
			cg := &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, e.Name())}
			cg.Kill()
			cg.Remove()
		}
	}
}

// Detach drops connections to all sandboxes without stopping them (edge
// shutdown with keep_sandboxes_on_exit); a restarted edge re-adopts them.
func (b *Backend) Detach() {
	b.pool.close() // unassigned members: nobody would adopt them
	b.mu.Lock()
	ss := b.sbs
	b.sbs = map[string]*sandbox{}
	b.mu.Unlock()
	for _, s := range ss {
		s.once.Do(func() { close(s.stopped) })
		if s.conn != nil {
			s.conn.Close()
		}
	}
}

func (b *Backend) get(id string) (*sandbox, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sbs[id]
	if s == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "container %s", id)
	}
	return s, nil
}

func (b *Backend) Create(ctx context.Context, sb *backend.Sandbox) error {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return err
	}
	if s := b.pool.take(sb); s != nil {
		return b.assign(s, sb, lease)
	}
	s, err := b.start(ctx, sb, lease, false)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.mu.Unlock()
	return nil
}

// start creates and starts a sandbox for sb under lease; warm (a pool
// member) prepares it for networking assigned later.
func (b *Backend) start(ctx context.Context, sb *backend.Sandbox, lease string, warm bool) (_ *sandbox, err error) {
	spec := sb.Spec
	var img *resolved
	if spec.Snapshot != "" {
		img, err = b.resolveSnapshot(spec.Snapshot)
	} else {
		img, err = b.resolve(spec.Image)
	}
	if err != nil {
		return nil, err
	}
	lower := img.lower
	s := &sandbox{id: sb.ID, lease: lease, dir: filepath.Join(b.sbRoot(), lease), exited: make(chan struct{}), stopped: make(chan struct{})}
	defer func() {
		if err != nil {
			b.teardown(s)
		}
	}()
	runDir, rootfs, disk := filepath.Join(s.dir, "run"), filepath.Join(s.dir, "rootfs"), filepath.Join(s.dir, "disk")
	for _, d := range []string{runDir, rootfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// While it runs, the store keeps its layers (GC, spec §24).
	if b.opt.Store != nil && len(img.layers) > 0 {
		if err := b.opt.Store.MarkInUse(b.holder(lease), img.layers); err != nil {
			return nil, err
		}
	}
	// The layers resolved now, not the image name: a tag can be overwritten
	// later, and a snapshot must stack on what the sandbox actually runs.
	if err := linuxrt.WriteJSON(filepath.Join(s.dir, "image.json"), imageState{Base: img.base, Layers: img.layers,
		Env: img.env, Workdir: img.workdir, User: img.user}); err != nil {
		return nil, err
	}
	// Run on local copies of the store layers (after image.json: from then
	// on the cache's GC sees them in use).
	if b.layers != nil && len(img.layers) > 0 {
		local, err := b.layers.lowerdirs(img.layers)
		if err != nil {
			return nil, err
		}
		lower = append(local, b.opt.Images[img.base]...)
	}
	diskMB := spec.Resources.GetDiskMb()
	if diskMB <= 0 {
		diskMB = b.opt.DefaultDiskMB
	}
	loopDev, loopRdev, loopf, err := makeDisk(filepath.Join(s.dir, "disk.img"), diskMB)
	if err != nil {
		return nil, fmt.Errorf("writable disk: %w", err)
	}
	defer loopf.Close() // the sandbox's mount holds the device from then on
	if err := os.MkdirAll(disk, 0o755); err != nil {
		return nil, err
	}
	s.cg, err = linuxrt.NewCgroup(b.cgRel, lease, linuxrt.Limits{
		CPUCores: spec.Resources.GetCpuCores(), MemoryMB: spec.Resources.GetMemoryMb(),
		Pids: b.opt.PidsMax, BestEffort: spec.Qos == "BE",
	})
	if err != nil {
		return nil, err
	}
	if !b.opt.DiskIO.Zero() {
		if err := s.cg.SetIO(loopRdev, b.opt.DiskIO); err != nil {
			return nil, err
		}
	}
	cgfd, err := s.cg.Open()
	if err != nil {
		return nil, err
	}
	defer cgfd.Close()

	workdir := spec.Labels["workdir"]
	if workdir == "" {
		workdir = img.workdir
	}
	if workdir == "" {
		workdir = "/"
	}
	user := spec.InitUser
	if user == "" {
		user = img.user
	}
	var gpus []int
	shared := spec.GpuMode == "shared"
	var devices, gpuMounts []string
	if spec.Resources.GetGpus() > 0 || shared {
		if b.opt.GPUs == nil || len(b.opt.GPUs.Devices) == 0 {
			return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s has no GPUs", b.opt.EdgeID)
		}
		if gpus, err = b.opt.GPUs.Allocate(lease, int(spec.Resources.GetGpus()), shared); err != nil {
			return nil, err
		}
		devices, gpuMounts = b.opt.GPUs.Paths(gpus), b.opt.GPUs.Mounts
		env := map[string]string{}
		for k, v := range img.env {
			env[k] = v
		}
		var vis []string
		for i := range gpus {
			vis = append(vis, strconv.Itoa(i))
		}
		// The devices appear under their own names; inside, CUDA numbers
		// what it sees from 0.
		env["CUDA_VISIBLE_DEVICES"] = strings.Join(vis, ",")
		env["NVIDIA_VISIBLE_DEVICES"] = "all"
		img.env = env
	}
	aenv, _ := json.Marshal(img.env)
	var resolv string
	if sb.Net != nil || warm {
		// A warm sandbox's network comes when it is assigned: the file is
		// bound now, written then.
		resolv = filepath.Join(s.dir, "resolv.conf")
		if err := os.WriteFile(resolv, []byte(resolvConf(sb.Net)), 0o644); err != nil {
			return nil, err
		}
	}
	icfg, _ := json.Marshal(initConfig{
		Resolv: resolv, ReadonlyPaths: spec.ReadonlyPaths, MaskedPaths: spec.MaskedPaths, Devices: devices, Mounts: gpuMounts,
		Lower: lower, Disk: loopDev, DiskDir: disk, Rootfs: rootfs, AgentDir: b.opt.AgentDir, RunDir: runDir,
		Hostname: "sb-" + lease[:12], CoreSched: b.opt.CoreSched,
		AetherArgs: []string{"--socket", "/.opendsec/run/aether.sock", "--rundir", "/.opendsec/run",
			"--workdir", workdir, "--user", user, "--env", string(aenv)},
	})
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	logf, err := os.Create(filepath.Join(s.dir, "init.log"))
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	cmd := &exec.Cmd{
		Path: self, Args: []string{initArg0},
		Env:    []string{initEnvKey + "=" + string(icfg), "GOMAXPROCS=" + strconv.Itoa(goMaxProcs(spec.Resources.GetCpuCores()))},
		Stdout: logf, Stderr: logf,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS |
				syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | syscall.CLONE_NEWCGROUP,
			UseCgroupFD: true, CgroupFD: int(cgfd.Fd()),
			Setsid: true,
		},
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start sandbox init: %w", err)
	}
	s.proc, s.pid = cmd, cmd.Process.Pid
	go func() { linuxrt.WaitCmd(cmd); s.markExited() }()
	s.start, _ = linuxrt.ProcStartTime(s.pid)
	if sb.Net != nil {
		if err := sb.Net.Setup(s.pid, 0); err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
	}
	if err := linuxrt.WriteJSON(filepath.Join(s.dir, "state.json"), runtimeState{Pid: s.pid, StartTime: s.start,
		GPUs: gpus, SharedGPU: shared}); err != nil {
		return nil, fmt.Errorf("persist runtime state: %w", err)
	}

	sock := filepath.Join(runDir, "aether.sock")
	deadline := time.Now().Add(startTimeout)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case <-s.exited:
			return nil, fmt.Errorf("sandbox init exited: %s", tail(filepath.Join(s.dir, "init.log")))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("aether did not start within %v: %s", startTimeout, tail(filepath.Join(s.dir, "init.log")))
		}
	}
	watch, err := b.connect(ctx, s, sock, deadline)
	if err != nil {
		return nil, err
	}
	go b.watch(s, watch)
	return s, nil
}

func resolvConf(n *netpol.Attachment) string {
	if n == nil {
		return ""
	}
	return "nameserver " + n.Nameserver() + "\noptions timeout:2 attempts:2\n"
}

// connect dials aether and waits for its first heartbeat. The socket file
// appears at bind(), slightly before listen(), so failures are retried until
// the deadline rather than trusting the file.
func (b *Backend) connect(ctx context.Context, s *sandbox, sock string, deadline time.Time) (pb.Runtime_WatchClient, error) {
	var err error
	s.conn, err = grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(80<<20), grpc.MaxCallSendMsgSize(80<<20)))
	if err != nil {
		return nil, err
	}
	s.rt = pb.NewRuntimeClient(s.conn)
	for {
		watch, err := s.rt.Watch(context.Background(), &pb.Empty{})
		if err == nil {
			if _, err = watch.Recv(); err == nil {
				return watch, nil
			}
		}
		select {
		case <-s.exited:
			return nil, fmt.Errorf("sandbox init exited: %s", tail(filepath.Join(s.dir, "init.log")))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("aether channel: %v: %s", err, tail(filepath.Join(s.dir, "init.log")))
		}
	}
}

// Adopt re-attaches to a sandbox started by a previous edge process: the init
// process must still be the same process (pid + starttime) inside this
// sandbox's cgroup, the writable disk must still be mounted, and aether must
// answer. Reports whether the sandbox is frozen (paused).
func (b *Backend) Adopt(ctx context.Context, sb *backend.Sandbox) (bool, error) {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return false, err
	}
	// A sandbox made from a warm member: its state is the member's.
	internal, alias := lease, ""
	if target, err := os.Readlink(filepath.Join(b.sbRoot(), lease)); err == nil {
		internal, alias = target, lease
	}
	s := &sandbox{id: sb.ID, dir: filepath.Join(b.sbRoot(), internal), alias: alias, exited: make(chan struct{}), stopped: make(chan struct{}),
		cg: &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, internal)}}
	var st runtimeState
	if err := linuxrt.ReadJSON(filepath.Join(s.dir, "state.json"), &st); err != nil {
		return false, fmt.Errorf("runtime state: %w", err)
	}
	s.pid, s.start, s.lease = st.Pid, st.StartTime, internal
	if !s.alive() {
		return false, fmt.Errorf("sandbox init (pid %d) is gone", s.pid)
	}
	if !s.cg.Has(s.pid) {
		return false, fmt.Errorf("pid %d is not in the sandbox cgroup", s.pid)
	}
	if _, err := os.Stat(filepath.Join(s.diskDir(), "upper")); err != nil {
		return false, fmt.Errorf("writable disk is not mounted: %v", err)
	}
	if len(st.GPUs) > 0 {
		if b.opt.GPUs == nil {
			return false, fmt.Errorf("sandbox holds GPUs %v, the edge has none configured", st.GPUs)
		}
		if err := b.opt.GPUs.Restore(lease, st.GPUs, st.SharedGPU); err != nil {
			return false, err
		}
	}
	// A frozen aether cannot answer; thaw briefly to verify the channel.
	paused := s.cg.Frozen()
	if paused {
		if err := s.cg.Freeze(false); err != nil {
			return false, err
		}
	}
	go s.pollExit()
	watch, err := b.connect(ctx, s, filepath.Join(s.dir, "run", "aether.sock"), time.Now().Add(startTimeout))
	if err != nil {
		s.once.Do(func() { close(s.stopped) })
		return false, err
	}
	if paused {
		if err := s.cg.Freeze(true); err != nil {
			s.conn.Close()
			return false, err
		}
	}
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.mu.Unlock()
	go b.watch(s, watch)
	return paused, nil
}

// alive reports whether the sandbox init is still the process we started.
func (s *sandbox) alive() bool {
	st, err := linuxrt.ProcStartTime(s.pid)
	return err == nil && st == s.start
}

// pollExit closes exited when an adopted (non-child) init process dies.
func (s *sandbox) pollExit() {
	for {
		if !s.alive() {
			s.markExited()
			return
		}
		select {
		case <-s.exited:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type resolved struct {
	lower         []string // overlay lowerdirs, topmost first
	env           map[string]string
	workdir, user string
	base          string   // edge-local image, if any, under layers
	layers        []string // store layers, bottom first
}

// imageState is the resolved image of a sandbox, persisted in its dir.
type imageState struct {
	Base    string            `json:"base,omitempty"`
	Layers  []string          `json:"layers,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Workdir string            `json:"workdir,omitempty"`
	User    string            `json:"user,omitempty"`
}

// resolve maps an image name to overlay layers: "<project>/<repo>:<tag>"
// from the shared store (on-demand, spec §17.2), anything else from the
// edge's static image config.
func (b *Backend) resolve(image string) (*resolved, error) {
	if b.opt.Store != nil && images.IsStoreName(image) {
		m, err := b.opt.Store.GetManifest(image)
		if err != nil {
			return nil, err
		}
		if m.Snapshot != "" {
			if snap, err := b.opt.Store.GetSnapshot(m.Snapshot); err == nil && snap.VM != nil {
				return nil, rpcutil.Err(rpcutil.Invalid, "image %s is a microvm snapshot; use backend microvm", image)
			}
		}
		lower, err := b.opt.Store.Lowerdirs(m)
		if err != nil {
			return nil, err
		}
		return &resolved{lower: lower, env: m.Env, workdir: m.Workdir, user: m.User, layers: m.Layers}, nil
	}
	lower, ok := b.opt.Images[image]
	if !ok || len(lower) == 0 {
		return nil, rpcutil.Err(rpcutil.NotFound, "image %q is not available on edge %s", image, b.opt.EdgeID)
	}
	return &resolved{lower: lower, base: image}, nil
}

// resolveSnapshot maps a snapshot (spec §19) to overlay layers: its store
// layers, on top of its edge-local base image if it has one.
func (b *Backend) resolveSnapshot(id string) (*resolved, error) {
	if b.opt.Store == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s has no image store", b.opt.EdgeID)
	}
	snap, err := b.opt.Store.GetSnapshot(id)
	if err != nil {
		return nil, err
	}
	lower, err := b.opt.Store.SnapshotLowerdirs(snap)
	if err != nil {
		return nil, err
	}
	if snap.Base != "" {
		base, ok := b.opt.Images[snap.Base]
		if !ok || len(base) == 0 {
			return nil, rpcutil.Err(rpcutil.NotFound, "image %q (base of snapshot %s) is not available on edge %s", snap.Base, id, b.opt.EdgeID)
		}
		lower = append(lower, base...)
	}
	return &resolved{lower: lower, env: snap.Env, workdir: snap.Workdir, user: snap.User, base: snap.Base, layers: snap.Layers}, nil
}

// maxSnapshotLayers bounds the layers a sandbox can be snapshotted on:
// overlayfs takes all lowerdirs in one page of mount options.
const maxSnapshotLayers = 48

// mergeSnapshotLayers: every snapshot adds a layer over the ones it runs
// on; once more than this many snapshot layers top the stack, they are
// merged into one (spec §19.12), so fork chains do not deepen without end.
var mergeSnapshotLayers = 8

const snapshotSource = "snapshot "

func (b *Backend) MemorySnapshots() bool { return false }

// PauseReleasesMemory: with pause_reclaim, a pause swaps the memory out.
func (b *Backend) PauseReleasesMemory() bool { return b.opt.PauseReclaim }

// NetworkVM: container sandboxes use their namespace's veth directly.
func (b *Backend) NetworkVM() bool { return false }

// Snapshot freezes the sandbox and records its writable layer, on top of the
// layers it runs on, as snapshot id (spec §19). Container snapshots hold the
// filesystem only.
func (b *Backend) Snapshot(_ context.Context, sb *backend.Sandbox, id string, memory bool) (*images.Snapshot, error) {
	if memory {
		return nil, rpcutil.Err(rpcutil.Invalid, "container sandboxes have no memory snapshots (use backend microvm)")
	}
	if b.opt.Store == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s has no image store", b.opt.EdgeID)
	}
	s, err := b.get(sb.ID)
	if err != nil {
		return nil, err
	}
	var img imageState
	if err := linuxrt.ReadJSON(filepath.Join(s.dir, "image.json"), &img); err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s cannot be snapshotted (no resolved image: %v)", sb.ID, err)
	}
	if len(img.Layers) >= maxSnapshotLayers {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s already runs on %d layers (max %d); snapshot chains this deep need merging",
			sb.ID, len(img.Layers), maxSnapshotLayers)
	}
	frozen := false
	if !s.cg.Frozen() {
		if err := s.cg.Freeze(true); err != nil {
			return nil, err
		}
		frozen = true
	}
	layer, err := b.opt.Store.PublishLayerDir(images.NewDiffLayerID(), filepath.Join(s.diskDir(), "upper"), b.lowerOf(img), nil,
		images.LayerMeta{Source: snapshotSource + sb.ID})
	if frozen {
		s.cg.Freeze(false)
	}
	if err != nil {
		return nil, err
	}
	layers := append(append([]string{}, img.Layers...), layer.ID)
	// The snapshot layers on top (the image's own layers stay shared).
	top := len(layers) - 1
	for top > 0 {
		m, err := b.opt.Store.LayerMeta(layers[top-1])
		if err != nil || !strings.HasPrefix(m.Source, snapshotSource) {
			break
		}
		top--
	}
	if n := len(layers) - top; n > mergeSnapshotLayers {
		merged, err := b.opt.Store.MergeLayers(images.NewDiffLayerID(), layers[top:],
			images.LayerMeta{Source: fmt.Sprintf("%s%s (%d layers merged)", snapshotSource, sb.ID, n)})
		if err != nil {
			return nil, err
		}
		b.opt.Log.Info("merged snapshot layers", "sandbox", sb.ID, "layers", n, "layer", merged.ID)
		layers, layer = append(layers[:top:top], merged.ID), merged
	}
	snap := &images.Snapshot{ID: id, Base: img.Base, Layers: layers,
		Env: img.Env, Workdir: img.Workdir, User: img.User, Image: sb.Spec.GetImage(), Source: sb.ID, Size: layer.Size}
	if err := b.opt.Store.PutSnapshot(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// PackDiff snapshots a sandbox's writable layer into the shared store as
// layer id (spec §17.4). The sandbox is frozen while its upper dir is copied,
// so the snapshot is consistent; a sandbox that was already paused stays so.
func (b *Backend) PackDiff(_ context.Context, sb *backend.Sandbox, id string, scrub []string) (*images.LayerMeta, error) {
	if b.opt.Store == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s has no image store", b.opt.EdgeID)
	}
	s, err := b.get(sb.ID)
	if err != nil {
		return nil, err
	}
	var img imageState
	if err := linuxrt.ReadJSON(filepath.Join(s.dir, "image.json"), &img); err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s cannot be packed (no resolved image: %v)", sb.ID, err)
	}
	wasFrozen := s.cg.Frozen()
	if !wasFrozen {
		if err := s.cg.Freeze(true); err != nil {
			return nil, err
		}
		defer s.cg.Freeze(false)
	}
	return b.opt.Store.PublishLayerDir(id, filepath.Join(s.diskDir(), "upper"), b.lowerOf(img), scrub,
		images.LayerMeta{Source: "pack_diff " + sb.ID})
}

// lowerOf is the overlay lowerdirs (topmost first) a sandbox of img runs
// on: its store layers, then the local base image's.
func (b *Backend) lowerOf(img imageState) []string {
	var lower []string
	for i := len(img.Layers) - 1; i >= 0; i-- {
		lower = append(lower, b.layerRootfs(img.Layers[i]))
	}
	return append(lower, b.opt.Images[img.Base]...)
}

// layerRootfs is where layer id's files are read: the local copy if
// there is one, else the store.
func (b *Backend) layerRootfs(id string) string {
	if b.layers != nil {
		if p := b.layers.path(id); dirExists(p) {
			return p
		}
	}
	return b.opt.Store.LayerRootfs(id)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// watch consumes aether heartbeats; the stream ending outside Stop means the
// sandbox is gone (paper §3: channel closed -> sandbox failed).
func (b *Backend) watch(s *sandbox, w pb.Runtime_WatchClient) {
	for {
		if _, err := w.Recv(); err != nil {
			break
		}
	}
	select {
	case <-s.stopped:
		return
	default:
	}
	reason := "aether channel closed"
	select {
	case <-s.exited:
		reason = "sandbox init exited"
	case <-time.After(200 * time.Millisecond):
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	b.onLost(id, reason)
}

func tail(path string) string {
	b, _ := os.ReadFile(path)
	if len(b) > 2000 {
		b = b[len(b)-2000:]
	}
	return strings.TrimSpace(string(b))
}

// teardown releases everything a (possibly half-created) sandbox holds.
func (b *Backend) teardown(s *sandbox) {
	s.once.Do(func() { close(s.stopped) })
	if s.conn != nil {
		s.conn.Close()
	}
	if s.cg != nil {
		s.cg.Kill()
	}
	if s.proc != nil {
		select {
		case <-s.exited:
		case <-time.After(10 * time.Second):
			b.opt.Log.Warn("sandbox init did not exit after kill", "sandbox", s.id)
		}
	}
	if s.cg != nil {
		s.cg.Remove()
	}
	unmount(filepath.Join(s.dir, "disk"))
	os.RemoveAll(s.dir)
	s.mu.Lock()
	alias := s.alias
	s.mu.Unlock()
	if alias != "" {
		os.Remove(filepath.Join(b.sbRoot(), alias))
	}
	if b.opt.GPUs != nil && s.lease != "" {
		b.opt.GPUs.Release(s.lease)
	}
	if b.opt.Store != nil && s.lease != "" {
		b.opt.Store.ReleaseInUse(b.holder(s.lease))
	}
}

// holder names a sandbox's in-use marker in the store: by its internal
// lease (a warm member keeps its own).
func (b *Backend) holder(lease string) string { return b.opt.EdgeID + "." + b.opt.Name + "." + lease }

func (b *Backend) Stop(_ context.Context, sb *backend.Sandbox) error {
	b.mu.Lock()
	s := b.sbs[sb.ID]
	delete(b.sbs, sb.ID)
	b.mu.Unlock()
	if s == nil {
		return nil // never created or already torn down
	}
	b.teardown(s)
	return nil
}

// Pause freezes the sandbox; with PauseReclaim its memory then goes out to
// swap (paper §4.3: a paused sandbox should cost no memory).
func (b *Backend) Pause(_ context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	if err := s.cg.Freeze(true); err != nil {
		return err
	}
	if b.opt.PauseReclaim {
		t0 := time.Now()
		s.cg.SetSwap(true)
		s.reclaimed = s.cg.Reclaim()
		b.opt.Log.Debug("paused sandbox reclaimed", "sandbox", sb.ID, "bytes", s.reclaimed, "took", time.Since(t0))
	}
	return nil
}

// Resume thaws the sandbox; memory reclaimed at pause is read back in the
// background (MADV_WILLNEED), not page fault by page fault.
func (b *Backend) Resume(_ context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	if err := s.cg.Freeze(false); err != nil {
		return err
	}
	if b.opt.PauseReclaim && s.reclaimed > 0 {
		s.reclaimed = 0
		go func() {
			s.cg.Prefetch()
			if !s.cg.Frozen() {
				s.cg.SetSwap(false) // swap only while paused
			}
		}()
	}
	return nil
}

func (b *Backend) Probe(_ context.Context, sb *backend.Sandbox) bool {
	s, err := b.get(sb.ID)
	if err != nil {
		return false
	}
	select {
	case <-s.exited:
		return false
	default:
		return true
	}
}

func (b *Backend) Runtime(id string) (pb.RuntimeClient, error) {
	s, err := b.get(id)
	if err != nil {
		return nil, err
	}
	return s.rt, nil
}

// MemoryCurrent reports the sandbox cgroup's memory usage (bytes).
func (b *Backend) MemoryCurrent(id string) int64 {
	s, err := b.get(id)
	if err != nil {
		return 0
	}
	return s.cg.MemoryCurrent()
}

// goMaxProcs sizes the Go runtime of the sandbox init to the sandbox's CPU
// limit. The init starts before it can read its cgroup, and sized to a large
// host's CPU count its runtime alone can exceed a small sandbox's memory.
func goMaxProcs(cores float64) int {
	if cores <= 0 {
		return runtime.NumCPU()
	}
	return max(2, int(math.Ceil(cores)))
}
