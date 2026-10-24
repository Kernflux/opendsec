// Package fullvm is the QEMU full VM backend (spec §23). A sandbox is one
// QEMU process (q35 machine, KVM) booting the OpenDsec guest kernel with the
// microVM disk layout (agent disk, flattened image, writable disk, config
// disk) on virtio-pci; aether serves the Runtime API over vhost-vsock.
// Unlike microVMs it has a full PCI bus, so devices can be passed through
// with VFIO (GPUs), and with full_init the image's own /sbin/init
// (systemd) runs as PID 1. Pause stops the vCPUs (the memory stays);
// there are no memory snapshots or fork (spec §19.8).
package fullvm

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/aether"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/edge/backend/microvm"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const (
	startTimeout = 30 * time.Second
	minMemoryMB  = 128
	uidRange     = 65536
	cidBase      = 1 << 20 // vsock context ids: host-global, away from small ones
	cidRange     = 1 << 30
)

type Options struct {
	Store         *images.Store
	Name          string
	EdgeID        string
	StateDir      string
	AgentDir      string
	Images        map[string][]string
	DefaultDiskMB int64
	Kernel        string
	QEMU          string
	UIDBase       int
	OverheadMB    int64
	FullInit      bool
	CoreSched     bool          // a core scheduling cookie per VM (spec §29.1)
	PCI           *linuxrt.GPUs // passthrough devices (PCI addresses); nil = none
	DiskIO        linuxrt.IOLimit
	Log           *slog.Logger
}

func FromConfig(name string, ec config.Edge, bc config.Backend, store *images.Store, log *slog.Logger) Options {
	o := Options{Name: name, EdgeID: ec.ID, StateDir: ec.StateDir, AgentDir: ec.AgentDir, Images: ec.Images, Store: store,
		DefaultDiskMB: bc.DefaultDiskMB, Kernel: bc.Kernel, QEMU: bc.QEMU, UIDBase: bc.UIDBase, OverheadMB: bc.VMOverheadMB,
		FullInit: bc.FullInit, CoreSched: linuxrt.CoreSchedDefault(bc.CoreSched), Log: log,
		DiskIO: linuxrt.IOLimit{ReadMBps: bc.DiskIO.ReadMBps, WriteMBps: bc.DiskIO.WriteMBps, ReadIOPS: bc.DiskIO.ReadIOPS, WriteIOPS: bc.DiskIO.WriteIOPS}}
	if len(ec.GPU.PCI) > 0 {
		o.PCI = linuxrt.NewGPUs(ec.GPU.PCI, nil, nil, 1)
	}
	if o.AgentDir == "" {
		if self, err := os.Executable(); err == nil {
			o.AgentDir = filepath.Dir(self)
		}
	}
	if o.DefaultDiskMB == 0 {
		o.DefaultDiskMB = 10240
	}
	if o.QEMU == "" {
		o.QEMU = "qemu-system-x86_64"
	}
	if o.UIDBase == 0 {
		o.UIDBase = 1100000000 // apart from microvm's default range
	}
	if o.OverheadMB == 0 {
		o.OverheadMB = 160
	}
	return o
}

// Check reports whether this host can run full VMs, resolving QEMU on PATH.
func Check(o *Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("fullvm backend needs root")
	}
	if o.CoreSched {
		if err := linuxrt.CoreSchedSupported(); err != nil {
			return err
		}
	}
	for _, dev := range []string{"/dev/kvm", "/dev/vhost-vsock"} {
		f, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("no usable %s: %w", dev, err)
		}
		f.Close()
	}
	if o.Kernel == "" {
		return fmt.Errorf("no guest kernel configured (backend \"kernel\")")
	}
	if _, err := os.Stat(o.Kernel); err != nil {
		return fmt.Errorf("guest kernel: %w", err)
	}
	abs, err := exec.LookPath(o.QEMU)
	if err != nil {
		return err
	}
	o.QEMU = abs
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		return fmt.Errorf("mkfs.ext4 not found")
	}
	return nil
}

type Backend struct {
	opt    Options
	cgRel  string
	agents string
	imgs   *microvm.ImageCache
	kvmGID int

	mu     sync.Mutex
	sbs    map[string]*sandbox
	uids   map[int]bool
	cids   map[uint32]bool
	onLost func(id, reason string)
	netCG  *linuxrt.Cgroup // the sandboxes' network namespace holders

	done      chan struct{}
	closeOnce sync.Once
}

type sandbox struct {
	id, lease, dir string
	cg             *linuxrt.Cgroup
	st             state
	proc           *exec.Cmd // nil when adopted
	exited         chan struct{}
	exitOnce       sync.Once
	conn           *grpc.ClientConn
	rt             pb.RuntimeClient
	cancel         context.CancelFunc // the heartbeat stream
	stopped        chan struct{}
	once           sync.Once
}

// state is persisted in the sandbox dir, for Adopt.
type state struct {
	Pid       int                  `json:"pid"`
	StartTime uint64               `json:"start_time"`
	UID       int                  `json:"uid"`
	CID       uint32               `json:"cid"`
	Netns     string               `json:"netns,omitempty"`
	Holder    *linuxrt.NetnsHolder `json:"netns_holder,omitempty"`
	PCI       []int                `json:"pci,omitempty"`
}

func (s *sandbox) markExited() { s.exitOnce.Do(func() { close(s.exited) }) }

func New(opt Options) (*Backend, error) {
	if err := Check(&opt); err != nil {
		return nil, err
	}
	b := &Backend{opt: opt, cgRel: filepath.Join("opendsec", opt.EdgeID+"-"+opt.Name), sbs: map[string]*sandbox{},
		uids: map[int]bool{}, cids: map[uint32]bool{}, onLost: func(string, string) {}}
	g, err := user.LookupGroup("kvm")
	if err != nil {
		return nil, fmt.Errorf("group kvm (owner of /dev/kvm, /dev/vhost-vsock): %w", err)
	}
	b.kvmGID, _ = strconv.Atoi(g.Gid)
	for _, d := range []string{b.sbRoot(), b.cacheDir()} {
		if err := os.MkdirAll(d, 0o711); err != nil {
			return nil, err
		}
	}
	// QEMU runs as the VM's uid: it must traverse to the disks and its dir.
	for d := b.sbRoot(); ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && fi.Mode().Perm()&0o001 == 0 {
			os.Chmod(d, fi.Mode().Perm()|0o011)
		}
		if d == filepath.Clean(opt.StateDir) || d == "/" {
			break
		}
	}
	b.imgs = microvm.NewImageCache(b.cacheDir())
	if b.agents, err = microvm.BuildAgentDisk(b.cacheDir(), opt.AgentDir); err != nil {
		return nil, fmt.Errorf("agent disk: %w", err)
	}
	if err := linuxrt.EnsureParent(b.cgRel, !opt.DiskIO.Zero()); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	if b.netCG, err = linuxrt.NewCgroup(b.cgRel, "netns", linuxrt.Limits{}); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	b.done = make(chan struct{})
	go b.gcLoop(b.done)
	return b, nil
}

func (b *Backend) stopLoops() { b.closeOnce.Do(func() { close(b.done) }) }

func (b *Backend) Name() string { return b.opt.Name }
func (b *Backend) sbRoot() string {
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "sb")
}
func (b *Backend) cacheDir() string {
	return filepath.Join(b.opt.StateDir, b.opt.EdgeID, b.opt.Name, "cache")
}

func (b *Backend) Images() []string {
	if b.opt.Store != nil {
		return nil
	}
	out := make([]string, 0, len(b.opt.Images))
	for name := range b.opt.Images {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func (b *Backend) OnLost(f func(id, reason string)) { b.onLost = f }

// NetworkVM: the namespace holds the VM's tap (spec §20).
func (b *Backend) NetworkVM() bool { return true }

func (b *Backend) get(id string) (*sandbox, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.sbs[id]; s != nil {
		return s, nil
	}
	return nil, rpcutil.Err(rpcutil.NotFound, "fullvm %s", id)
}

// alloc picks a free uid and vsock context id for lease.
func (b *Backend) alloc(lease string) (int, uint32, error) {
	h := fnv.New32a()
	h.Write([]byte(b.opt.EdgeID + "/" + lease))
	sum := h.Sum32()
	b.mu.Lock()
	defer b.mu.Unlock()
	uid := -1
	for i := 0; i < uidRange; i++ {
		u := b.opt.UIDBase + int((sum+uint32(i))%uidRange)
		if !b.uids[u] {
			uid = u
			break
		}
	}
	var cid uint32
	for i := uint32(0); i < cidRange; i++ {
		if c := cidBase + (sum+i)%cidRange; !b.cids[c] {
			cid = c
			break
		}
	}
	if uid < 0 || cid == 0 {
		return 0, 0, rpcutil.Err(rpcutil.NoCapacity, "no free fullvm uid / cid")
	}
	b.uids[uid], b.cids[cid] = true, true
	return uid, cid, nil
}

func (b *Backend) free(s *sandbox) {
	b.mu.Lock()
	delete(b.uids, s.st.UID)
	delete(b.cids, s.st.CID)
	b.mu.Unlock()
	if b.opt.PCI != nil {
		b.opt.PCI.Release(s.lease)
	}
}

func (b *Backend) lower(spec *pb.SandboxSpec) ([]string, map[string]string, string, string, error) {
	if spec.Snapshot != "" {
		return nil, nil, "", "", rpcutil.Err(rpcutil.Invalid, "fullvm sandboxes have no snapshots (use microvm)")
	}
	if b.opt.Store != nil && images.IsStoreName(spec.Image) {
		m, err := b.opt.Store.GetManifest(spec.Image)
		if err != nil {
			return nil, nil, "", "", err
		}
		if m.Snapshot != "" {
			return nil, nil, "", "", rpcutil.Err(rpcutil.Invalid, "image %s is a snapshot: fullvm sandboxes cannot start from it", spec.Image)
		}
		lower, err := b.opt.Store.Lowerdirs(m)
		return lower, m.Env, m.Workdir, m.User, err
	}
	lower, ok := b.opt.Images[spec.Image]
	if !ok || len(lower) == 0 {
		return nil, nil, "", "", rpcutil.Err(rpcutil.NotFound, "image %q is not available on edge %s", spec.Image, b.opt.EdgeID)
	}
	if slices.Contains(lower, "/") {
		return nil, nil, "", "", rpcutil.Err(rpcutil.Invalid, "image %q is the host's root, which fullvm sandboxes cannot use", spec.Image)
	}
	return lower, nil, "", "", nil
}

func (b *Backend) Create(ctx context.Context, sb *backend.Sandbox) (err error) {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return err
	}
	spec := sb.Spec
	memMB := spec.Resources.GetMemoryMb()
	if memMB < minMemoryMB {
		return rpcutil.Err(rpcutil.Invalid, "fullvm sandboxes need resources.memory_mb >= %d", minMemoryMB)
	}
	lower, env, workdir, usr, err := b.lower(spec)
	if err != nil {
		return err
	}
	uid, cid, err := b.alloc(lease)
	if err != nil {
		return err
	}
	s := &sandbox{id: sb.ID, lease: lease, dir: filepath.Join(b.sbRoot(), lease), exited: make(chan struct{}),
		stopped: make(chan struct{}), st: state{UID: uid, CID: cid}}
	defer func() {
		if err != nil {
			b.teardown(s)
		}
	}()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if n := spec.Resources.GetGpus(); n > 0 {
		if b.opt.PCI == nil {
			return rpcutil.Err(rpcutil.NoCapacity, "edge %s has no PCI devices to pass through", b.opt.EdgeID)
		}
		if s.st.PCI, err = b.opt.PCI.Allocate(lease, int(n), false); err != nil {
			return err
		}
	}
	s.cg, err = linuxrt.NewCgroup(b.cgRel, lease, linuxrt.Limits{CPUCores: spec.Resources.GetCpuCores(),
		MemoryMB: memMB + b.opt.OverheadMB, BestEffort: spec.Qos == "BE"})
	if err != nil {
		return err
	}
	if !b.opt.DiskIO.Zero() {
		dev, err := linuxrt.DeviceOf(s.dir)
		if err == nil {
			err = s.cg.SetIO(dev, b.opt.DiskIO)
		}
		if err != nil {
			return err
		}
	}
	cached, err := b.imgs.Get(lower)
	if err != nil {
		return fmt.Errorf("image disk: %w", err)
	}
	// A link of its own: the cache's GC sees the disk in use.
	base := filepath.Join(s.dir, images.VMImageFile)
	if err := microvm.LinkOrCopy(cached, base); err != nil {
		return err
	}
	diskMB := spec.Resources.GetDiskMb()
	if diskMB <= 0 {
		diskMB = b.opt.DefaultDiskMB
	}
	disk := filepath.Join(s.dir, images.VMDiskFile)
	if err := microvm.MakeWritableDisk(disk, diskMB); err != nil {
		return fmt.Errorf("writable disk: %w", err)
	}
	if sb.Net != nil {
		h, err := linuxrt.StartNetnsHolder(b.netCG)
		if err != nil {
			return fmt.Errorf("network: %w", err)
		}
		s.st.Holder, s.st.Netns = h, h.Path()
		if err := sb.Net.Setup(h.Pid, uid); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	}
	aenv, _ := json.Marshal(env)
	cfg := aether.VMConfig{Hostname: "sb-" + lease[:12], FullInit: b.opt.FullInit,
		AetherArgs: []string{"--vsock-port", strconv.Itoa(aether.VMVsockPort), "--rundir", "/.opendsec/run",
			"--workdir", cmpOr(spec.Labels["workdir"], workdir, "/"), "--user", cmpOr(spec.InitUser, usr), "--env", string(aenv)},
		ReadonlyPaths: spec.ReadonlyPaths, MaskedPaths: spec.MaskedPaths}
	if s.st.Netns != "" {
		cfg.Address = fmt.Sprintf("%s/%d", netpol.VMGuestIP, netpol.VMPrefixLen)
		cfg.Gateway, cfg.Nameserver = netpol.VMGatewayIP, netpol.VMGatewayIP
	}
	cb, _ := json.Marshal(cfg)
	if err := microvm.MakeConfigDisk(filepath.Join(s.dir, "config.ext4"), cb); err != nil {
		return fmt.Errorf("config disk: %w", err)
	}
	for _, f := range []string{disk, filepath.Join(s.dir, "config.ext4")} {
		if err := os.Chown(f, uid, uid); err != nil {
			return err
		}
	}
	os.Chown(s.dir, uid, uid)
	vcpus := min(255, max(1, int(math.Ceil(spec.Resources.GetCpuCores()))))
	var watch pb.Runtime_WatchClient
	for attempt := 0; ; attempt++ {
		if err := b.startQEMU(s, base, memMB, vcpus); err != nil {
			return err
		}
		if err := linuxrt.WriteJSON(filepath.Join(s.dir, "state.json"), s.st); err != nil {
			return err
		}
		watch, err = b.connect(ctx, s, time.Now().Add(startTimeout))
		if err == nil {
			break
		}
		// The tap's queue can be held for a moment by a child the edge
		// forked while creating it (see microvm): start QEMU again.
		if !strings.Contains(err.Error(), "resource busy") || attempt >= 3 {
			return err
		}
		s.cg.Kill()
		<-s.exited
		s.exited, s.exitOnce = make(chan struct{}), sync.Once{}
	}
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.mu.Unlock()
	go b.watch(s, watch)
	return nil
}

func cmpOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

const bootArgs = "console=ttyS0 reboot=k panic=1 quiet loglevel=3 root=/dev/vda ro init=/" + aether.VMInitName

func (b *Backend) startQEMU(s *sandbox, image string, memMB int64, vcpus int) error {
	drive := func(id, file string, ro bool, opts ...string) []string {
		d := fmt.Sprintf("file=%s,if=none,id=%s,format=raw", file, id) + strings.Join(opts, "")
		if ro {
			d += ",readonly=on"
		}
		return []string{"-drive", d, "-device", "virtio-blk-pci,drive=" + id}
	}
	args := []string{"-name", "opendsec-" + s.lease, "-machine", "q35,accel=kvm", "-cpu", "host",
		"-smp", strconv.Itoa(vcpus), "-m", strconv.FormatInt(memMB, 10),
		"-nodefaults", "-no-user-config", "-nographic", "-display", "none",
		"-serial", "file:" + filepath.Join(s.dir, "console.log"),
		"-kernel", b.opt.Kernel, "-append", bootArgs,
		"-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", s.st.CID),
		"-qmp", "unix:" + filepath.Join(s.dir, "qmp.sock") + ",server=on,wait=off",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
	}
	args = append(args, drive("agents", b.agents, true)...)
	args = append(args, drive("image", image, true)...)
	args = append(args, drive("disk", filepath.Join(s.dir, images.VMDiskFile), false, throttle(b.opt.DiskIO))...)
	args = append(args, drive("config", filepath.Join(s.dir, "config.ext4"), true)...)
	if s.st.Netns != "" {
		args = append(args, "-netdev", "tap,id=n0,ifname="+netpol.VMTap+",script=no,downscript=no",
			"-device", "virtio-net-pci,netdev=n0,mac="+netpol.VMGuestMAC)
	}
	for _, i := range s.st.PCI {
		args = append(args, "-device", "vfio-pci,host="+b.opt.PCI.Devices[i])
	}
	cgfd, err := s.cg.Open()
	if err != nil {
		return err
	}
	defer cgfd.Close()
	logf, err := os.OpenFile(filepath.Join(s.dir, "qemu.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(b.opt.QEMU, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(s.st.UID), Gid: uint32(s.st.UID), Groups: []uint32{uint32(b.kvmGID)}},
		UseCgroupFD: true, CgroupFD: int(cgfd.Fd()), Setsid: true,
	}
	if s.st.Netns == "" {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET // no network: an empty namespace
	}
	if err := startIn(s.st.Netns, cmd); err != nil {
		return fmt.Errorf("start qemu: %w", err)
	}
	if b.opt.CoreSched { // QEMU's vCPU threads, started later, inherit it (spec §29.1)
		if err := linuxrt.CoreSchedNew(cmd.Process.Pid); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return err
		}
	}
	s.proc, s.st.Pid = cmd, cmd.Process.Pid
	go func() { linuxrt.WaitCmd(cmd); s.markExited() }()
	s.st.StartTime, _ = linuxrt.ProcStartTime(s.st.Pid)
	return nil
}

// startIn starts cmd inside the network namespace at path (a fork from a
// thread moved into it inherits it); "" starts it here.
func startIn(path string, cmd *exec.Cmd) error {
	if path == "" {
		return cmd.Start()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		f, err := os.Open(path)
		if err != nil {
			errc <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		errc <- cmd.Start()
	}()
	return <-errc
}

func (b *Backend) consoleTail(s *sandbox) string {
	var parts []string
	for _, f := range []string{"qemu.log", "console.log"} {
		data, _ := os.ReadFile(filepath.Join(s.dir, f))
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		parts = append(parts, strings.Join(lines, " | "))
	}
	return strings.Join(parts, " || ")
}

// connect dials aether over vsock until its first heartbeat.
func (b *Backend) connect(ctx context.Context, s *sandbox, deadline time.Time) (pb.Runtime_WatchClient, error) {
	for {
		c, err := dialVsock(s.st.CID, aether.VMVsockPort)
		if err == nil {
			c.Close()
			break
		}
		select {
		case <-s.exited:
			return nil, fmt.Errorf("qemu exited: %s", b.consoleTail(s))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("aether did not listen within %v: %v: %s", startTimeout, err, b.consoleTail(s))
		}
	}
	conn, err := grpcVsock(s.st.CID)
	if err != nil {
		return nil, err
	}
	rt := pb.NewRuntimeClient(conn)
	for {
		sctx, cancel := context.WithCancel(context.Background())
		w, err := rt.Watch(sctx, &pb.Empty{})
		if err == nil {
			if _, err = w.Recv(); err == nil {
				s.conn, s.rt, s.cancel = conn, rt, cancel
				return w, nil
			}
		}
		cancel()
		if time.Now().After(deadline) {
			conn.Close()
			return nil, fmt.Errorf("aether did not answer: %v: %s", err, b.consoleTail(s))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (b *Backend) watch(s *sandbox, w pb.Runtime_WatchClient) {
	for {
		if _, err := w.Recv(); err != nil {
			break
		}
	}
	reason := "aether channel closed"
	select {
	case <-s.exited:
		reason = "qemu exited"
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-s.stopped:
		return
	default:
	}
	b.onLost(s.id, reason)
}

func (b *Backend) teardown(s *sandbox) {
	s.once.Do(func() { close(s.stopped) })
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	if s.cg != nil {
		s.cg.Kill()
		if s.proc != nil {
			select {
			case <-s.exited:
			case <-time.After(10 * time.Second):
			}
		}
		s.cg.Remove()
	}
	s.st.Holder.Stop()
	os.RemoveAll(s.dir)
	b.free(s)
}

func (b *Backend) Stop(_ context.Context, sb *backend.Sandbox) error {
	b.mu.Lock()
	s := b.sbs[sb.ID]
	delete(b.sbs, sb.ID)
	b.mu.Unlock()
	if s != nil {
		b.teardown(s)
	}
	return nil
}

// Pause stops the vCPUs (QMP "stop"); the guest's memory stays.
func (b *Backend) Pause(ctx context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	return qmp(ctx, filepath.Join(s.dir, "qmp.sock"), "stop")
}

func (b *Backend) Resume(ctx context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	return qmp(ctx, filepath.Join(s.dir, "qmp.sock"), "cont")
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

func (b *Backend) MemoryCurrent(id string) int64 {
	s, err := b.get(id)
	if err != nil {
		return 0
	}
	return s.cg.MemoryCurrent()
}

// Adopt reattaches to a VM of a previous edge process.
func (b *Backend) Adopt(ctx context.Context, sb *backend.Sandbox) (bool, error) {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return false, err
	}
	s := &sandbox{id: sb.ID, lease: lease, dir: filepath.Join(b.sbRoot(), lease), exited: make(chan struct{}),
		stopped: make(chan struct{}), cg: &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, lease)}}
	if err := linuxrt.ReadJSON(filepath.Join(s.dir, "state.json"), &s.st); err != nil {
		return false, fmt.Errorf("runtime state: %w", err)
	}
	if st, err := linuxrt.ProcStartTime(s.st.Pid); err != nil || st != s.st.StartTime || !s.cg.Has(s.st.Pid) {
		return false, fmt.Errorf("qemu (pid %d) is gone", s.st.Pid)
	}
	if h := s.st.Holder; h != nil && !h.Alive() {
		return false, fmt.Errorf("the holder of its network namespace (pid %d) is gone", h.Pid)
	}
	go func() {
		for {
			if st, err := linuxrt.ProcStartTime(s.st.Pid); err != nil || st != s.st.StartTime {
				s.markExited()
				return
			}
			select {
			case <-s.stopped:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	status, err := qmpStatus(ctx, filepath.Join(s.dir, "qmp.sock"))
	if err != nil {
		return false, err
	}
	paused := status == "paused"
	if paused {
		qmp(ctx, filepath.Join(s.dir, "qmp.sock"), "cont") // vCPUs must run for aether to answer
	}
	watch, err := b.connect(ctx, s, time.Now().Add(15*time.Second))
	if paused {
		qmp(ctx, filepath.Join(s.dir, "qmp.sock"), "stop")
	}
	if err != nil {
		return false, err
	}
	if b.opt.PCI != nil && len(s.st.PCI) > 0 {
		if err := b.opt.PCI.Restore(lease, s.st.PCI, false); err != nil {
			return false, err
		}
	}
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.uids[s.st.UID], b.cids[s.st.CID] = true, true
	b.mu.Unlock()
	go b.watch(s, watch)
	return paused, nil
}

// CleanupExcept removes VMs, dirs and cgroups whose lease is not kept.
func (b *Backend) CleanupExcept(keep map[string]bool) {
	leases := map[string]bool{}
	for _, dir := range []string{b.sbRoot(), filepath.Join(linuxrt.CgroupRoot, b.cgRel)} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() && !keep[e.Name()] && ids.ValidLease(e.Name()) {
				leases[e.Name()] = true
			}
		}
	}
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
		time.Sleep(50 * time.Millisecond)
		cg.Remove()
		os.RemoveAll(filepath.Join(b.sbRoot(), lease))
		b.opt.Log.Info("removed leftover full vm", "lease", lease)
	}
}

// gcLoop removes image disks unused for a day.
func (b *Backend) gcLoop(done chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		b.imgs.GC(24 * time.Hour)
		select {
		case <-t.C:
		case <-done:
			return
		}
	}
}

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

func (b *Backend) Detach() {
	b.stopLoops()
	b.mu.Lock()
	ss := b.sbs
	b.sbs = map[string]*sandbox{}
	b.mu.Unlock()
	for _, s := range ss {
		s.once.Do(func() { close(s.stopped) })
		if s.cancel != nil {
			s.cancel()
		}
		if s.conn != nil {
			s.conn.Close()
		}
	}
}

// throttle is QEMU's per-drive I/O throttling for l (on top of io.max: the
// guest's writes may sit in the host's page cache).
func throttle(l linuxrt.IOLimit) string {
	var out string
	for _, x := range []struct {
		key string
		v   int64
	}{{"bps-read", l.ReadMBps << 20}, {"bps-write", l.WriteMBps << 20}, {"iops-read", l.ReadIOPS}, {"iops-write", l.WriteIOPS}} {
		if x.v > 0 {
			out += fmt.Sprintf(",throttling.%s=%d", x.key, x.v)
		}
	}
	return out
}
