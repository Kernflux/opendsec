package microvm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/aether"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// source is what a new sandbox starts from: layers to boot, or a VM
// snapshot to restore.
type source struct {
	img     imageState
	lower   []string // cold boot: overlay lowerdirs, topmost first
	snap    *images.Snapshot
	snapDir string
	peer    backend.SnapshotPeer // holds snap's files if not in the store
}

func (b *Backend) resolve(spec *pb.SandboxSpec) (*source, error) {
	snapID := spec.Snapshot
	if snapID == "" && b.opt.Store != nil && images.IsStoreName(spec.Image) {
		m, err := b.opt.Store.GetManifest(spec.Image)
		if err != nil {
			return nil, err
		}
		if m.Snapshot == "" {
			lower, err := b.opt.Store.Lowerdirs(m)
			if err != nil {
				return nil, err
			}
			return &source{img: imageState{Name: m.Name, Layers: m.Layers, Env: m.Env, Workdir: m.Workdir, User: m.User}, lower: lower}, nil
		}
		snapID = m.Snapshot
	}
	if snapID != "" {
		if b.opt.Store == nil {
			return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s has no image store", b.opt.EdgeID)
		}
		snap, err := b.opt.Store.GetSnapshot(snapID)
		if err != nil {
			return nil, err
		}
		img := imageState{Name: cmpOr(snap.Image, spec.Image), Base: snap.Base, Layers: snap.Layers, Env: snap.Env,
			Workdir: snap.Workdir, User: snap.User}
		if snap.VM != nil {
			if !snap.Memory {
				return nil, rpcutil.Err(rpcutil.Invalid, "snapshot %s has no memory", snapID)
			}
			dir, err := b.opt.Store.SnapshotDir(snapID)
			if err != nil {
				return nil, err
			}
			return &source{img: img, snap: snap, snapDir: dir}, nil
		}
		// A filesystem snapshot (of a container): boot on its layers.
		lower, err := b.opt.Store.SnapshotLowerdirs(snap)
		if err != nil {
			return nil, err
		}
		if snap.Base != "" {
			base, err := b.localImage(snap.Base)
			if err != nil {
				return nil, err
			}
			lower = append(lower, base...)
		}
		return &source{img: img, lower: lower}, nil
	}
	lower, err := b.localImage(spec.Image)
	if err != nil {
		return nil, err
	}
	return &source{img: imageState{Name: spec.Image, Base: spec.Image}, lower: lower}, nil
}

func (b *Backend) localImage(name string) ([]string, error) {
	lower, ok := b.opt.Images[name]
	if !ok || len(lower) == 0 {
		return nil, rpcutil.Err(rpcutil.NotFound, "image %q is not available on edge %s", name, b.opt.EdgeID)
	}
	// Images are flattened into a disk: never the whole host (the dev "host" image).
	if slices.Contains(lower, "/") {
		return nil, rpcutil.Err(rpcutil.Invalid, "image %q is the host's root, which microvm sandboxes cannot use; use a store image", name)
	}
	return lower, nil
}

// vmConfig is Firecracker's --config-file, with paths inside the jail.
type vmConfig struct {
	BootSource struct {
		KernelImagePath string `json:"kernel_image_path"`
		BootArgs        string `json:"boot_args"`
	} `json:"boot-source"`
	Drives  []drive `json:"drives"`
	Machine struct {
		VCPUs  int   `json:"vcpu_count"`
		MemMiB int64 `json:"mem_size_mib"`
		SMT    bool  `json:"smt"`
		Track  bool  `json:"track_dirty_pages"` // for diff pause snapshots
	} `json:"machine-config"`
	Vsock struct {
		CID     int    `json:"guest_cid"`
		UDSPath string `json:"uds_path"`
	} `json:"vsock"`
	Pmem    []pmemDev `json:"pmem,omitempty"`
	Balloon *balloon  `json:"balloon,omitempty"`
	NICs    []nic     `json:"network-interfaces,omitempty"`
}

type nic struct {
	ID      string `json:"iface_id"`
	MAC     string `json:"guest_mac"`
	HostDev string `json:"host_dev_name"`
}

type pmemDev struct {
	ID       string `json:"id"`
	Path     string `json:"path_on_host"`
	ReadOnly bool   `json:"read_only"`
}

type balloon struct {
	AmountMiB         int  `json:"amount_mib"`
	DeflateOnOOM      bool `json:"deflate_on_oom"`
	FreePageReporting bool `json:"free_page_reporting"`
}

// reportOrder is the smallest free block the guest reports to the host
// (log2 pages): the kernel's default, 2 MB, misses most of what DAMON frees.
const reportOrder = 6

type drive struct {
	ID       string       `json:"drive_id"`
	Path     string       `json:"path_on_host"`
	Root     bool         `json:"is_root_device"`
	ReadOnly bool         `json:"is_read_only"`
	Limit    *rateLimiter `json:"rate_limiter,omitempty"`
}

// rateLimiter is Firecracker's token buckets for a device: one for bytes,
// one for operations, reads and writes together.
type rateLimiter struct {
	Bandwidth *bucket `json:"bandwidth,omitempty"`
	Ops       *bucket `json:"ops,omitempty"`
}

type bucket struct {
	Size       int64 `json:"size"`
	RefillTime int64 `json:"refill_time"` // ms
}

// diskLimiter maps the backend's DiskIO onto the writable disk's limiter:
// Firecracker's buckets count reads and writes together, so the lower of
// the two rates applies to both. The guest's flushes are not passed to the
// host (cache "Unsafe"), so io.max would not hold the VM back.
func (b *Backend) diskLimiter() *rateLimiter {
	l := b.opt.DiskIO
	low := func(x, y int64) int64 {
		if x <= 0 || y > 0 && y < x {
			return y
		}
		return x
	}
	var rl rateLimiter
	if bw := low(l.ReadMBps, l.WriteMBps); bw > 0 {
		rl.Bandwidth = &bucket{Size: bw << 20, RefillTime: 1000}
	}
	if ops := low(l.ReadIOPS, l.WriteIOPS); ops > 0 {
		rl.Ops = &bucket{Size: ops, RefillTime: 1000}
	}
	if rl.Bandwidth == nil && rl.Ops == nil {
		return nil
	}
	return &rl
}

// The i8042 options skip a ~0.5 s keyboard controller probe at boot.
const bootArgs = "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd quiet loglevel=3 init=/" + aether.VMInitName

func (b *Backend) Create(ctx context.Context, sb *backend.Sandbox) (err error) {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return err
	}
	t0, w := time.Now(), newStopwatch()
	spec := sb.Spec
	memMB := spec.Resources.GetMemoryMb()
	if memMB < minMemoryMB {
		return rpcutil.Err(rpcutil.Invalid, "microvm sandboxes need resources.memory_mb >= %d", minMemoryMB)
	}
	src, err := b.resolve(spec)
	if err != nil {
		return err
	}
	src.peer = sb.Peer
	if src.snap != nil && src.snap.VM.MemMB != memMB {
		return rpcutil.Err(rpcutil.Invalid, "snapshot %s holds a %d MB VM: request resources.memory_mb = %d",
			src.snap.ID, src.snap.VM.MemMB, src.snap.VM.MemMB)
	}
	uid, err := b.allocUID(lease)
	if err != nil {
		return err
	}
	s := &sandbox{id: sb.ID, lease: lease, dir: filepath.Join(b.sbRoot(), lease), uid: uid,
		root: filepath.Join(b.jailDir(lease), "root"), stopped: make(chan struct{}),
		st: runtimeState{UID: uid, MemMB: memMB, Hostname: "sb-" + lease[:12], Image: src.img}}
	defer func() {
		if err != nil {
			b.teardown(s)
		}
	}()
	for _, d := range []string{s.dir, s.root} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	s.cg, err = linuxrt.NewCgroup(b.cgRel, lease, linuxrt.Limits{
		CPUCores: spec.Resources.GetCpuCores(), MemoryMB: memMB + b.opt.OverheadMB, BestEffort: spec.Qos == "BE",
	})
	if err != nil {
		return err
	}
	if !b.opt.DiskIO.Zero() {
		dev, err := linuxrt.DeviceOf(s.root)
		if err == nil {
			err = s.cg.SetIO(dev, b.opt.DiskIO)
		}
		if err != nil {
			return err
		}
	}
	tNet := time.Now()
	w.markAt("prepare", tNet)
	if sb.Net != nil {
		h, err := linuxrt.StartNetnsHolder(b.netCG)
		if err != nil {
			return fmt.Errorf("network: %w", err)
		}
		s.st.Holder, s.st.Netns = h, h.Path()
		if err := sb.Net.Setup(h.Pid, s.uid); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	}
	tCfg := time.Now()
	w.markAt("network", tCfg)
	if err := MakeConfigDisk(filepath.Join(s.root, "config.ext4"), b.guestConfig(s, spec)); err != nil {
		return fmt.Errorf("config disk: %w", err)
	}
	tStart := time.Now()
	w.markAt("config", tStart)
	how := "booted"
	if src.snap != nil {
		how = "restored"
		err = b.createRestored(ctx, s, src, w)
	} else {
		err = b.createCold(ctx, s, spec, src)
	}
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.mu.Unlock()
	b.opt.Log.Debug("microvm "+how, "id", sb.ID, "took", time.Since(t0), "prepare", tNet.Sub(t0),
		"network", tCfg.Sub(tNet), "config", tStart.Sub(tCfg), "start", time.Since(tStart))
	for phase, d := range map[string]time.Duration{"prepare": tNet.Sub(t0), "network": tCfg.Sub(tNet),
		"config": tStart.Sub(tCfg), how: time.Since(tStart)} {
		metrics.CreatePhase(b.opt.Name, phase, d)
	}
	return nil
}

func (b *Backend) guestConfig(s *sandbox, spec *pb.SandboxSpec) []byte {
	img := s.st.Image
	aenv, _ := json.Marshal(img.Env)
	cfg := aether.VMConfig{Hostname: s.st.Hostname, AetherArgs: []string{
		"--vsock-port", strconv.Itoa(aether.VMVsockPort), "--rundir", "/.opendsec/run",
		"--workdir", cmpOr(spec.Labels["workdir"], img.Workdir, "/"), "--user", cmpOr(spec.InitUser, img.User),
		"--env", string(aenv)}, ReadonlyPaths: spec.ReadonlyPaths, MaskedPaths: spec.MaskedPaths}
	if b.opt.ColdAgeS > 0 {
		pct := b.opt.ZramPct
		if pct == 0 {
			pct = 100
		}
		cfg.ColdAgeS, cfg.ZramMB = b.opt.ColdAgeS, s.st.MemMB*int64(pct)/100
	}
	if b.opt.FreePageReporting {
		cfg.ReportOrder = reportOrder
	}
	if s.st.Netns != "" {
		// The same address in every VM (spec §20): snapshot copies need no
		// change.
		cfg.Address = fmt.Sprintf("%s/%d", netpol.VMGuestIP, netpol.VMPrefixLen)
		cfg.Gateway, cfg.Nameserver = netpol.VMGatewayIP, netpol.VMGatewayIP
	}
	out, _ := json.Marshal(cfg)
	return out
}

func (b *Backend) createCold(ctx context.Context, s *sandbox, spec *pb.SandboxSpec, src *source) error {
	t0 := time.Now()
	base, err := b.imgs.get(src.lower)
	if err != nil {
		return fmt.Errorf("image disk: %w", err)
	}
	for from, name := range map[string]string{b.kernel: "vmlinux", b.agents: images.VMAgentsFile, base: images.VMImageFile} {
		if err := LinkOrCopy(from, filepath.Join(s.root, name)); err != nil {
			return err
		}
	}
	s.st.DiskMB = spec.Resources.GetDiskMb()
	if s.st.DiskMB <= 0 {
		s.st.DiskMB = b.opt.DefaultDiskMB
	}
	disk := filepath.Join(s.root, images.VMDiskFile)
	if err := MakeWritableDisk(disk, s.st.DiskMB); err != nil {
		return fmt.Errorf("writable disk: %w", err)
	}
	if err := os.Chown(disk, s.uid, s.uid); err != nil {
		return err
	}
	var vc vmConfig
	vc.BootSource.KernelImagePath, vc.BootSource.BootArgs = "/vmlinux", bootArgs
	if s.st.Netns != "" {
		vc.NICs = []nic{{ID: "eth0", MAC: netpol.VMGuestMAC, HostDev: netpol.VMTap}}
	}
	vc.Drives = []drive{
		{ID: "agents", Path: "/" + images.VMAgentsFile, Root: true, ReadOnly: true},
		{ID: "image", Path: "/" + images.VMImageFile, ReadOnly: true},
		{ID: "disk", Path: "/" + images.VMDiskFile, Limit: b.diskLimiter()},
		{ID: "config", Path: "/config.ext4", ReadOnly: true},
	}
	if b.opt.ImagePmem {
		// The guest finds the image as /dev/pmem0, the next drives as
		// vdb, vdc (aether.VMImagePmem).
		vc.Drives = slices.Delete(vc.Drives, 1, 2)
		vc.Pmem = []pmemDev{{ID: "image", Path: "/" + images.VMImageFile, ReadOnly: true}}
	}
	if b.opt.FreePageReporting {
		vc.Balloon = &balloon{DeflateOnOOM: true, FreePageReporting: true}
	}
	s.st.VCPUs = min(maxVCPUs, max(1, int(math.Ceil(spec.Resources.GetCpuCores()))))
	vc.Machine.VCPUs, vc.Machine.MemMiB = s.st.VCPUs, s.st.MemMB
	vc.Machine.Track = !b.opt.NoDirtyTracking && !b.opt.UntrackedBoot
	s.st.Untracked = b.opt.UntrackedBoot
	vc.Vsock.CID, vc.Vsock.UDSPath = 3, "/v.sock"
	if err := linuxrt.WriteJSON(filepath.Join(s.root, "vm.json"), vc); err != nil {
		return err
	}
	os.Chmod(filepath.Join(s.root, "vm.json"), 0o644) // read by the jailed uid
	tVMM := time.Now()
	var tJail time.Time
	for attempt := 0; ; attempt++ {
		v, err := b.startVM(s, true)
		if err != nil {
			return err
		}
		tJail = time.Now()
		s.st.Base = zeroBase
		if s.st.Untracked {
			s.st.Base = ""
		}
		s.setVM(v)
		if err := s.persist(); err != nil {
			return fmt.Errorf("persist runtime state: %w", err)
		}
		s.setVM(nil)
		watch, err := b.connect(ctx, s, v, time.Now().Add(startTimeout))
		if err != nil {
			b.endVM(s, v)
			if tapBusy(err) && attempt < tapRetries {
				time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
				continue
			}
			return err
		}
		b.attach(s, v, watch)
		b.opt.Log.Debug("microvm cold boot", "id", s.id, "disks", tVMM.Sub(t0), "jailer", tJail.Sub(tVMM), "boot", time.Since(tJail), "attempts", attempt+1)
		metrics.CreatePhase(b.opt.Name, "disks", tVMM.Sub(t0))
		metrics.CreatePhase(b.opt.Name, "vmm_boot", time.Since(tJail))
		return nil
	}
}

// tapRetries: a VM whose tap was busy is started again. The edge opens the
// tap queue to create it, and a child it forks meanwhile holds a copy until
// it execs: under a burst of starts the VMM's own open can meet it (EBUSY).
const tapRetries = 3

func tapBusy(err error) bool {
	m := err.Error()
	return strings.Contains(m, "Open tap device failed") && strings.Contains(m, "Resource busy")
}

// createRestored starts s from a memory snapshot: the read-only disks it
// had are linked in (the guest has them mounted: they must be the same
// files), the writable disk is copied, the memory is mapped privately from
// the snapshot (copies on a node share its page cache until they write).
// w times its steps (spec §19.15).
func (b *Backend) createRestored(ctx context.Context, s *sandbox, src *source, w *stopwatch) error {
	snap := src.snap
	s.st.VCPUs, s.st.DiskMB = snap.VM.VCPUs, snap.VM.DiskMB
	dir, err := b.snaps.dirFor(ctx, snap.ID, src.snapDir, src.peer)
	if err != nil {
		return err
	}
	src.snapDir = dir
	for _, f := range []string{images.VMAgentsFile, images.VMImageFile} {
		if err := LinkOrCopy(filepath.Join(src.snapDir, f), filepath.Join(s.root, f)); err != nil {
			return err
		}
	}
	disk := filepath.Join(s.root, images.VMDiskFile)
	if err := copySparse(filepath.Join(src.snapDir, images.VMDiskFile), disk); err != nil {
		return err
	}
	if err := os.Chown(disk, s.uid, s.uid); err != nil {
		return err
	}
	for f, name := range map[string]string{images.VMStateFile: "restore.vmstate", images.VMMemFile: baseMem} {
		if err := LinkOrCopy(filepath.Join(src.snapDir, f), filepath.Join(s.root, name)); err != nil {
			return err
		}
	}
	w.mark("files")
	v, watch, err := b.restore(ctx, s, "/restore.vmstate", baseMem, newIdentity(s.st.Hostname), w)
	os.Remove(filepath.Join(s.root, "restore.vmstate"))
	if err != nil {
		return err
	}
	// The snapshot's memory, shared with its other copies: the base of
	// this one's pauses.
	s.st.Base, s.st.BaseOwned = baseMem, false
	b.attach(s, v, watch)
	if err := s.persist(); err != nil {
		return err
	}
	w.mark("attach")
	s.lastRestore = w.ps
	args := []any{"id", s.id}
	for _, p := range w.ps {
		args = append(args, p.Name, p.D)
		metrics.CreatePhase(b.opt.Name, "restore_"+p.Name, p.D)
	}
	b.opt.Log.Debug("microvm restore steps", args...)
	return nil
}

func (b *Backend) teardown(s *sandbox) {
	s.once.Do(func() { close(s.stopped) })
	s.stopDig()
	if v := s.vm(); v != nil {
		b.endVM(s, v)
	}
	if s.cg != nil {
		s.cg.Kill()
		s.cg.Remove()
	}
	s.st.Holder.Stop()
	os.RemoveAll(b.jailDir(s.lease))
	os.RemoveAll(s.dir)
	if s.uid != 0 {
		b.freeUID(s.uid)
	}
}

func (b *Backend) Stop(_ context.Context, sb *backend.Sandbox) error {
	b.mu.Lock()
	s := b.sbs[sb.ID]
	delete(b.sbs, sb.ID)
	b.mu.Unlock()
	if s == nil {
		return nil
	}
	b.teardown(s)
	return nil
}

// Pause snapshots the VM and ends its process, freeing its memory (paper
// §11, as E2B). Calls in flight fail; processes in the guest just stop.
// With a Base, only the pages dirtied since are written, and merged into it
// (spec §19.12).
func (b *Backend) Pause(ctx context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	v := s.vm()
	if v == nil {
		return nil
	}
	ctx = context.WithoutCancel(ctx) // a half-taken snapshot helps no one
	t0 := time.Now()
	s.stopDig() // the merge below writes the file it may be punching
	if err := v.api.setState(ctx, "Paused"); err != nil {
		return err
	}
	diff := s.st.Base != ""
	typ, mem := "Full", pauseMem
	if diff {
		typ, mem = "Diff", pauseDiff
	}
	os.Remove(filepath.Join(s.root, pauseState))
	os.Remove(filepath.Join(s.root, mem))
	if err := v.api.call(ctx, "PUT", "/snapshot/create", map[string]string{"snapshot_type": typ,
		"snapshot_path": pauseState, "mem_file_path": mem}, nil); err != nil {
		v.api.setState(ctx, "Resumed")
		return fmt.Errorf("pause snapshot: %w", err)
	}
	var merged int64
	if diff {
		// Merged while the VM still exists, so a failure can resume it: it
		// maps Base privately, and the pages merged are the ones it wrote,
		// so its own copies.
		if merged, err = s.mergePause(); err != nil {
			os.Remove(filepath.Join(s.root, pauseDiff))
			s.st.Base, s.st.BaseOwned = "", false // the log was reset: no base now
			s.persist()
			v.api.setState(ctx, "Resumed")
			return fmt.Errorf("pause snapshot: %w", err)
		}
	}
	s.st.Base, s.st.BaseOwned = pauseMem, true
	s.lastPause = pauseStats{Type: typ, Merged: merged}
	s.setVM(nil)
	b.endVM(s, v)
	dropCache(filepath.Join(s.root, pauseMem))
	s.digHoles(filepath.Join(s.root, pauseMem))
	if err := s.persist(); err != nil {
		return err
	}
	b.opt.Log.Debug("microvm paused to snapshot", "id", sb.ID, "type", typ, "merged_bytes", merged, "took", time.Since(t0))
	return nil
}

// Resume restores the VM from its pause snapshot, on this node.
func (b *Backend) Resume(ctx context.Context, sb *backend.Sandbox) error {
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	if s.vm() != nil {
		return nil
	}
	t0 := time.Now()
	v, watch, err := b.restore(context.WithoutCancel(ctx), s, pauseState, pauseMem, &pb.PostRestoreRequest{}, newStopwatch())
	if err != nil {
		return err
	}
	// pauseMem stays: the VM maps it, and it is the base of the next pause.
	os.Remove(filepath.Join(s.root, pauseState))
	b.attach(s, v, watch)
	if err := s.persist(); err != nil {
		return err
	}
	b.opt.Log.Debug("microvm resumed from snapshot", "id", sb.ID, "took", time.Since(t0))
	return nil
}

func (s *sandbox) hasPauseSnapshot() bool {
	for _, p := range []string{pauseState, pauseMem} {
		if _, err := os.Stat(filepath.Join(s.root, p)); err != nil {
			return false
		}
	}
	return true
}

func (b *Backend) Probe(_ context.Context, sb *backend.Sandbox) bool {
	s, err := b.get(sb.ID)
	if err != nil {
		return false
	}
	v := s.vm()
	if v == nil {
		return s.hasPauseSnapshot()
	}
	select {
	case <-v.exited:
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
	v := s.vm()
	if v == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "microvm %s is paused", id)
	}
	l := v.link()
	if l == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "microvm %s is reconnecting", id)
	}
	return l.rt, nil
}

// MemoryCurrent reports the VM cgroup's memory usage (bytes).
func (b *Backend) MemoryCurrent(id string) int64 {
	s, err := b.get(id)
	if err != nil {
		return 0
	}
	return s.cg.MemoryCurrent()
}

// Adopt reattaches to a sandbox of a previous edge process: a paused one
// is its pause snapshot; a running VM must still be the process recorded,
// in the sandbox cgroup, and aether must answer.
func (b *Backend) Adopt(ctx context.Context, sb *backend.Sandbox) (bool, error) {
	_, lease, err := ids.Parse(sb.ID)
	if err != nil {
		return false, err
	}
	s := &sandbox{id: sb.ID, lease: lease, dir: filepath.Join(b.sbRoot(), lease), root: filepath.Join(b.jailDir(lease), "root"),
		stopped: make(chan struct{}), cg: &linuxrt.Cgroup{Path: filepath.Join(linuxrt.CgroupRoot, b.cgRel, lease)}}
	if err := linuxrt.ReadJSON(filepath.Join(s.dir, "state.json"), &s.st); err != nil {
		return false, fmt.Errorf("runtime state: %w", err)
	}
	s.uid = s.st.UID
	if h := s.st.Holder; h != nil && !h.Alive() {
		return false, fmt.Errorf("the holder of its network namespace (pid %d) is gone", h.Pid)
	}
	register := func() {
		b.mu.Lock()
		b.sbs[sb.ID] = s
		b.uids[s.uid] = true
		b.mu.Unlock()
	}
	if s.st.Suspended {
		if !s.hasPauseSnapshot() {
			return false, fmt.Errorf("pause snapshot of %s is missing", sb.ID)
		}
		register()
		return true, nil
	}
	v := &vm{pid: s.st.Pid, start: s.st.StartTime, exited: make(chan struct{}), retired: make(chan struct{}),
		api: newFCAPI(filepath.Join(s.root, "run", "fc.sock"))}
	if !v.alive() {
		return false, fmt.Errorf("microvm (pid %d) is gone", v.pid)
	}
	if !s.cg.Has(v.pid) {
		return false, fmt.Errorf("pid %d is not in the sandbox cgroup", v.pid)
	}
	state, err := v.api.state(ctx)
	if err != nil {
		return false, err
	}
	// vCPUs paused through the API cannot answer: resume them briefly.
	paused := state == "Paused"
	if paused {
		if err := v.api.setState(ctx, "Resumed"); err != nil {
			return false, err
		}
	}
	go v.pollExit()
	watch, err := b.connect(ctx, s, v, time.Now().Add(startTimeout))
	if err != nil {
		v.disconnect()
		return false, err
	}
	if paused {
		if err := v.api.setState(ctx, "Paused"); err != nil {
			v.disconnect()
			return false, err
		}
	}
	register()
	b.attach(s, v, watch)
	return paused, nil
}
