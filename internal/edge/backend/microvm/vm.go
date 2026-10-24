package microvm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/aether"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
)

// sandbox is one microVM sandbox. Its VM (Firecracker process) changes over
// its life: pausing ends it after a snapshot, resuming starts a new one.
type sandbox struct {
	id, lease string
	dir, root string // state dir; jail root (the VM's view of /)
	uid       int
	cg        *linuxrt.Cgroup
	st        runtimeState

	mu  sync.Mutex
	cur *vm // nil while paused to a snapshot

	stopped chan struct{} // closed when Stop/Detach begins
	once    sync.Once

	lastPause   pauseStats
	lastRestore []phase // the steps of the last create from a snapshot

	digMu sync.Mutex
	dig   chan struct{} // closed when the hole punching below ends
	digP  *os.Process
}

// digHoles punches the all-zero blocks of the pause memory file out in the
// background (spec §19.13): the pages the guest gave back are zeros, still
// written by snapshots. Only the disk use changes.
func (s *sandbox) digHoles(path string) {
	if _, err := exec.LookPath("fallocate"); err != nil {
		return
	}
	cmd := exec.Command("fallocate", "--dig-holes", path)
	if cmd.Start() != nil {
		return
	}
	done := make(chan struct{})
	go func() { linuxrt.WaitCmd(cmd); close(done) }()
	s.digMu.Lock()
	s.dig, s.digP = done, cmd.Process
	s.digMu.Unlock()
}

// digHolesNow punches the zero blocks out of path, waiting for it; best
// effort, like digHoles.
func digHolesNow(path string) {
	if _, err := exec.LookPath("fallocate"); err == nil {
		exec.Command("fallocate", "--dig-holes", path).Run()
	}
}

// stopDig ends a running digHoles (before the file is written again).
func (s *sandbox) stopDig() {
	s.digMu.Lock()
	done, p := s.dig, s.digP
	s.dig, s.digP = nil, nil
	s.digMu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	default:
		p.Kill()
		<-done
	}
}

// phase is one timed step of starting a VM (spec §19.15).
type phase struct {
	Name string
	D    time.Duration
}

// stopwatch times the steps of a start.
type stopwatch struct {
	t  time.Time
	ps []phase
}

func newStopwatch() *stopwatch { return &stopwatch{t: time.Now()} }

// mark ends the step name now.
func (w *stopwatch) mark(name string) { w.markAt(name, time.Now()) }

// markAt ends the step name at t.
func (w *stopwatch) markAt(name string, t time.Time) {
	w.ps = append(w.ps, phase{name, t.Sub(w.t)})
	w.t = t
}

// pauseStats describes the last pause snapshot.
type pauseStats struct {
	Type   string // Full or Diff
	Merged int64  // Diff: the bytes of dirty pages merged
}

func (s *sandbox) vm() *vm {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *sandbox) setVM(v *vm) {
	s.mu.Lock()
	s.cur = v
	s.mu.Unlock()
}

// runtimeState is persisted in the sandbox dir for re-adoption and
// snapshots.
type runtimeState struct {
	Pid       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
	UID       int    `json:"uid"`
	// Suspended: paused to pauseState/pauseMem, no process.
	Suspended bool       `json:"suspended,omitempty"`
	MemMB     int64      `json:"mem_mb"`
	VCPUs     int        `json:"vcpus"`
	DiskMB    int64      `json:"disk_mb"`
	Hostname  string     `json:"hostname"`
	Image     imageState `json:"image"`
	// Base (a path in the jail) holds the guest memory as of the last reset
	// of its dirty page log (the last snapshot or restore): the next pause
	// writes only the pages dirtied since, merged into a copy of Base, or
	// into Base itself when BaseOwned (no other VM or snapshot shares it).
	// zeroBase after a cold boot: memory started out all zeros, and the
	// dirty pages are all it holds. Empty when there is none (the log was
	// reset without a base kept): the next pause writes all memory.
	Base      string `json:"base,omitempty"`
	BaseOwned bool   `json:"base_owned,omitempty"`
	// Untracked: the VM runs without a dirty page log (cold booted with
	// UntrackedBoot), so it has no Base until it is restored from a
	// snapshot: its pauses and snapshots write all memory.
	Untracked bool `json:"untracked,omitempty"`
	// Netns is the network namespace the VM runs in (spec §20); empty: a
	// fresh one without network per process.
	Netns string `json:"netns,omitempty"`
	// Holder keeps Netns alive (spec §25.4).
	Holder *linuxrt.NetnsHolder `json:"netns_holder,omitempty"`
}

// imageState is what the sandbox runs on, recorded in its snapshots.
type imageState struct {
	Name    string            `json:"name,omitempty"`
	Base    string            `json:"base,omitempty"`
	Layers  []string          `json:"layers,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Workdir string            `json:"workdir,omitempty"`
	User    string            `json:"user,omitempty"`
}

// Files in the jail root.
const (
	pauseState = "/pause.vmstate"
	pauseMem   = "/pause.mem"
	pauseDiff  = "/pause.diff" // the dirty pages of a pause, merged into pauseMem
	baseMem    = "/base.mem"   // a shared Base (of a snapshot)
	zeroBase   = "zero"        // Base of a cold-booted VM: no file, all zeros
)

func (s *sandbox) persist() error {
	if v := s.vm(); v != nil {
		s.st.Pid, s.st.StartTime, s.st.Suspended = v.pid, v.start, false
	} else {
		s.st.Pid, s.st.StartTime, s.st.Suspended = 0, 0, true
	}
	return linuxrt.WriteJSON(filepath.Join(s.dir, "state.json"), s.st)
}

// vm is one Firecracker process of a sandbox.
type vm struct {
	pid      int
	start    uint64
	api      *fcAPI
	exited   chan struct{}
	exitOnce sync.Once

	retired    chan struct{} // closed when the VM is ended on purpose
	retireOnce sync.Once

	mu sync.Mutex
	l  *link // the connection to aether

	listened time.Time // when aether first accepted on vsock (connect)
}

// link is one connection to aether. A VM gets a new one after a snapshot:
// taking one resets the guest's vsock connections.
type link struct {
	conn   *grpc.ClientConn
	rt     pb.RuntimeClient
	cancel context.CancelFunc // ends the heartbeat stream
	closed chan struct{}      // closed when the link is dropped on purpose
	once   sync.Once
}

func (l *link) close() {
	l.once.Do(func() { close(l.closed) })
	if l.cancel != nil {
		l.cancel()
	}
	l.conn.Close()
}

func (v *vm) markExited() { v.exitOnce.Do(func() { close(v.exited) }) }

func (v *vm) link() *link {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.l
}

// setLink replaces the VM's link, closing the previous one.
func (v *vm) setLink(l *link) {
	v.mu.Lock()
	old := v.l
	v.l = l
	v.mu.Unlock()
	if old != nil && old != l {
		old.close()
	}
}

func (v *vm) disconnect() {
	v.retireOnce.Do(func() { close(v.retired) })
	v.setLink(nil)
}

func (v *vm) alive() bool {
	st, err := linuxrt.ProcStartTime(v.pid)
	return err == nil && st == v.start
}

// pollExit closes exited when an adopted (non-child) VM process dies.
func (v *vm) pollExit() {
	for {
		if !v.alive() {
			v.markExited()
			return
		}
		select {
		case <-v.exited:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// startVM starts a jailed Firecracker for s: booting vm.json with
// withConfig, else idle, waiting for a snapshot to load.
func (b *Backend) startVM(s *sandbox, withConfig bool) (*vm, error) {
	// Leftovers of a previous process in the same jail.
	for _, p := range []string{"firecracker", "dev", "run", "v.sock", "firecracker.pid"} {
		os.RemoveAll(filepath.Join(s.root, p))
	}
	cgfd, err := s.cg.Open()
	if err != nil {
		return nil, err
	}
	defer cgfd.Close()
	logf, err := os.OpenFile(filepath.Join(s.dir, "console.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	args := []string{"jailer", "--id", s.lease, "--exec-file", b.opt.Firecracker,
		"--uid", strconv.Itoa(s.uid), "--gid", strconv.Itoa(s.uid), "--chroot-base-dir", b.jailBase(),
		"--cgroup-version", "2"}
	// No network yet (as containers: spec §19.3) unless the sandbox has
	// one (spec §20): the jailer then joins its namespace.
	clone := uintptr(syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS)
	if s.st.Netns != "" {
		args = append(args, "--netns", s.st.Netns)
		clone &^= syscall.CLONE_NEWNET
	}
	args = append(args, "--", "--api-sock", "/run/fc.sock")
	if withConfig {
		args = append(args, "--config-file", "/vm.json")
	}
	cmd := &exec.Cmd{
		Path: b.opt.Jailer, Args: args, Stdout: logf, Stderr: logf,
		SysProcAttr: &syscall.SysProcAttr{
			// The jailer adds its own mount namespace and chroot.
			Cloneflags:  clone,
			UseCgroupFD: true, CgroupFD: int(cgfd.Fd()),
			Setsid: true,
		},
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start jailer: %w", err)
	}
	// The cookie covers the jailer's threads now and, through exec and
	// clone, Firecracker's vCPU threads later (spec §29.1).
	if b.opt.CoreSched {
		if err := linuxrt.CoreSchedNew(cmd.Process.Pid); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, err
		}
	}
	v := &vm{pid: cmd.Process.Pid, exited: make(chan struct{}), retired: make(chan struct{}),
		api: newFCAPI(filepath.Join(s.root, "run", "fc.sock"))}
	go func() { linuxrt.WaitCmd(cmd); v.markExited() }()
	v.start, _ = linuxrt.ProcStartTime(v.pid)
	return v, nil
}

// endVM ends v on purpose (pause, stop): its loss is not reported.
func (b *Backend) endVM(s *sandbox, v *vm) {
	v.disconnect()
	s.cg.Kill()
	select {
	case <-v.exited:
	case <-time.After(5 * time.Second):
	}
}

// waitAPI waits until v's API socket answers.
func (b *Backend) waitAPI(ctx context.Context, s *sandbox, v *vm) error {
	deadline := time.Now().Add(startTimeout)
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		_, err := v.api.state(cctx)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-v.exited:
			return fmt.Errorf("microvm exited: %s", tail(filepath.Join(s.dir, "console.log")))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("firecracker API did not come up: %v", err)
		}
	}
}

// restore loads a snapshot (paths inside the jail) into a new VM of s and
// prepares the guest with post (its clock and entropy are always renewed).
// w times its steps.
func (b *Backend) restore(ctx context.Context, s *sandbox, state, mem string, post *pb.PostRestoreRequest, w *stopwatch) (*vm, pb.Runtime_WatchClient, error) {
	for attempt := 0; ; attempt++ {
		v, watch, err := b.restoreOnce(ctx, s, state, mem, post, w)
		if err != nil && tapBusy(err) && attempt < tapRetries {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			w.mark("tap_retry")
			continue
		}
		return v, watch, err
	}
}

func (b *Backend) restoreOnce(ctx context.Context, s *sandbox, state, mem string, post *pb.PostRestoreRequest, w *stopwatch) (*vm, pb.Runtime_WatchClient, error) {
	v, err := b.startVM(s, false)
	if err != nil {
		return nil, nil, err
	}
	w.mark("jailer")
	fail := func(err error) (*vm, pb.Runtime_WatchClient, error) {
		b.endVM(s, v)
		return nil, nil, err
	}
	if err := b.waitAPI(ctx, s, v); err != nil {
		return fail(err)
	}
	w.mark("api")
	load := map[string]any{"snapshot_path": state, "resume_vm": true, "track_dirty_pages": !b.opt.NoDirtyTracking,
		"mem_backend": map[string]string{"backend_type": "File", "backend_path": mem}}
	if err := v.api.call(ctx, "PUT", "/snapshot/load", load, nil); err != nil {
		return fail(fmt.Errorf("load snapshot: %w", err))
	}
	s.st.Untracked = false // loaded with the log on
	w.mark("load")
	watch, err := b.connect(ctx, s, v, time.Now().Add(startTimeout))
	if err != nil {
		return fail(err)
	}
	w.markAt("vsock", v.listened)
	w.mark("grpc")
	post.UnixNanos = time.Now().UnixNano()
	post.Entropy = make([]byte, 64)
	rand.Read(post.Entropy)
	if _, err := v.link().rt.PostRestore(ctx, post); err != nil {
		return fail(fmt.Errorf("post-restore: %w", err))
	}
	w.mark("post_restore")
	return v, watch, nil
}

// newIdentity is the PostRestore request giving a restored copy its own
// hostname and machine id.
func newIdentity(hostname string) *pb.PostRestoreRequest {
	var id [16]byte
	rand.Read(id[:])
	return &pb.PostRestoreRequest{Hostname: hostname, MachineId: hex.EncodeToString(id[:])}
}

// connect dials aether over vsock until its first heartbeat, making the
// connection v's link.
func (b *Backend) connect(ctx context.Context, s *sandbox, v *vm, deadline time.Time) (pb.Runtime_WatchClient, error) {
	uds := filepath.Join(s.root, "v.sock")
	// Wait for aether to listen with plain handshakes (the VMM answers OK
	// only once the guest accepted): gRPC would back off for a second after
	// the first failed attempt of a booting guest.
	for {
		c, err := dialVsock(ctx, uds, aether.VMVsockPort)
		if err == nil {
			c.Close()
			v.listened = time.Now()
			break
		}
		select {
		case <-v.exited:
			return nil, fmt.Errorf("microvm exited: %s", tail(filepath.Join(s.dir, "console.log")))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("aether did not listen within %v: %v: %s", startTimeout, err, tail(filepath.Join(s.dir, "console.log")))
		}
	}
	conn, err := grpc.NewClient("passthrough:///"+s.lease, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialVsock(ctx, uds, aether.VMVsockPort)
		}),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 20 * time.Millisecond,
			Multiplier: 1.6, Jitter: 0.2, MaxDelay: time.Second}, MinConnectTimeout: 5 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(80<<20), grpc.MaxCallSendMsgSize(80<<20)))
	if err != nil {
		return nil, err
	}
	l := &link{conn: conn, rt: pb.NewRuntimeClient(conn), closed: make(chan struct{})}
	for {
		// The stream of the successful attempt lives as long as the link.
		sctx, cancel := context.WithCancel(context.Background())
		watch, err := l.rt.Watch(sctx, &pb.Empty{})
		if err == nil {
			got := make(chan error, 1)
			go func() { _, err := watch.Recv(); got <- err }()
			select {
			case err = <-got:
			case <-time.After(time.Second):
				err = fmt.Errorf("no heartbeat")
			}
			if err == nil {
				l.cancel = cancel
				v.setLink(l)
				return watch, nil
			}
		}
		cancel()
		select {
		case <-v.exited:
			conn.Close()
			return nil, fmt.Errorf("microvm exited: %s", tail(filepath.Join(s.dir, "console.log")))
		case <-ctx.Done():
			conn.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			conn.Close()
			return nil, fmt.Errorf("aether did not answer within %v: %v: %s", startTimeout, err, tail(filepath.Join(s.dir, "console.log")))
		}
	}
}

// attach makes v the sandbox's VM and watches its heartbeats.
func (b *Backend) attach(s *sandbox, v *vm, w pb.Runtime_WatchClient) {
	s.setVM(v)
	go b.watch(s, v, v.link(), w)
}

// watch consumes the heartbeats of v's link l; the stream ending while l is
// in use means the sandbox is gone.
func (b *Backend) watch(s *sandbox, v *vm, l *link, w pb.Runtime_WatchClient) {
	for {
		if _, err := w.Recv(); err != nil {
			break
		}
	}
	reason := "aether channel closed"
	select {
	case <-v.exited:
		reason = "microvm exited"
	case <-v.retired:
	case <-l.closed:
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-s.stopped:
		return
	case <-v.retired:
		return
	case <-l.closed:
		return
	default:
	}
	b.onLost(s.id, reason)
}

// dropCache writes back and evicts a file's page cache (a pause snapshot's
// memory, so pausing really frees the sandbox's memory).
func dropCache(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	unix.Fdatasync(int(f.Fd()))
	unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
