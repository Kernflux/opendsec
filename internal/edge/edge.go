// Package edge implements the node-local control plane (paper §3, spec §3.6):
// final admission, the sandbox state machine, TTL reclamation, liveness
// probing, resource release and scheduling-state reports for the watcher.
// Runtimes plug in through backend.Backend.
package edge

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/host"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/internal/sandboxfs"
)

// createTimeout bounds a backend creation independently of the caller's
// deadline: a creation that has started finishes (or fails) cleanly even if
// the client gave up, and the idle TTL reclaims it.
const createTimeout = 5 * time.Minute

type record struct {
	sb         *pb.Sandbox // guarded by Edge.mu
	lease      string
	createdAt  time.Time
	lastActive time.Time
	endedAt    time.Time
	released   bool
	inflight   int           // runtime calls in progress; blocks idle reaping
	memRebate  int64         // memory not charged while paused (spec §24); guarded by Edge.mu
	squeezedMB int64         // its balloon (spec §24); guarded by Edge.mu
	op         chan struct{} // serializes lifecycle operations on this sandbox
	// moving: frozen for a move to another edge (spec §26.2) since then;
	// guarded by Edge.mu.
	moving time.Time
	// handedOff: the sandbox runs on another edge now, which holds its
	// quota lease: ending it here must not release the lease.
	handedOff bool
	peer      backend.SnapshotPeer // holds Spec.Snapshot's files, while creating
	unsaved   bool                 // its record on disk is behind (persist failed); guarded by Edge.mu
}

func (r *record) ended() bool {
	return r.sb.State == pb.SandboxState_STOPPED || r.sb.State == pb.SandboxState_FAILED
}

type Edge struct {
	cfg      config.Edge
	capacity *pb.Capacity
	backends map[string]backend.Backend
	// Release returns a lease's quota to IAM; called once per sandbox, async.
	Release func(lease string)
	// LeaseEdge, if set, asks IAM whether a lease is held and where it is
	// bound, before a new sandbox is kept (spec §36).
	LeaseEdge func(ctx context.Context, lease string) (held bool, edge string, err error)
	// Pressure, if set, gates admission on node memory pressure.
	Pressure *host.Pressure
	// DiskPressure, if set, gates admission on free space in the state dir.
	DiskPressure *host.DiskPressure
	// Usage, if set, reports what the host actually uses (spec §3.4); with
	// CPUPressureLimit > 0 it also gates admission on CPU pressure.
	Usage            *host.Usage
	CPUPressureLimit float64
	// Net, if set, gives sandboxes of networked backends a network under
	// their network_rules (spec §20).
	Net *netpol.Manager
	// Peers, if set, connects to other edges (spec §26): to fetch snapshots
	// they hold, and to complete moves.
	Peers func(*pb.EdgePeer) (pb.EdgeClient, error)
	now   func() time.Time
	store *store // nil: records are not persisted

	mu            sync.Mutex
	sbs           map[string]*record
	alloc         pb.Resources
	counts        map[string]int32
	draining      bool
	totalCreated  int64
	totalRejected int64
	moved         map[string]moved // sandboxes that moved away, by id
}

func New(cfg config.Edge, backends map[string]backend.Backend) *Edge {
	cfg.Defaults()
	c := &pb.Capacity{
		CpuCores:     cfg.Capacity.CPUCores * cfg.CPUOvercommit,
		MemoryMb:     int64(float64(cfg.Capacity.MemoryMB) * cfg.MemOvercommit),
		Gpus:         cfg.Capacity.GPUs,
		DiskMb:       int64(float64(cfg.Capacity.DiskMB) * cfg.DiskOvercommit),
		MaxSandboxes: map[string]int32{},
	}
	for name, b := range cfg.Backends {
		if _, ok := backends[name]; ok {
			c.MaxSandboxes[name] = b.MaxSandboxes
			if b.DefaultDiskMB > 0 {
				if c.DefaultDiskMb == nil {
					c.DefaultDiskMb = map[string]int64{}
				}
				c.DefaultDiskMb[name] = b.DefaultDiskMB
			}
		}
	}
	e := &Edge{
		cfg: cfg, capacity: c, backends: backends,
		Release: func(string) {},
		now:     time.Now,
		sbs:     map[string]*record{},
		counts:  map[string]int32{},
		moved:   map[string]moved{},
	}
	for _, b := range backends {
		if lr, ok := b.(backend.LossReporter); ok {
			lr.OnLost(e.lost)
		}
	}
	return e
}

// lost handles a backend reporting that a sandbox died on its own.
func (e *Edge) lost(id, reason string) {
	e.mu.Lock()
	r := e.sbs[id]
	e.mu.Unlock()
	if r != nil {
		e.fail(r, "sandbox lost: "+reason)
	}
}

// fail marks r FAILED and has the backend release whatever it still holds.
func (e *Edge) fail(r *record, msg string) {
	if e.state(r) == pb.SandboxState_STOPPING {
		return // an in-progress stop is tearing it down anyway
	}
	e.terminate(r, pb.SandboxState_FAILED, msg)
	go e.backends[r.sb.Spec.Backend].Stop(context.Background(), e.bsb(r))
}

func (e *Edge) ID() string { return e.cfg.ID }

func unix(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

func (e *Edge) get(id string) (*record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.sbs[id]
	if r == nil {
		if m, ok := e.moved[id]; ok {
			return nil, rpcutil.Moved(id, m.to)
		}
		return nil, rpcutil.Err(rpcutil.NotFound, "sandbox %s", id)
	}
	if !r.moving.IsZero() {
		return nil, rpcutil.Err(rpcutil.Unavailable, "sandbox %s is moving to another edge", id)
	}
	return r, nil
}

func (e *Edge) snapshot(r *record) *pb.Sandbox {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cloneLocked(r)
}

func (e *Edge) cloneLocked(r *record) *pb.Sandbox {
	out := proto.Clone(r.sb).(*pb.Sandbox)
	out.LastActiveAt = unix(r.lastActive)
	return out
}

// ---- admission & creation ------------------------------------------------------

// diskOf is the writable-disk size a sandbox is charged: its request, or
// the backend's default disk.
func (e *Edge) diskOf(spec *pb.SandboxSpec) int64 {
	if d := spec.Resources.GetDiskMb(); d > 0 {
		return d
	}
	return e.capacity.DefaultDiskMb[spec.Backend]
}

// fitsLocked returns why spec does not fit on this edge ("" if it does).
func (e *Edge) fitsLocked(spec *pb.SandboxSpec) string {
	c, res := e.capacity, spec.Resources
	if e.counts[spec.Backend]+1 > c.MaxSandboxes[spec.Backend] {
		return "sandbox slots"
	}
	if e.alloc.CpuCores+res.GetCpuCores() > c.CpuCores+1e-9 {
		return "cpu"
	}
	if e.alloc.MemoryMb+res.GetMemoryMb() > c.MemoryMb {
		return "memory"
	}
	if c.DiskMb > 0 && e.alloc.DiskMb+e.diskOf(spec) > c.DiskMb {
		return "disk"
	}
	if spec.GpuMode == "shared" {
		if c.Gpus == 0 {
			return "gpus"
		}
		return ""
	}
	if e.alloc.Gpus+res.GetGpus() > c.Gpus {
		return "gpus"
	}
	return ""
}

func (e *Edge) chargeLocked(spec *pb.SandboxSpec, sign int) {
	res := spec.Resources
	e.alloc.CpuCores += float64(sign) * res.GetCpuCores()
	e.alloc.MemoryMb += int64(sign) * res.GetMemoryMb()
	e.alloc.DiskMb += int64(sign) * e.diskOf(spec)
	if spec.GpuMode != "shared" {
		e.alloc.Gpus += int32(sign) * res.GetGpus()
	}
	e.counts[spec.Backend] += int32(sign)
}

// Create admits and starts a sandbox. Creating an id that already exists
// returns the existing record (idempotent retries from the apiserver).
// timed runs backend operation op on r, recording its duration.
func (e *Edge) timed(r *record, op string, f func() error) error {
	t0 := time.Now()
	err := f()
	metrics.Op(r.sb.Spec.Backend, op, rpcutil.ReasonOf(err), time.Since(t0))
	return err
}

func (e *Edge) Create(ctx context.Context, req *pb.EdgeCreateRequest) (*pb.Sandbox, error) {
	t0 := time.Now()
	sb, err := e.create(ctx, req)
	metrics.Create(req.Spec.GetBackend(), rpcutil.ReasonOf(err), time.Since(t0))
	return sb, err
}

func (e *Edge) create(ctx context.Context, req *pb.EdgeCreateRequest) (*pb.Sandbox, error) {
	edgeID, lease, err := ids.Parse(req.Id)
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	if edgeID != e.cfg.ID && !(req.Move && req.SnapshotPeer.GetId() == edgeID) {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s does not belong to edge %s", req.Id, e.cfg.ID)
	}
	var peer backend.SnapshotPeer
	if req.SnapshotPeer != nil && req.SnapshotPeer.Id != e.cfg.ID {
		if e.Peers == nil {
			return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s cannot reach other edges", e.cfg.ID)
		}
		c, err := e.Peers(req.SnapshotPeer)
		if err != nil {
			return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s: %v", req.SnapshotPeer.Id, err)
		}
		peer = peerSource{c}
	}
	spec := req.Spec
	if spec == nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "spec required")
	}
	be := e.backends[spec.Backend]
	if be == nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "edge %s has no backend %q", e.cfg.ID, spec.Backend)
	}
	if il, ok := be.(backend.ImageLister); ok {
		if imgs := il.Images(); imgs != nil && !contains(imgs, spec.Image) {
			// Retryable: another edge may have it (stale placement snapshot).
			return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s does not have image %q", e.cfg.ID, spec.Image)
		}
	}
	for _, paths := range [][]string{spec.ReadonlyPaths, spec.MaskedPaths} {
		if err := sandboxfs.Validate(paths); err != nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "%v", err)
		}
	}
	nb, networked := be.(backend.Networked)
	networked = networked && e.Net != nil
	if networked {
		if err := e.Net.Validate(spec.NetworkRules); err != nil {
			return nil, err
		}
	}
	if spec.Resources == nil {
		spec.Resources = &pb.Resources{}
	}
	if spec.Resources.DiskMb == 0 { // record the disk the sandbox actually gets
		spec.Resources.DiskMb = e.capacity.DefaultDiskMb[spec.Backend]
	}
	now := e.now()
	created := now
	if req.Move && req.CreatedAt > 0 {
		created = time.Unix(0, int64(req.CreatedAt*1e9))
	}

	e.mu.Lock()
	if r := e.sbs[req.Id]; r != nil {
		e.mu.Unlock()
		return e.waitCreated(ctx, r)
	}
	if e.draining {
		e.totalRejected++
		e.mu.Unlock()
		return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s is draining", e.cfg.ID)
	}
	if short := e.fitsLocked(spec); short != "" {
		e.totalRejected++
		e.mu.Unlock()
		return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s cannot fit %s sandbox: not enough %s", e.cfg.ID, spec.Backend, short)
	}
	if e.Pressure != nil {
		if avail, under := e.Pressure.Check(); under {
			e.totalRejected++
			e.mu.Unlock()
			return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s under memory pressure: %d MB available < %d MB reserve",
				e.cfg.ID, avail, e.Pressure.ReserveMB)
		}
	}
	if e.DiskPressure != nil {
		if avail, under := e.DiskPressure.Check(); under {
			e.totalRejected++
			e.mu.Unlock()
			return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s under disk pressure: %d MB free < %d MB reserve",
				e.cfg.ID, avail, e.DiskPressure.ReserveMB)
		}
	}
	if psi, under := e.cpuPressure(); under {
		e.totalRejected++
		e.mu.Unlock()
		return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s under CPU pressure: PSI some avg10 %.1f%% > %g%%",
			e.cfg.ID, psi, e.CPUPressureLimit)
	}
	e.chargeLocked(spec, 1)
	r := &record{
		sb: &pb.Sandbox{
			Id: req.Id, Project: req.Project, Principal: req.Principal, EdgeId: e.cfg.ID,
			Spec: spec, State: pb.SandboxState_CREATING, CreatedAt: unix(created),
		},
		lease: lease, createdAt: created, lastActive: now,
		op: make(chan struct{}, 1), peer: peer,
	}
	r.op <- struct{}{} // held until creation finishes
	e.sbs[req.Id] = r
	delete(e.moved, req.Id) // moving back
	e.mu.Unlock()
	// Persist before touching the backend: if the edge dies mid-creation, the
	// restarted edge knows this sandbox exists and cleans it up.
	if err := e.persist(r); err != nil {
		e.terminate(r, pb.SandboxState_FAILED, "persist record: "+err.Error())
		<-r.op
		return nil, rpcutil.Err(rpcutil.Internal, "persist %s: %v", req.Id, err)
	}

	if networked {
		if _, err := e.Net.Allocate(lease, spec.NetworkRules, nb.NetworkVM()); err != nil {
			e.terminate(r, pb.SandboxState_FAILED, "network: "+err.Error())
			<-r.op
			if rpcutil.Reason(err) != "" {
				return nil, err
			}
			return nil, rpcutil.Err(rpcutil.Internal, "network for %s: %v", req.Id, err)
		}
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), createTimeout)
	defer cancel()
	err = be.Create(cctx, e.bsb(r))
	if err != nil {
		e.terminate(r, pb.SandboxState_FAILED, "create failed: "+err.Error())
		<-r.op
		// Keep the reason of backend errors that carry one (a bad request, a
		// missing image, no capacity), so callers and retries can act on it.
		switch reason := rpcutil.Reason(err); reason {
		case rpcutil.Invalid, rpcutil.NotFound, rpcutil.NoCapacity, rpcutil.Unavailable:
			return nil, rpcutil.Err(reason, "create %s: %s", req.Id, rpcutil.Message(err))
		}
		return nil, rpcutil.Err(rpcutil.Internal, "create %s: %v", req.Id, err)
	}
	if !req.Move {
		if why := e.abandoned(ctx, lease); why != "" {
			if err := be.Stop(context.WithoutCancel(ctx), e.bsb(r)); err != nil {
				why += "; stop failed: " + err.Error()
			}
			e.terminate(r, pb.SandboxState_FAILED, why) // IAM keeps a lease bound elsewhere
			<-r.op
			return nil, rpcutil.Err(rpcutil.Unavailable, "create %s: %s", req.Id, why)
		}
	}
	if req.Move {
		// The edge it came from lets go of it; until then it must not run
		// there too (spec §26.2).
		if err := e.endMove(ctx, req.SnapshotPeer, req.Id); err != nil {
			r.handedOff = true // the lease stays with the original
			be.Stop(context.WithoutCancel(ctx), e.bsb(r))
			e.terminate(r, pb.SandboxState_FAILED, "move: "+err.Error())
			<-r.op
			return nil, rpcutil.Err(rpcutil.Unavailable, "move %s: edge %s did not let go of it: %v", req.Id, req.SnapshotPeer.Id, err)
		}
	}
	if e.Pressure != nil {
		e.Pressure.Invalidate()
	}
	e.mu.Lock()
	r.peer = nil
	r.sb.State = pb.SandboxState_RUNNING
	r.lastActive = e.now()
	e.mu.Unlock()
	// Restarted with the record still saying CREATING, the edge would
	// remove the sandbox: do not report one that would not survive that.
	// A moved one is kept (the edge it came from let go of it); its record
	// is saved again by the sweep.
	if err := e.persist(r); err != nil && !req.Move {
		be.Stop(context.WithoutCancel(ctx), e.bsb(r))
		e.terminate(r, pb.SandboxState_FAILED, "persist record: "+err.Error())
		<-r.op
		return nil, rpcutil.Err(rpcutil.Internal, "persist %s: %v", req.Id, err)
	}
	e.mu.Lock()
	e.totalCreated++
	out := e.cloneLocked(r)
	e.mu.Unlock()
	<-r.op
	return out, nil
}

// abandoned says why a sandbox just created must go, or "": its caller
// gave up (a hung or slow edge) and placed it on another edge, which moved
// the lease there, or released the lease (spec §36). Kept, it would be an
// orphan nobody knows of. When IAM cannot be asked the sandbox stays (the
// caller of LeaseEdge logs why), and the watcher's reconcile reports the
// conflict.
func (e *Edge) abandoned(ctx context.Context, lease string) string {
	if e.LeaseEdge == nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	held, edge, err := e.LeaseEdge(cctx, lease)
	switch {
	case err != nil:
		return ""
	case !held:
		return "abandoned by its caller: the lease was released"
	case edge != "" && edge != e.cfg.ID:
		return "abandoned by its caller: it was created on edge " + edge + " instead"
	}
	return ""
}

// waitCreated waits for an in-progress creation of r and returns its result.
func (e *Edge) waitCreated(ctx context.Context, r *record) (*pb.Sandbox, error) {
	select {
	case r.op <- struct{}{}:
		<-r.op
	case <-ctx.Done():
		return nil, rpcutil.Err(rpcutil.Timeout, "waiting for %s", r.sb.Id)
	}
	sb := e.snapshot(r)
	if sb.State == pb.SandboxState_FAILED {
		return nil, rpcutil.Err(rpcutil.Internal, "%s: %s", sb.Id, sb.Message)
	}
	return sb, nil
}

func (e *Edge) bsb(r *record) *backend.Sandbox {
	sb := &backend.Sandbox{ID: r.sb.Id, Project: r.sb.Project, Spec: r.sb.Spec, Peer: r.peer}
	if e.Net != nil {
		sb.Net = e.Net.Get(r.lease)
	}
	return sb
}

// terminate moves r to a terminal state and frees its node resources and quota
// lease exactly once.
func (e *Edge) terminate(r *record, state pb.SandboxState, msg string) {
	e.mu.Lock()
	if r.ended() { // e.g. a liveness failure racing with a stop
		e.mu.Unlock()
		return
	}
	r.sb.State = state
	r.sb.Message = msg
	r.endedAt = e.now()
	r.sb.EndedAt = unix(r.endedAt)
	release := !r.released
	if release {
		r.released = true
		e.rebateLocked(r, false)
		e.chargeLocked(r.sb.Spec, -1)
	}
	e.mu.Unlock()
	if e.store != nil {
		e.store.remove(r.lease)
	}
	if e.Net != nil {
		e.Net.Release(r.lease)
	}
	if release && !r.handedOff {
		e.Release(r.lease)
	}
}

// persist writes r's current record if persistence is enabled. A record
// that could not be written is marked unsaved, and the sweep writes it
// again: in memory it is right, on disk it is behind (a restart would
// bring back its old state, rules and timeouts).
func (e *Edge) persist(r *record) error {
	if e.store == nil {
		return nil
	}
	e.mu.Lock()
	sb := proto.Clone(r.sb).(*pb.Sandbox)
	ended := r.ended()
	e.mu.Unlock()
	if ended {
		return nil
	}
	err := e.store.save(r.lease, sb)
	e.mu.Lock()
	r.unsaved = err != nil
	e.mu.Unlock()
	if err != nil {
		slog.Warn("saving a sandbox record failed; the sweep retries it", "sandbox", sb.Id, "err", err)
	}
	return err
}

// ---- lifecycle operations ---------------------------------------------------------

// lock acquires r's operation lock.
func lock(ctx context.Context, r *record) error {
	select {
	case r.op <- struct{}{}:
		return nil
	case <-ctx.Done():
		return rpcutil.Err(rpcutil.Timeout, "sandbox %s busy", r.sb.Id)
	}
}

func (e *Edge) state(r *record) pb.SandboxState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return r.sb.State
}

func (e *Edge) setState(r *record, s pb.SandboxState) {
	e.mu.Lock()
	r.sb.State = s
	e.mu.Unlock()
}

func (e *Edge) Get(id string) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

func (e *Edge) Stop(ctx context.Context, id string) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	return e.stop(ctx, r, "stopped by request")
}

func (e *Edge) stop(ctx context.Context, r *record, msg string) (*pb.Sandbox, error) {
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	if e.state(r) == pb.SandboxState_STOPPED || e.state(r) == pb.SandboxState_FAILED {
		return e.snapshot(r), nil
	}
	e.setState(r, pb.SandboxState_STOPPING)
	err := e.timed(r, "stop", func() error { return e.backends[r.sb.Spec.Backend].Stop(context.WithoutCancel(ctx), e.bsb(r)) })
	if err != nil {
		e.terminate(r, pb.SandboxState_FAILED, "stop failed: "+err.Error())
	} else {
		e.terminate(r, pb.SandboxState_STOPPED, msg)
	}
	return e.snapshot(r), nil
}

func (e *Edge) Pause(ctx context.Context, id string) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	switch e.state(r) {
	case pb.SandboxState_PAUSED:
		return e.snapshot(r), nil
	case pb.SandboxState_RUNNING:
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "cannot pause %s in state %s", id, e.state(r))
	}
	e.setState(r, pb.SandboxState_PAUSING)
	if err := e.timed(r, "pause", func() error { return e.backends[r.sb.Spec.Backend].Pause(ctx, e.bsb(r)) }); err != nil {
		e.setState(r, pb.SandboxState_RUNNING)
		return nil, rpcutil.Err(rpcutil.Internal, "pause %s: %v", id, err)
	}
	e.mu.Lock()
	r.sb.State = pb.SandboxState_PAUSED
	e.rebateLocked(r, true)
	e.mu.Unlock()
	e.persist(r)
	return e.snapshot(r), nil
}

// autoPause pauses r at its timeout instead of stopping it (ttl_paused_s,
// spec §37.11) and keeps it paused ttl_paused_s more; a sandbox that does
// not pause is stopped, as without ttl_paused_s.
func (e *Edge) autoPause(ctx context.Context, r *record, msg string) {
	if _, err := e.Pause(ctx, r.sb.Id); err != nil {
		e.stop(ctx, r, msg+"; pausing instead failed: "+err.Error())
		return
	}
	e.mu.Lock()
	keep := e.now().Sub(r.createdAt) + time.Duration(r.sb.Spec.TtlPausedS)*time.Second
	r.sb.Spec.TtlMaxS = int64((keep + time.Second - 1) / time.Second)
	e.mu.Unlock()
	e.persist(r)
}

// rebateLocked stops (on) or resumes charging the memory a paused sandbox
// gave back to the node (paused_mem_charge, spec §24).
func (e *Edge) rebateLocked(r *record, on bool) {
	if !on {
		e.alloc.MemoryMb += r.memRebate
		r.memRebate = 0
		return
	}
	f := 1.0
	if e.cfg.PausedMemCharge != nil {
		f = min(1, max(0, *e.cfg.PausedMemCharge))
	}
	rp, ok := e.backends[r.sb.Spec.Backend].(backend.MemoryReleasingPause)
	if r.memRebate != 0 || f >= 1 || !ok || !rp.PauseReleasesMemory() {
		return
	}
	r.memRebate = int64(float64(r.sb.Spec.Resources.GetMemoryMb()) * (1 - f))
	e.alloc.MemoryMb -= r.memRebate
}

func (e *Edge) Resume(ctx context.Context, id string) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	return e.resumeLocked(ctx, r)
}

// resumeLocked resumes a paused sandbox; the caller holds r.op.
func (e *Edge) resumeLocked(ctx context.Context, r *record) (*pb.Sandbox, error) {
	switch e.state(r) {
	case pb.SandboxState_RUNNING:
		return e.snapshot(r), nil
	case pb.SandboxState_PAUSED:
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "cannot resume %s in state %s", r.sb.Id, e.state(r))
	}
	e.mu.Lock()
	if r.memRebate > 0 && e.Pressure != nil {
		if avail, under := e.Pressure.Check(); under {
			e.mu.Unlock()
			return nil, rpcutil.Err(rpcutil.NoCapacity, "cannot resume %s: edge %s under memory pressure (%d MB available)",
				r.sb.Id, e.cfg.ID, avail)
		}
	}
	e.rebateLocked(r, false)
	r.sb.State = pb.SandboxState_RESUMING
	e.mu.Unlock()
	if err := e.timed(r, "resume", func() error { return e.backends[r.sb.Spec.Backend].Resume(ctx, e.bsb(r)) }); err != nil {
		e.mu.Lock()
		r.sb.State = pb.SandboxState_PAUSED
		e.rebateLocked(r, true)
		e.mu.Unlock()
		return nil, rpcutil.Err(rpcutil.Internal, "resume %s: %v", r.sb.Id, err)
	}
	e.mu.Lock()
	r.sb.State = pb.SandboxState_RUNNING
	r.lastActive = e.now() // paused time does not count toward the idle TTL
	e.mu.Unlock()
	e.persist(r)
	return e.snapshot(r), nil
}

// Touch marks activity. A request to a paused sandbox resumes it first
// (paper §5: transparent resume).
func (e *Edge) Touch(ctx context.Context, id string) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	if e.state(r) == pb.SandboxState_PAUSED {
		if _, err := e.resumeLocked(ctx, r); err != nil {
			return nil, err
		}
	}
	if st := e.state(r); st != pb.SandboxState_RUNNING {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, st)
	}
	e.mu.Lock()
	r.lastActive = e.now()
	e.mu.Unlock()
	return e.snapshot(r), nil
}

// SetTimeout ends sandbox id timeout from now (spec §37): its ttl_max
// becomes its age plus timeout (at most maxLife, when set), and its idle
// timeout is raised to timeout, so that it does not end earlier. A paused
// sandbox stays paused.
func (e *Edge) SetTimeout(ctx context.Context, id string, timeout, maxLife time.Duration) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	switch st := e.state(r); st {
	case pb.SandboxState_RUNNING, pb.SandboxState_PAUSED:
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, st)
	}
	e.mu.Lock()
	ttl := e.now().Sub(r.createdAt) + timeout
	if maxLife > 0 && ttl > maxLife {
		ttl = maxLife
	}
	spec := r.sb.Spec
	spec.TtlMaxS = int64((ttl + time.Second - 1) / time.Second)
	if t := int64(timeout / time.Second); spec.TtlRunningStopS > 0 && spec.TtlRunningStopS < t {
		spec.TtlRunningStopS = t
	}
	e.mu.Unlock()
	e.persist(r)
	return e.snapshot(r), nil
}

// ---- queries & bulk operations ------------------------------------------------------

func inProject(p, filter string) bool {
	return filter == "" || p == filter || strings.HasPrefix(p, filter+"/")
}

func (e *Edge) List(f *pb.SandboxFilter) []*pb.Sandbox {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*pb.Sandbox
	for _, r := range e.sbs {
		if (!f.IncludeEnded && r.ended()) || !inProject(r.sb.Project, f.Project) ||
			(f.TaskId != "" && r.sb.Spec.TaskId != f.TaskId) {
			continue
		}
		out = append(out, e.cloneLocked(r))
	}
	return out
}

// TaskAction pauses, resumes or stops every live sandbox of a task within a
// project subtree (used by the RL framework on preemption / job end).
func (e *Edge) TaskAction(ctx context.Context, project, task string, action pb.TaskAction) *pb.TaskActionResult {
	e.mu.Lock()
	var targets []*record
	for _, r := range e.sbs {
		if !r.ended() && r.sb.Spec.TaskId == task && inProject(r.sb.Project, project) {
			targets = append(targets, r)
		}
	}
	e.mu.Unlock()

	res := &pb.TaskActionResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, r := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(r *record) {
			defer func() { <-sem; wg.Done() }()
			var err error
			switch action {
			case pb.TaskAction_TASK_PAUSE:
				_, err = e.Pause(ctx, r.sb.Id)
			case pb.TaskAction_TASK_RESUME:
				_, err = e.Resume(ctx, r.sb.Id)
			case pb.TaskAction_TASK_STOP:
				_, err = e.stop(ctx, r, "task stopped")
			default:
				err = rpcutil.Err(rpcutil.Invalid, "unknown task action %v", action)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed++
				if len(res.Errors) < 10 {
					res.Errors = append(res.Errors, err.Error())
				}
			} else {
				res.Affected++
			}
		}(r)
	}
	wg.Wait()
	return res
}

// Shutdown ends the edge. With stopSandboxes it stops every live sandbox
// first; otherwise sandboxes keep running and a restarted edge re-adopts them
// from the persisted records (spec §13.5). Backends are closed either way.
func (e *Edge) Shutdown(stopSandboxes bool) {
	e.mu.Lock()
	e.draining = true
	var live []*record
	for _, r := range e.sbs {
		if !r.ended() {
			live = append(live, r)
		}
	}
	e.mu.Unlock()
	if stopSandboxes {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 32)
		for _, r := range live {
			wg.Add(1)
			sem <- struct{}{}
			go func(r *record) {
				defer func() { <-sem; wg.Done() }()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				e.stop(ctx, r, "edge shutting down")
			}(r)
		}
		wg.Wait()
	}
	for _, b := range e.backends {
		if stopSandboxes {
			if c, ok := b.(interface{ Close() }); ok {
				c.Close()
			}
		} else if d, ok := b.(interface{ Detach() }); ok {
			d.Detach()
		}
	}
	if e.Net != nil {
		if stopSandboxes {
			e.Net.Cleanup() // while its netlink connection is open: much faster
		}
		e.Net.Close()
	}
}

// UpdateNetwork changes a sandbox's network rules (spec §20): merged into
// its current ones, or replacing them.
func (e *Edge) UpdateNetwork(ctx context.Context, id string, rules map[string]bool, replace bool) (*pb.Sandbox, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	var a *netpol.Attachment
	if e.Net != nil {
		a = e.Net.Get(r.lease)
	}
	if a == nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s has no network (edge %s networking is off, or backend %s has none)",
			id, e.cfg.ID, r.sb.Spec.GetBackend())
	}
	e.mu.Lock()
	next := map[string]bool{}
	if !replace {
		for k, v := range r.sb.Spec.NetworkRules {
			next[k] = v
		}
	}
	e.mu.Unlock()
	for k, v := range rules {
		next[k] = v
	}
	if err := a.Rules(next); err != nil {
		return nil, err
	}
	e.mu.Lock()
	r.sb.Spec.NetworkRules = next
	e.mu.Unlock()
	e.persist(r)
	return e.snapshot(r), nil
}

func (e *Edge) SetDraining(d bool) {
	e.mu.Lock()
	e.draining = d
	e.mu.Unlock()
}

// cpuPressure returns the host's CPU pressure (PSI some avg10, percent) and
// whether it is above CPUPressureLimit (never when the limit is off).
func (e *Edge) cpuPressure() (float64, bool) {
	if e.Usage == nil || e.CPUPressureLimit <= 0 {
		return 0, false
	}
	psi := e.Usage.Read().Pressure
	return psi, psi > e.CPUPressureLimit
}

// The host's CPU threads and identity, reported with the edge's state.
var (
	hostCPUs = int32(runtime.NumCPU())
	hostID   = func() string {
		b, _ := os.ReadFile("/etc/machine-id")
		return strings.TrimSpace(string(b))
	}()
)

// Status reports scheduling state; leases are included for IAM reconcile.
func (e *Edge) Status(includeLeases bool) *pb.EdgeStatusResponse {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &pb.EdgeState{
		Id: e.cfg.ID, Addr: e.cfg.Addr, Zone: e.cfg.Zone, Healthy: true, Draining: e.draining,
		Capacity:       e.capacity,
		Alloc:          proto.Clone(&e.alloc).(*pb.Resources),
		CountByBackend: map[string]int32{},
		ByTask:         map[string]int32{}, ByProject: map[string]int32{}, ByPrincipal: map[string]int32{},
		TotalCreated: e.totalCreated, TotalRejected: e.totalRejected,
		HostCpus: hostCPUs, HostId: hostID,
	}
	for name, b := range e.backends {
		st.Backends = append(st.Backends, name)
		if il, ok := b.(backend.ImageLister); ok {
			if imgs := il.Images(); imgs != nil {
				if st.ImagesByBackend == nil {
					st.ImagesByBackend = map[string]*pb.ImageList{}
				}
				st.ImagesByBackend[name] = &pb.ImageList{Names: imgs}
			}
		}
		if sc, ok := b.(backend.SnapshotCacher); ok {
			st.Snapshots = append(st.Snapshots, sc.CachedSnapshots()...)
		}
	}
	for b, n := range e.counts {
		if n > 0 {
			st.CountByBackend[b] = n
		}
	}
	if e.Pressure != nil {
		avail, under := e.Pressure.Check()
		st.MemAvailableMb, st.UnderPressure = avail, under
		if under {
			st.Pressure = "memory"
		}
	}
	if e.DiskPressure != nil {
		avail, under := e.DiskPressure.Check()
		st.DiskAvailableMb = avail
		if under && !st.UnderPressure {
			st.UnderPressure, st.Pressure = true, "disk"
		}
	}
	if e.Usage != nil {
		u := e.Usage.Read()
		st.CpuUsed, st.MemUsed, st.CpuPressure = u.CPU, u.Mem, u.Pressure
		if _, under := e.cpuPressure(); under && !st.UnderPressure {
			st.UnderPressure, st.Pressure = true, "cpu"
		}
	}
	resp := &pb.EdgeStatusResponse{State: st}
	for _, b := range e.backends {
		if v, ok := b.(backend.Versioned); ok {
			for k, ver := range v.RuntimeVersions() {
				if st.RuntimeVersions == nil {
					st.RuntimeVersions = map[string]string{}
				}
				st.RuntimeVersions[k] = ver
			}
		}
	}
	for _, r := range e.sbs {
		if r.released {
			continue
		}
		if t := r.sb.Spec.TaskId; t != "" {
			st.ByTask[t]++
		}
		st.ByProject[r.sb.Project]++
		st.ByPrincipal[r.sb.Principal]++
		if !strings.HasPrefix(r.sb.Id, e.cfg.ID+".") {
			st.MovedIn = append(st.MovedIn, r.sb.Id)
		}
		if includeLeases {
			resp.Leases = append(resp.Leases, &pb.LeaseInfo{Lease: r.lease, Project: r.sb.Project, Resources: r.sb.Spec.Resources})
		}
	}
	return resp
}

// ---- background loop ------------------------------------------------------------------

// Run reaps TTL-expired sandboxes, probes liveness and garbage-collects ended
// records until ctx is cancelled.
func (e *Edge) Run(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Sweep(ctx)
			if e.Pressure != nil {
				if avail, _ := e.Pressure.Check(); avail > 0 {
					e.balance(ctx, avail, e.Pressure.ReserveMB)
				}
			}
		}
	}
}

// Sweep runs one reaper pass.
func (e *Edge) Sweep(ctx context.Context) {
	now := e.now()
	retention := config.Seconds(e.cfg.StoppedRetention)
	type job struct {
		r   *record
		msg string
	}
	var expire, pause, probe []job
	var unsaved, abandoned []*record
	e.mu.Lock()
	for id, m := range e.moved {
		if now.Sub(m.at) > movedRetention {
			delete(e.moved, id)
		}
	}
	for id, r := range e.sbs {
		if r.ended() {
			if now.Sub(r.endedAt) > retention {
				delete(e.sbs, id)
			}
			continue
		}
		if r.unsaved {
			unsaved = append(unsaved, r)
		}
		spec := r.sb.Spec
		if r.sb.State == pb.SandboxState_STOPPING {
			continue
		}
		if !r.moving.IsZero() {
			if now.Sub(r.moving) > moveTimeout { // the move was abandoned
				r.moving = time.Time{}
				abandoned = append(abandoned, r)
			}
			continue
		}
		running := r.sb.State == pb.SandboxState_RUNNING
		switch {
		case spec.TtlMaxS > 0 && now.Sub(r.createdAt) > time.Duration(spec.TtlMaxS)*time.Second:
			if running && spec.TtlPausedS > 0 {
				pause = append(pause, job{r, "max lifetime (ttl_max) reached"})
			} else {
				expire = append(expire, job{r, "max lifetime (ttl_max) reached"})
			}
		case running && spec.TtlRunningStopS > 0 && r.inflight == 0 &&
			now.Sub(r.lastActive) > time.Duration(spec.TtlRunningStopS)*time.Second:
			if spec.TtlPausedS > 0 {
				pause = append(pause, job{r, "idle timeout (ttl_running_stop) reached"})
			} else {
				expire = append(expire, job{r, "idle timeout (ttl_running_stop) reached"})
			}
		case r.sb.State == pb.SandboxState_RUNNING:
			probe = append(probe, job{r, ""})
		}
	}
	e.mu.Unlock()

	for _, r := range unsaved {
		e.persist(r)
	}
	for _, r := range abandoned {
		e.clearMoving(r)
	}
	for _, j := range expire {
		go e.stop(context.WithoutCancel(ctx), j.r, j.msg)
	}
	for _, j := range pause {
		go e.autoPause(context.WithoutCancel(ctx), j.r, j.msg)
	}
	for _, j := range probe {
		if !e.backends[j.r.sb.Spec.Backend].Probe(ctx, e.bsb(j.r)) {
			e.fail(j.r, "sandbox lost (liveness probe failed)")
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
