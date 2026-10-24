// Package backend defines the interface between edge-core and a sandbox
// runtime. P1 ships only the sim backend; container / fncall / microvm /
// fullvm implement the same interface in later phases.
package backend

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/images"
)

// Sandbox is what a backend sees of a sandbox.
type Sandbox struct {
	ID      string
	Project string
	Spec    *pb.SandboxSpec
	State   pb.SandboxState // last persisted state (set for Adopt)
	// Net is the sandbox's network (spec §20), nil without networking: the
	// backend calls Net.Setup when it has the sandbox's namespace.
	Net *netpol.Attachment
	// Peer, when set, is the edge holding the files of Spec.Snapshot if they
	// are not in the image store (spec §26).
	Peer SnapshotPeer
}

type Backend interface {
	Name() string
	Create(ctx context.Context, sb *Sandbox) error
	Stop(ctx context.Context, sb *Sandbox) error
	Pause(ctx context.Context, sb *Sandbox) error
	Resume(ctx context.Context, sb *Sandbox) error
	// Probe reports whether the sandbox is still alive.
	Probe(ctx context.Context, sb *Sandbox) bool
}

// Runtime is implemented by backends whose sandboxes serve the Runtime API
// (exec, files, ...) through aether.
type Runtime interface {
	Runtime(id string) (pb.RuntimeClient, error)
}

// LossReporter is implemented by backends that detect sandbox death on their
// own (e.g. the aether channel closing). The edge registers a callback.
type LossReporter interface {
	OnLost(func(id, reason string))
}

// Versioned is implemented by backends that run on versioned runtime
// binaries (spec §28.12), e.g. {"firecracker": "1.17.0"}.
type Versioned interface {
	RuntimeVersions() map[string]string
}

// ImageLister is implemented by backends that can only run a fixed set of
// locally configured images. Images returns nil when any image is runnable
// (e.g. a shared image store).
type ImageLister interface {
	Images() []string
}

// Packer is implemented by backends that can snapshot a sandbox's writable
// layer into the shared image store (pack_diff, spec §17.4).
type Packer interface {
	PackDiff(ctx context.Context, sb *Sandbox, layerID string, scrub []string) (*images.LayerMeta, error)
}

// Snapshotter is implemented by backends that can snapshot a running sandbox
// for fork and CreateSnapshot (spec §19). Snapshot records snapshot id in
// the image store, so any edge sharing the store can start copies of it
// (spec.snapshot). Backends without memory snapshots reject memory=true.
type Snapshotter interface {
	Snapshot(ctx context.Context, sb *Sandbox, id string, memory bool) (*images.Snapshot, error)
	MemorySnapshots() bool
}

// PeerSnapshotter is implemented by backends whose memory snapshots can stay
// on the edge that took them (spec §26): ephemeral ones, only needed to start
// copies now, which other edges fetch from that edge instead of the store.
type PeerSnapshotter interface {
	// SnapshotHeld is Snapshot with memory, keeping the files on this edge;
	// the store's record names the edge (Snapshot.Holder).
	SnapshotHeld(ctx context.Context, sb *Sandbox, id string) (*images.Snapshot, error)
	// SnapshotFile returns the path of file name of a snapshot held here,
	// and its content id ("" unless the file is an immutable disk).
	SnapshotFile(id, name string) (path, contentID string, err error)
}

// SnapshotPeer fetches files of a snapshot another edge holds.
type SnapshotPeer interface {
	// FetchFile copies file name of snapshot id to dst and returns its
	// content id. reuse, if set, is offered the content id first: a path it
	// returns is linked to dst instead of transferring the file.
	FetchFile(ctx context.Context, id, name, dst string, reuse func(contentID string) string) (string, error)
}

// SnapshotCacher is implemented by backends keeping node-local copies of
// store snapshots; CachedSnapshots lists them for placement.
type SnapshotCacher interface {
	CachedSnapshots() []string
}

// Networked is implemented by backends whose sandboxes get a network when
// the edge has networking (spec §20). VM reports whether the network is
// set up for a microVM (a tap in the namespace).
type Networked interface {
	NetworkVM() bool
}

// MemoryReleasingPause is implemented by backends whose pause can give a
// sandbox's memory back to the node (paused_mem_charge, spec §24).
type MemoryReleasingPause interface {
	PauseReleasesMemory() bool
}

// Squeezer is implemented by backends that can take memory back from a
// running sandbox (a balloon, spec §24): Squeeze sets how much (MB; 0
// gives it all back).
type Squeezer interface {
	Squeeze(ctx context.Context, sb *Sandbox, mb int64) error
}

// Adopter is implemented by backends whose sandboxes outlive the edge
// process. Adopt reattaches to a sandbox created by a previous edge process
// and reports whether it is paused (spec §13.3).
type Adopter interface {
	Adopt(ctx context.Context, sb *Sandbox) (paused bool, err error)
}

// Cleaner removes node-local leftovers of sandboxes that were not adopted.
type Cleaner interface {
	CleanupExcept(keep map[string]bool)
}

// Sim simulates a runtime: operations take a lognormal-distributed latency and
// creation fails with a configurable probability. No processes are started.
type Sim struct {
	name   string
	median time.Duration
	sigma  float64
	fail   float64
	// Dead, if set, makes Probe report the sandbox as gone (fault injection).
	Dead func(id string) bool

	squeezeMu sync.Mutex
	Squeezed  map[string]int64 // balloon sizes asked for (Squeeze)
}

func NewSim(name string, cfg config.Backend) *Sim {
	return &Sim{
		name:   name,
		median: time.Duration(cfg.CreateLatencyMs * float64(time.Millisecond)),
		sigma:  cfg.LatencySigma,
		fail:   cfg.FailureRate,
	}
}

func (s *Sim) Name() string { return s.name }

func (s *Sim) delay(ctx context.Context, scale float64) error {
	if s.median <= 0 {
		return nil
	}
	d := time.Duration(float64(s.median) * scale * math.Exp(s.sigma*rand.NormFloat64()))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var ErrSimFailure = simError("sim: injected creation failure")

type simError string

func (e simError) Error() string { return string(e) }

func (s *Sim) Create(ctx context.Context, _ *Sandbox) error {
	if err := s.delay(ctx, 1); err != nil {
		return err
	}
	if s.fail > 0 && rand.Float64() < s.fail {
		return ErrSimFailure
	}
	return nil
}

func (s *Sim) Stop(ctx context.Context, _ *Sandbox) error   { return s.delay(ctx, 0.2) }
func (s *Sim) Pause(ctx context.Context, _ *Sandbox) error  { return s.delay(ctx, 0.5) }
func (s *Sim) Resume(ctx context.Context, _ *Sandbox) error { return s.delay(ctx, 0.5) }

// Snapshot takes as long as a pause; sim snapshots have no content and are
// not recorded anywhere, and every sim backend accepts memory snapshots.
func (s *Sim) Snapshot(ctx context.Context, _ *Sandbox, id string, memory bool) (*images.Snapshot, error) {
	if err := s.delay(ctx, 0.5); err != nil {
		return nil, err
	}
	return &images.Snapshot{ID: id, Memory: memory}, nil
}

func (s *Sim) MemorySnapshots() bool { return true }

// SnapshotHeld: sim snapshots have no files, so a held one is any snapshot
// (moving sim sandboxes exercises the control plane, spec §26).
func (s *Sim) SnapshotHeld(ctx context.Context, sb *Sandbox, id string) (*images.Snapshot, error) {
	return s.Snapshot(ctx, sb, id, true)
}

func (s *Sim) SnapshotFile(id, name string) (string, string, error) {
	return "", "", fmt.Errorf("sim snapshot %s has no file %s", id, name)
}

// Squeeze records the balloon size asked for (tests).
func (s *Sim) Squeeze(_ context.Context, sb *Sandbox, mb int64) error {
	s.squeezeMu.Lock()
	defer s.squeezeMu.Unlock()
	if s.Squeezed == nil {
		s.Squeezed = map[string]int64{}
	}
	s.Squeezed[sb.ID] = mb
	return nil
}

// SqueezedMB is the balloon size last asked for sb.
func (s *Sim) SqueezedMB(id string) int64 {
	s.squeezeMu.Lock()
	defer s.squeezeMu.Unlock()
	return s.Squeezed[id]
}

// PauseReleasesMemory: sim sandboxes stand for microVMs here.
func (s *Sim) PauseReleasesMemory() bool { return true }

// Adopt always succeeds: sim sandboxes have no node state to reattach to,
// so the persisted state is taken as-is.
func (s *Sim) Adopt(_ context.Context, sb *Sandbox) (bool, error) {
	return sb.State == pb.SandboxState_PAUSED, nil
}

func (s *Sim) Probe(_ context.Context, sb *Sandbox) bool {
	return s.Dead == nil || !s.Dead(sb.ID)
}
