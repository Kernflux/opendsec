// Package watcher probes edge health and aggregates scheduling state for the
// placement engines (paper §3, spec §3.5). It holds no durable state: after a
// restart it rebuilds its view from the configured edge list, from edges
// re-registering, and by polling them.
//
// It also drives IAM lease reconciliation, since it is the one component that
// sees every edge's live sandboxes.
package watcher

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

type entry struct {
	id, addr, zone string
	state          *pb.EdgeState
	healthy        bool
	fails          int
	lastSeen       float64
	downSince      time.Time // when it last became unhealthy (zero while healthy)
}

type Watcher struct {
	cfg  config.Watcher
	pool *rpcutil.Pool
	iam  pb.IAMClient // nil disables reconcile
	log  *slog.Logger
	// Holder identifies this instance for the reconcile lock; "" means a
	// single watcher that always reconciles.
	Holder string
	// Peers are the other watcher replicas: a watcher starting takes the
	// edges they know (seedFromPeers).
	Peers []pb.WatcherClient

	leaderUntil atomic.Int64 // unix nanos (local monotonic-derived) until which we hold the lock

	mu      sync.Mutex
	edges   map[string]*entry
	version int64
	snap    atomic.Pointer[pb.Snapshot]
}

func New(cfg config.Watcher, edges []config.Edge, pool *rpcutil.Pool, iam pb.IAMClient, log *slog.Logger) *Watcher {
	w := &Watcher{cfg: cfg, pool: pool, iam: iam, log: log, edges: map[string]*entry{}}
	for _, e := range edges {
		w.edges[e.ID] = &entry{id: e.ID, addr: e.Addr, zone: e.Zone}
	}
	w.snap.Store(&pb.Snapshot{})
	return w
}

// seedFromPeers registers the edges the other watchers know. Edges of the
// edge template are known only from their registrations, every 10 s: a
// watcher that just started would otherwise publish snapshots without them,
// and calls to their sandboxes through an apiserver that just started too
// would fail as not_found. Edges probe as usual from here; a peer that
// does not answer within 2 s is skipped (a whole cluster starting).
func (w *Watcher) seedFromPeers(ctx context.Context) {
	if len(w.Peers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, p := range w.Peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap, err := p.GetSnapshot(ctx, &pb.Empty{})
			if err != nil {
				return
			}
			for _, e := range snap.Edges {
				w.mu.Lock()
				known := w.edges[e.Id] != nil
				w.mu.Unlock()
				if !known {
					w.Register(e.Id, e.Addr, e.Zone)
				}
			}
		}()
	}
	wg.Wait()
}

// Register adds or updates an edge (edges re-register periodically).
func (w *Watcher) Register(id, addr, zone string) error {
	if !ids.ValidEdgeID(id) || addr == "" {
		return rpcutil.Err(rpcutil.Invalid, "bad edge registration %q %q", id, addr)
	}
	if zone == "" {
		zone = "onprem"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.edges[id]; e != nil {
		e.addr, e.zone = addr, zone
		return nil
	}
	w.edges[id] = &entry{id: id, addr: addr, zone: zone}
	w.log.Info("edge registered", "edge", id, "addr", addr, "zone", zone)
	return nil
}

func (w *Watcher) Snapshot() *pb.Snapshot { return w.snap.Load() }

// ReconcileLock is the IAM lock name watchers elect a reconciler with.
const ReconcileLock = "watcher-reconcile"

func (w *Watcher) Run(ctx context.Context) {
	probe := time.NewTicker(config.Seconds(w.cfg.ProbeInterval))
	defer probe.Stop()
	reconcile := time.NewTicker(config.Seconds(w.cfg.ReconcileInterval))
	defer reconcile.Stop()
	if w.Holder != "" && w.iam != nil {
		go w.elect(ctx)
	}
	w.seedFromPeers(ctx)
	w.ProbeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-probe.C:
			w.ProbeAll(ctx)
		case <-reconcile.C:
			if w.IsLeader() {
				w.Reconcile(ctx)
			}
		}
	}
}

// fence makes IAM apply a reconcile only while this instance holds the
// reconcile lock: one paused past its lease, with an old view of an edge,
// must not release what the new leader keeps (spec §16.1).
func (w *Watcher) fence() *pb.Fence {
	if w.Holder == "" {
		return nil
	}
	return &pb.Fence{Lock: ReconcileLock, Holder: w.Holder}
}

// IsLeader reports whether this instance may reconcile now.
func (w *Watcher) IsLeader() bool {
	if w.Holder == "" {
		return true
	}
	return time.Now().UnixNano() < w.leaderUntil.Load()
}

// elect keeps trying to hold the reconcile lock, renewing every ttl/3. The
// lease is trusted until (local time at the request) + ttl - 2s, so clock
// differences with IAM never extend it. On shutdown the lock is released so
// another instance takes over at once.
func (w *Watcher) elect(ctx context.Context) {
	ttl := config.Seconds(w.cfg.LockTTL)
	margin := min(2*time.Second, ttl/4)
	t := time.NewTicker(ttl / 3)
	defer t.Stop()
	for {
		sent := time.Now()
		cctx, cancel := context.WithTimeout(ctx, ttl/3)
		r, err := w.iam.AcquireLock(cctx, &pb.LockRequest{Name: ReconcileLock, Holder: w.Holder, TtlS: ttl.Seconds()})
		cancel()
		was := w.IsLeader()
		switch {
		case err != nil:
			if ctx.Err() == nil {
				w.log.Warn("reconcile lock: renew failed", "err", err)
			}
		case r.Acquired:
			w.leaderUntil.Store(sent.Add(ttl - margin).UnixNano())
			if !was {
				w.log.Info("reconcile leader", "holder", w.Holder)
			}
		default:
			w.leaderUntil.Store(0)
			if was {
				w.log.Info("lost reconcile leadership", "holder", w.Holder, "now", r.Holder)
			}
		}
		select {
		case <-ctx.Done():
			if w.IsLeader() {
				rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				w.iam.ReleaseLock(rctx, &pb.LockRequest{Name: ReconcileLock, Holder: w.Holder})
				cancel()
			}
			w.leaderUntil.Store(0)
			return
		case <-t.C:
		}
	}
}

func (w *Watcher) entries() []*entry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*entry, 0, len(w.edges))
	for _, e := range w.edges {
		out = append(out, e)
	}
	return out
}

func (w *Watcher) status(ctx context.Context, e *entry, leases bool, timeout time.Duration) (*pb.EdgeStatusResponse, error) {
	conn, err := w.pool.GetEdge(e.addr, e.id)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return pb.NewEdgeClient(conn).Status(cctx, &pb.EdgeStatusRequest{IncludeLeases: leases})
}

// ProbeAll polls every edge once and publishes a new snapshot.
func (w *Watcher) ProbeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range w.entries() {
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			sent := rpcutil.Now() // edge's report reflects everything admitted before this
			resp, err := w.status(ctx, e, false, config.Seconds(w.cfg.ProbeTimeout))
			w.mu.Lock()
			defer w.mu.Unlock()
			if err != nil {
				e.fails++
				if e.healthy && e.fails >= w.cfg.UnhealthyAfter {
					e.healthy = false
					e.downSince = time.Now()
					w.log.Warn("edge unhealthy", "edge", e.id, "err", err)
				}
				if !e.healthy && e.downSince.IsZero() { // never seen healthy since we started
					e.downSince = time.Now()
				}
				return
			}
			if resp.State.GetId() != e.id {
				e.fails++
				w.log.Warn("edge id mismatch", "want", e.id, "got", resp.State.GetId())
				return
			}
			if !e.healthy {
				w.log.Info("edge healthy", "edge", e.id)
			}
			e.fails, e.healthy, e.state, e.lastSeen, e.downSince = 0, true, resp.State, sent, time.Time{}
		}(e)
	}
	wg.Wait()
	w.publish()
}

func (w *Watcher) publish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.version++
	s := &pb.Snapshot{Version: w.version, TakenAt: rpcutil.Now()}
	for _, e := range w.edges {
		var st *pb.EdgeState
		if e.state != nil {
			st = proto.Clone(e.state).(*pb.EdgeState)
		} else {
			st = &pb.EdgeState{Id: e.id}
		}
		st.Addr, st.Zone, st.Healthy, st.LastSeen = e.addr, e.zone, e.healthy, e.lastSeen
		s.Edges = append(s.Edges, st)
	}
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].Id < s.Edges[j].Id })
	w.snap.Store(s)
}

// Reconcile aligns IAM's quota leases with what each edge actually runs
// (spec §15.2). Edges are reconciled independently: one unreachable edge only
// skips itself. An edge that has been unhealthy for longer than
// lost_edge_grace is reconciled as empty, releasing its quota (if it comes
// back with its sandboxes, the next pass re-adopts them). Finally leases no
// edge ever claimed are swept.
func (w *Watcher) Reconcile(ctx context.Context) {
	if w.iam == nil {
		return
	}
	grace := config.Seconds(w.cfg.LostEdgeGrace)
	minAge := w.cfg.ReconcileMinAge
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, e := range w.entries() {
		w.mu.Lock()
		healthy, down := e.healthy, e.downSince
		w.mu.Unlock()
		if !healthy && (down.IsZero() || time.Since(down) < grace) {
			continue // maybe just restarting: keep its quota for now
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(e *entry, healthy bool) {
			defer func() { <-sem; wg.Done() }()
			var live []*pb.LeaseInfo
			if healthy {
				resp, err := w.status(ctx, e, true, 10*time.Second)
				if err != nil {
					w.log.Warn("reconcile: edge unreachable, skipped", "edge", e.id, "err", err)
					return
				}
				live = resp.Leases
			}
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			r, err := w.iam.ReconcileEdge(cctx, &pb.ReconcileEdgeRequest{Edge: e.id, Live: live, MinAgeS: minAge, Fence: w.fence()})
			if err != nil {
				w.log.Warn("reconcile edge failed", "edge", e.id, "err", err)
				return
			}
			if r.Adopted+r.Released+r.Conflicts > 0 {
				w.log.Info("leases reconciled", "edge", e.id, "live", len(live), "adopted", r.Adopted,
					"bound", r.Bound, "released", r.Released, "conflicts", r.Conflicts, "edge_lost", !healthy)
			}
		}(e, healthy)
	}
	wg.Wait()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if r, err := w.iam.SweepUnbound(cctx, &pb.SweepUnboundRequest{MaxAgeS: w.cfg.UnboundMaxAge, Fence: w.fence()}); err != nil {
		w.log.Warn("sweep unbound leases failed", "err", err)
	} else if r.Released > 0 {
		w.log.Info("released leases no edge claimed", "count", r.Released)
	}
}

// Service exposes the watcher over gRPC.
type Service struct {
	pb.UnimplementedWatcherServer
	W *Watcher
}

func (s *Service) GetSnapshot(context.Context, *pb.Empty) (*pb.Snapshot, error) {
	return s.W.Snapshot(), nil
}

func (s *Service) Register(ctx context.Context, r *pb.RegisterEdgeRequest) (*pb.Empty, error) {
	// With mTLS an edge may only register itself (spec §14.1).
	if id, ok := rpcutil.PeerIdentity(ctx); ok && (id.Role != pki.RoleEdge || id.ID != r.Id) {
		return nil, rpcutil.Err(rpcutil.Forbidden, "%s may not register edge %q", id, r.Id)
	}
	return &pb.Empty{}, s.W.Register(r.Id, r.Addr, r.Zone)
}
