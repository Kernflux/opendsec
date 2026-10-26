package fleet

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// LeaderLock is the IAM lock the fleet replicas elect a leader with.
const LeaderLock = "fleet-controller"

// ActorKey carries the authenticated caller from the apiserver's FleetAdmin
// proxy (and from a forwarding replica) to the leader.
const ActorKey = "x-opendsec-actor"

// Options configure one fleet replica.
type Options struct {
	ID      string
	Cfg     config.Fleet
	KV      KV
	IAM     pb.IAMClient     // leader lock
	Watcher pb.WatcherClient // edge health for rollouts; nil in tests without edges
	Pool    *rpcutil.Pool    // peers and edges
	Log     *slog.Logger
	Now     func() time.Time
	// Tick is the controller period; default 1s.
	Tick time.Duration
}

// Server is a fleet replica. Every replica serves releases and forwards
// heartbeats and management calls to the leader, the holder of the IAM
// lock; only the leader runs the controller.
type Server struct {
	pb.UnimplementedFleetServer
	pb.UnimplementedFleetAdminServer

	opt      Options
	store    *Store
	releases *releaseStore
	log      *slog.Logger
	peers    map[string]string // replica id -> addr

	leaderUntil atomic.Int64 // unix nanos until which this replica holds the lock
	leaderSince atomic.Int64 // unix nanos when it took it
	leaderID    atomic.Value // string: last known holder id
	lastLockOK  atomic.Int64 // unix nanos of the last successful lock call

	// ctl serializes controller rounds with management calls that act on
	// nodes directly (cordon drains an edge; a round re-drains cordoned ones).
	ctl sync.Mutex

	mu   sync.Mutex
	hb   map[string]*heartbeat // node -> last heartbeat (leader only)
	ops  map[string]*pb.NodeOp // node -> operation to hand out
	snap *pb.Snapshot          // last watcher snapshot

	nodesCache   []rec[*pb.FleetNode]
	nodesAt      time.Time
	nodesInvalid bool

	rolloutStat struct { // for metrics, under mu
		state    string
		progress float64
	}

	rolloutSeq atomic.Int64
	kick       chan struct{}
}

type heartbeat struct {
	addr   string
	status *pb.NodeStatus
	at     time.Time
}

func New(opt Options) (*Server, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Tick == 0 {
		opt.Tick = time.Second
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	dir := ""
	s := &Server{opt: opt, store: NewStore(opt.KV), log: opt.Log, peers: map[string]string{},
		hb: map[string]*heartbeat{}, ops: map[string]*pb.NodeOp{}, kick: make(chan struct{}, 1)}
	for _, r := range opt.Cfg.Replicas {
		s.peers[r.ID] = r.Addr
		if r.ID == opt.ID {
			dir = r.DataDir
		}
	}
	if dir == "" {
		return nil, errors.New("fleet: replica not in config")
	}
	rs, err := newReleaseStore(dir, opt.Cfg.MaxDownloads)
	if err != nil {
		return nil, err
	}
	s.releases = rs
	s.leaderID.Store("")
	return s, nil
}

func (s *Server) now() time.Time { return s.opt.Now() }
func (s *Server) unix() float64  { return float64(s.now().UnixNano()) / 1e9 }

// IsLeader reports whether this replica holds the leader lock.
func (s *Server) IsLeader() bool { return time.Now().UnixNano() < s.leaderUntil.Load() }

// Ready: the replica reached IAM recently (it can elect and read state).
func (s *Server) Ready() error {
	ttl := config.Seconds(s.opt.Cfg.LockTTL)
	if time.Since(time.Unix(0, s.lastLockOK.Load())) > 3*ttl {
		return errors.New("no recent answer from IAM")
	}
	return nil
}

// Run elects, runs the controller while leading, and collects old releases.
func (s *Server) Run(ctx context.Context) {
	go s.elect(ctx)
	go s.gcLoop(ctx)
	t := time.NewTicker(s.opt.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		if s.IsLeader() {
			tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			s.ctl.Lock()
			// The round's writes apply only while this replica still
			// holds the leader lock: one paused past its lease cannot
			// overwrite the new leader's records or hand out operations.
			s.tick(WithFence(tctx, &pb.Fence{Lock: LeaderLock, Holder: s.holder()}))
			s.ctl.Unlock()
			cancel()
		}
	}
}

// Kick runs a controller round soon (after a management change).
func (s *Server) Kick() {
	s.mu.Lock()
	s.nodesInvalid = true
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Server) holder() string { return "fleet/" + s.opt.ID }

// elect keeps trying to hold the leader lock, as the watchers do (spec
// §16.1): renew every ttl/3, trust the lease until ttl - margin after the
// request was sent, release it on shutdown.
func (s *Server) elect(ctx context.Context) {
	ttl := config.Seconds(s.opt.Cfg.LockTTL)
	margin := min(2*time.Second, ttl/4)
	t := time.NewTicker(ttl / 3)
	defer t.Stop()
	for {
		sent := time.Now()
		cctx, cancel := context.WithTimeout(ctx, ttl/3)
		r, err := s.opt.IAM.AcquireLock(cctx, &pb.LockRequest{Name: LeaderLock, Holder: s.holder(), TtlS: ttl.Seconds()})
		cancel()
		was := s.IsLeader()
		switch {
		case err != nil:
			if ctx.Err() == nil {
				s.log.Warn("leader lock: renew failed", "err", err)
			}
		default:
			s.lastLockOK.Store(time.Now().UnixNano())
			if r.Acquired {
				if !was {
					s.becomeLeader()
				}
				s.leaderUntil.Store(sent.Add(ttl - margin).UnixNano())
				s.leaderID.Store(s.opt.ID)
			} else {
				s.leaderUntil.Store(0)
				s.leaderID.Store(trimHolder(r.Holder))
				if was {
					s.log.Info("lost fleet leadership", "now", r.Holder)
				}
			}
		}
		select {
		case <-ctx.Done():
			if s.IsLeader() {
				rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				s.opt.IAM.ReleaseLock(rctx, &pb.LockRequest{Name: LeaderLock, Holder: s.holder()})
				cancel()
			}
			s.leaderUntil.Store(0)
			return
		case <-t.C:
		}
	}
}

func trimHolder(h string) string {
	if len(h) > 6 && h[:6] == "fleet/" {
		return h[6:]
	}
	return h
}

func (s *Server) becomeLeader() {
	s.mu.Lock()
	s.hb = map[string]*heartbeat{} // rebuilt from the agents within one interval
	s.ops = map[string]*pb.NodeOp{}
	s.nodesInvalid = true
	s.mu.Unlock()
	s.leaderSince.Store(time.Now().UnixNano())
	s.log.Info("fleet leader", "replica", s.opt.ID)
}

// warm reports whether the leader has led long enough to have heard from
// the agents (two heartbeat intervals); until then it only listens.
func (s *Server) warm() bool {
	return time.Since(time.Unix(0, s.leaderSince.Load())) >= 2*config.Seconds(s.opt.Cfg.Heartbeat)
}

// leaderConn returns a connection to the leader replica, or an error when
// none is known.
func (s *Server) leaderConn() (pb.FleetClient, pb.FleetAdminClient, error) {
	id, _ := s.leaderID.Load().(string)
	addr := s.peers[id]
	if id == "" || addr == "" || id == s.opt.ID {
		return nil, nil, rpcutil.Err(rpcutil.Unavailable, "fleet: no leader elected yet")
	}
	conn, err := s.opt.Pool.Get(addr)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewFleetClient(conn), pb.NewFleetAdminClient(conn), nil
}

// forwardCtx passes the caller's actor along to the leader.
func forwardCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, ActorKey, actorOf(ctx))
}

// actorOf returns who is calling: the actor the apiserver (or a forwarding
// replica) vouches for, or the operator certificate's identity.
func actorOf(ctx context.Context) string {
	id, ok := rpcutil.PeerIdentity(ctx)
	if ok && id.Role == pki.RoleOps {
		return id.String()
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(ActorKey); len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	if ok {
		return id.String()
	}
	return "unknown"
}

// ---- heartbeats -------------------------------------------------------------------

func (s *Server) Heartbeat(ctx context.Context, r *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if id, ok := rpcutil.PeerIdentity(ctx); ok && id.Role != pki.RoleFleet && (id.Role != pki.RoleNode || id.ID != r.Node) {
		return nil, rpcutil.Err(rpcutil.Forbidden, "%s may not report for node %q", id, r.Node)
	}
	if !validName(r.Node) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad node name %q", r.Node)
	}
	if !s.IsLeader() {
		c, _, err := s.leaderConn()
		if err != nil {
			return nil, err
		}
		return c.Heartbeat(ctx, r)
	}
	st := proto.Clone(r.Status).(*pb.NodeStatus)
	if st == nil {
		st = &pb.NodeStatus{}
	}
	st.LastSeen = s.unix()
	s.mu.Lock()
	_, known := s.hb[r.Node]
	s.hb[r.Node] = &heartbeat{addr: r.Addr, status: st, at: s.now()}
	op := s.ops[r.Node]
	s.mu.Unlock()
	resp := &pb.HeartbeatResponse{IntervalS: s.opt.Cfg.Heartbeat, Op: op}
	n, ok, err := s.store.Node(ctx, r.Node)
	if err != nil {
		return nil, err
	}
	if !ok {
		// First report of a new machine: it waits as pending until an
		// operator accepts it (spec §28.7).
		nn := &pb.FleetNode{Name: r.Node, Addr: r.Addr, State: "pending", CreatedAt: s.unix(), CreatedBy: "agent",
			Message: "waiting for opendsecctl fleet node accept"}
		if _, err := s.store.PutNode(ctx, nn, 0); err != nil && rpcutil.Reason(err) != rpcutil.Conflict {
			return nil, err
		}
		s.log.Info("new node reported", "node", r.Node, "addr", r.Addr)
		s.Kick()
		resp.State = "pending"
		return resp, nil
	}
	resp.State = n.V.State
	resp.Units = nodeUnits(n.V, s.opt.Cfg.ReadyPorts)
	if !known || (op != nil && st.Op.GetOpId() == op.OpId && st.Op.GetState() != "running") {
		s.Kick() // an operation finished: act on it now
	}
	return resp, nil
}

// statusOf returns the last heartbeat of node (nil if none recent).
func (s *Server) statusOf(node string) *pb.NodeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hb[node]
	if h == nil {
		return nil
	}
	return h.status
}

// fresh reports whether node reported within three heartbeat intervals.
func (s *Server) fresh(node string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hb[node]
	return h != nil && s.now().Sub(h.at) < 3*config.Seconds(s.opt.Cfg.Heartbeat)
}

// nodes returns every node record, cached for a few seconds (the leader is
// the only writer besides management calls, which invalidate the cache).
func (s *Server) nodes(ctx context.Context) ([]rec[*pb.FleetNode], error) {
	s.mu.Lock()
	if !s.nodesInvalid && s.nodesCache != nil && s.now().Sub(s.nodesAt) < 5*time.Second {
		c := s.nodesCache
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.nodesCache, s.nodesAt, s.nodesInvalid = ns, s.now(), false
	s.mu.Unlock()
	return ns, nil
}

func (s *Server) setOps(ops map[string]*pb.NodeOp) {
	s.mu.Lock()
	s.ops = ops
	s.mu.Unlock()
}

// withStatus returns n with its last heartbeat attached.
func (s *Server) withStatus(n *pb.FleetNode) *pb.FleetNode {
	c := proto.Clone(n).(*pb.FleetNode)
	if st := s.statusOf(n.Name); st != nil {
		c.Status = proto.Clone(st).(*pb.NodeStatus)
	}
	return c
}

// ---- metrics ------------------------------------------------------------------------

// Stats is what the fleet metrics report (leader only; zero elsewhere).
type Stats struct {
	Leader       bool
	Nodes        map[[2]string]int // {state, domain} -> nodes
	Releases     map[string]int    // current release -> nodes
	MaxHBAge     float64
	RolloutState string
	Progress     float64 // finished steps / steps of the active rollout
}

func (s *Server) Stats() Stats {
	st := Stats{Leader: s.IsLeader(), Nodes: map[[2]string]int{}, Releases: map[string]int{}}
	if !st.Leader {
		return st
	}
	s.mu.Lock()
	ns := s.nodesCache
	now := s.now()
	for _, n := range ns {
		st.Nodes[[2]string{n.V.State, n.V.Domain}]++
		if n.V.State != "active" && n.V.State != "cordoned" {
			continue
		}
		if h := s.hb[n.V.Name]; h != nil {
			st.Releases[h.status.CurrentRelease]++
			st.MaxHBAge = max(st.MaxHBAge, now.Sub(h.at).Seconds())
		} else {
			st.MaxHBAge = max(st.MaxHBAge, now.Sub(time.Unix(0, s.leaderSince.Load())).Seconds())
		}
	}
	st.RolloutState, st.Progress = s.rolloutStat.state, s.rolloutStat.progress
	s.mu.Unlock()
	return st
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
