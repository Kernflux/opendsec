package fleet

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// memKV is the IAM key-value area in memory; puts of keys fail(key) says
// fail, and lists of keys with prefix slow answer late (what they read
// may be stale by then).
type memKV struct {
	mu   sync.Mutex
	m    map[string]*pb.KVEntry
	rev  uint64
	fail func(key string) bool
	slow string
}

func (k *memKV) Get(_ context.Context, key string) (*pb.KVEntry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e := k.m[key]; e != nil {
		return proto.Clone(e).(*pb.KVEntry), nil
	}
	return &pb.KVEntry{Key: key}, nil
}

func (k *memKV) List(_ context.Context, prefix string) ([]*pb.KVEntry, error) {
	if k.slow != "" && strings.HasPrefix(prefix, k.slow) {
		defer time.Sleep(50 * time.Millisecond)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []*pb.KVEntry
	for key, e := range k.m {
		if strings.HasPrefix(key, prefix) {
			out = append(out, proto.Clone(e).(*pb.KVEntry))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (k *memKV) Put(_ context.Context, key string, value []byte, check bool, rev uint64) (*pb.KVEntry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil && k.fail(key) {
		return nil, rpcutil.Err(rpcutil.Unavailable, "injected: %s", key)
	}
	if cur := k.m[key]; check && cur.GetRev() != rev {
		return nil, rpcutil.Err(rpcutil.Conflict, "%s at rev %d, not %d", key, cur.GetRev(), rev)
	}
	k.rev++
	e := &pb.KVEntry{Key: key, Value: value, Rev: k.rev}
	k.m[key] = e
	return proto.Clone(e).(*pb.KVEntry), nil
}

func (k *memKV) Delete(_ context.Context, key string, _ bool, _ uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

// ctlFixture is a leader replica's controller over memKV, with the node
// agents simulated through heartbeats.
type ctlFixture struct {
	t      *testing.T
	s      *Server
	kv     *memKV
	now    time.Time
	ops    map[string]*pb.NodeOp // handed out in the last round
	handed []string              // every operation id handed out, in order
}

func newCtl(t *testing.T, nodes ...*pb.FleetNode) *ctlFixture {
	f := &ctlFixture{t: t, kv: &memKV{m: map[string]*pb.KVEntry{}}, now: time.Unix(1_800_000_000, 0)}
	f.s = &Server{opt: Options{Now: func() time.Time { return f.now }, Cfg: config.Fleet{Heartbeat: 10}},
		store: NewStore(f.kv), log: slog.New(slog.NewTextHandler(io.Discard, nil)), peers: map[string]string{},
		hb: map[string]*heartbeat{}, ops: map[string]*pb.NodeOp{}, kick: make(chan struct{}, 1)}
	ctx := context.Background()
	for _, gen := range []uint64{1, 2} {
		if _, err := f.s.store.AddConfig(ctx, &pb.FleetConfig{Gen: gen, ClusterJson: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range nodes {
		n.State, n.ConfigGen = "active", 1
		if _, err := f.s.store.PutNode(ctx, n, 0); err != nil {
			t.Fatal(err)
		}
		f.beat(n.Name, nil, unitsOf(n)...)
	}
	return f
}

func unitsOf(n *pb.FleetNode) []string {
	var out []string
	for _, u := range nodeUnits(n, nil) {
		out = append(out, u.Unit)
	}
	return out
}

// beat records a heartbeat of node: op's result (nil: none) and its units,
// all ready.
func (f *ctlFixture) beat(node string, op *pb.OpStatus, units ...string) {
	st := &pb.NodeStatus{Op: op}
	for _, u := range units {
		st.Units = append(st.Units, &pb.UnitStatus{Unit: u, ActiveState: "active", Ready: true})
	}
	f.s.mu.Lock()
	f.s.hb[node] = &heartbeat{status: st, at: f.now}
	f.s.mu.Unlock()
}

// finish reports node's operation of the last round as done in state.
func (f *ctlFixture) finish(node, state string) {
	f.t.Helper()
	op := f.ops[node]
	if op == nil {
		f.t.Fatalf("no operation for %s", node)
	}
	f.beat(node, &pb.OpStatus{OpId: op.OpId, State: state}, unitNames(op.Units)...)
}

func unitNames(us []*pb.NodeUnit) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.Unit)
	}
	return out
}

func (f *ctlFixture) create(nodes []string, st *pb.FleetStrategy) *pb.FleetRollout {
	f.t.Helper()
	ctx := context.Background()
	var picked []*pb.FleetNode
	for _, name := range nodes {
		n, _, err := f.s.store.Node(ctx, name)
		if err != nil {
			f.t.Fatal(err)
		}
		picked = append(picked, n.V)
	}
	ro, err := f.s.createRollout(ctx, &pb.FleetCreateRolloutRequest{ConfigGen: 2}, picked, Strategy(st, len(nodes)), false, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return ro
}

// round runs one controller round of the rollout and returns it as stored.
func (f *ctlFixture) round(id string) *pb.FleetRollout {
	f.t.Helper()
	ctx := context.Background()
	rr, _, err := f.s.store.Rollout(ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	ns, err := f.s.store.Nodes(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	byName := map[string]rec[*pb.FleetNode]{}
	for _, n := range ns {
		byName[n.V.Name] = n
	}
	f.ops = map[string]*pb.NodeOp{}
	if active(rr.V.State) {
		f.s.driveRollout(ctx, rr, byName, f.ops, map[string]bool{})
	}
	for _, name := range sortedKeys(f.ops) {
		f.handed = append(f.handed, f.ops[name].OpId)
	}
	rr, _, _ = f.s.store.Rollout(ctx, id)
	return rr.V
}

func (f *ctlFixture) step(id, node string) *pb.FleetStep {
	f.t.Helper()
	steps, err := f.s.store.Steps(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, x := range steps {
		if x.V.Node == node {
			return x.V
		}
	}
	f.t.Fatalf("no step for %s", node)
	return nil
}

func failing(prefix string) func(string) bool {
	return func(key string) bool { return strings.HasPrefix(key, prefix) }
}

// toApplying runs rounds until node's step is applying (its apply handed out).
func (f *ctlFixture) toApplying(id, node string) {
	f.t.Helper()
	for range 5 {
		f.round(id)
		if f.step(id, node).Phase == phApplying {
			return
		}
	}
	f.t.Fatalf("%s not applying: %v", node, f.step(id, node))
}

// TestStepNotSaved: a step change IAM did not take changes nothing: the
// rollout does not finish on it, and a revert is not handed out unsaved
// (the next round would hand the failed apply out again).
func TestStepNotSaved(t *testing.T) {
	t.Run("ok not saved", func(t *testing.T) {
		f := newCtl(t, &pb.FleetNode{Name: "c1", Roles: map[string]string{"e2b": "0"}})
		ro := f.create([]string{"c1"}, nil)
		f.toApplying(ro.Id, "c1")
		f.finish("c1", "ok")
		f.round(ro.Id) // applying -> verifying
		f.kv.fail = failing(pStep)
		if got := f.round(ro.Id); got.State != rsRunning {
			t.Fatalf("rollout %s on a step IAM did not take", got.State)
		}
		f.kv.fail = nil
		if got := f.round(ro.Id); got.State != rsDone || f.step(ro.Id, "c1").Phase != phOK {
			t.Fatalf("after IAM came back: %s, step %s", got.State, f.step(ro.Id, "c1").Phase)
		}
	})
	t.Run("revert not saved", func(t *testing.T) {
		f := newCtl(t, &pb.FleetNode{Name: "c1", Roles: map[string]string{"e2b": "0"}})
		ro := f.create([]string{"c1"}, nil)
		f.toApplying(ro.Id, "c1")
		apply := f.ops["c1"].OpId
		f.finish("c1", "failed")
		f.kv.fail = failing(pStep)
		f.round(ro.Id)
		if op := f.ops["c1"]; op != nil && op.OpId != apply {
			t.Fatalf("handed out %s for a revert IAM did not take", op.OpId)
		}
		f.kv.fail = nil
		for range 4 {
			f.round(ro.Id)
			if op := f.ops["c1"]; op != nil && strings.Contains(op.OpId, "/revert/") {
				f.finish("c1", "ok")
			}
		}
		reverted := false
		for _, id := range f.handed {
			if strings.Contains(id, "/revert/") {
				reverted = true
			} else if reverted && id == apply {
				t.Fatalf("the failed apply was handed out again after the revert: %v", f.handed)
			}
		}
		if st := f.step(ro.Id, "c1"); !reverted || st.Phase != phReverted {
			t.Fatalf("step %s, ops %v", st.Phase, f.handed)
		}
	})
	t.Run("target not saved", func(t *testing.T) {
		f := newCtl(t, &pb.FleetNode{Name: "c1", Roles: map[string]string{"e2b": "0"}})
		ro := f.create([]string{"c1"}, nil)
		f.toApplying(ro.Id, "c1")
		f.finish("c1", "ok")
		f.round(ro.Id)
		f.kv.fail = failing(pNode)
		f.round(ro.Id)
		if st := f.step(ro.Id, "c1"); st.Phase != phVerifying {
			t.Fatalf("step %s with the node's target not saved", st.Phase)
		}
		f.kv.fail = nil
		f.round(ro.Id)
		n, _, _ := f.s.store.Node(context.Background(), "c1")
		if st := f.step(ro.Id, "c1"); st.Phase != phOK || n.V.ConfigGen != 2 {
			t.Fatalf("step %s, node at config %d", st.Phase, n.V.ConfigGen)
		}
	})
}

// TestRetiredNode: a node retired during a rollout gets nothing more from
// it: its step is skipped, and its heartbeats carry no operation.
func TestRetiredNode(t *testing.T) {
	f := newCtl(t, &pb.FleetNode{Name: "c1", Roles: map[string]string{"e2b": "0"}},
		&pb.FleetNode{Name: "e1", Roles: map[string]string{"edge": "e1"}})
	ro := f.create([]string{"c1", "e1"}, &pb.FleetStrategy{Canary: -1, PauseS: -1})
	f.round(ro.Id) // both staged (config only)
	ctx := context.Background()
	if _, err := f.s.store.UpdateNode(ctx, "e1", func(n *pb.FleetNode) error { n.State = "retired"; return nil }); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		f.round(ro.Id)
		if f.ops["c1"] != nil && f.step(ro.Id, "c1").Phase == phApplying {
			f.finish("c1", "ok")
		}
		if f.ops["e1"] != nil {
			t.Fatalf("handed %s to a retired node", f.ops["e1"].OpId)
		}
	}
	if st := f.step(ro.Id, "e1"); st.Phase != phSkipped {
		t.Fatalf("retired node's step: %s", st.Phase)
	}

	f.s.leaderUntil.Store(time.Now().Add(time.Hour).UnixNano())
	f.s.mu.Lock()
	f.s.ops["e1"] = &pb.NodeOp{OpId: "x", Kind: "apply"}
	f.s.mu.Unlock()
	resp, err := f.s.Heartbeat(ctx, &pb.HeartbeatRequest{Node: "e1", Status: &pb.NodeStatus{}})
	if err != nil || resp.State != "retired" || resp.Op != nil {
		t.Fatalf("heartbeat of a retired node: %v, %v", resp, err)
	}
}

// TestOneRollout: of two rollouts created at once, one is refused.
func TestOneRollout(t *testing.T) {
	f := newCtl(t, &pb.FleetNode{Name: "c1", Roles: map[string]string{"e2b": "0"}})
	n, _, _ := f.s.store.Node(context.Background(), "c1")
	f.kv.slow = pRollout
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := f.s.createRollout(context.Background(), &pb.FleetCreateRolloutRequest{ConfigGen: 2},
				[]*pb.FleetNode{n.V}, Strategy(nil, 0), false, nil)
			errs <- err
		}()
	}
	refused := 0
	for range 2 {
		if <-errs != nil {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d of two concurrent rollouts refused", refused)
	}
}

// TestLastBatchWatched: the last batch, a lone canary included, is watched
// for its pause (the canary's bake) before the rollout is done.
func TestLastBatchWatched(t *testing.T) {
	f := newCtl(t, &pb.FleetNode{Name: "e1", Roles: map[string]string{"edge": "e1"}})
	ro := f.create([]string{"e1"}, &pb.FleetStrategy{Canary: 1, BakeS: 100})
	f.toApplying(ro.Id, "e1")
	f.finish("e1", "ok")
	f.round(ro.Id)
	f.round(ro.Id)
	if f.step(ro.Id, "e1").Phase != phOK {
		t.Fatalf("step %s", f.step(ro.Id, "e1").Phase)
	}
	if got := f.round(ro.Id); got.State != rsRunning {
		t.Fatalf("rollout %s before the canary's bake ended", got.State)
	}
	f.now = f.now.Add(101 * time.Second)
	f.beat("e1", nil, "opendsec-edge.service")
	if got := f.round(ro.Id); got.State != rsDone {
		t.Fatalf("rollout %s after the bake: %s", got.State, got.Message)
	}
}
