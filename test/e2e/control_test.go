// End-to-end tests of the control plane over real gRPC: IAM + watcher +
// two apiservers + sim edges, all in one process (spec §8).
package e2e

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

func start(t *testing.T, edges int, maxSb int32) (*cluster.Local, *client.Client) {
	t.Helper()
	cfg := cluster.SimConfig(edges, 2, 16, 64*1024, maxSb)
	cfg.Watcher.ReconcileMinAge = 0.1
	cfg.Watcher.LostEdgeGrace = 0.3
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return l, c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func usage(t *testing.T, c *client.Client, project string) map[string]float64 {
	t.Helper()
	p, err := c.GetProject(ctx(t), &pb.GetProjectRequest{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	return p.Usage
}

var spec = &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 1024}, TaskId: "job-1"}

func TestCreateStopQuota(t *testing.T) {
	_, c := start(t, 3, 100)
	sb, err := c.Create(ctx(t), spec)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != pb.SandboxState_RUNNING || !strings.HasPrefix(sb.Id, sb.EdgeId+".") {
		t.Fatalf("sandbox = %v", sb)
	}
	if u := usage(t, c, "root"); u["sandboxes"] != 1 || u["cpu_cores"] != 1 {
		t.Fatalf("usage = %v", u)
	}
	got, err := c.GetSandbox(ctx(t), &pb.SandboxRef{Id: sb.Id})
	if err != nil || got.Id != sb.Id {
		t.Fatal(err)
	}
	if s, err := c.Stop(ctx(t), sb.Id); err != nil || s.State != pb.SandboxState_STOPPED {
		t.Fatalf("stop: %v %v", s, err)
	}
	// The edge returns the lease to IAM asynchronously.
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 0 })
}

func TestAuthAndQuota(t *testing.T) {
	l, admin := start(t, 2, 100)
	cx := ctx(t)
	if _, err := admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "rl", Quota: map[string]float64{"sandboxes": 3}}); err != nil {
		t.Fatal(err)
	}
	pr, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/rl", Id: "harness", Kind: "service"})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := client.Dial(l.Cfg.APIServers[1].Addr, pr.Token, "root/rl")
	defer h.Close()

	// No permissions yet.
	if _, err := h.Create(cx, spec); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
	if _, err := admin.Grant(cx, &pb.GrantRequest{Project: "root/rl", Principal: "harness",
		Perms: []string{"sandbox.create", "sandbox.operate", "project.admin"}}); err != nil {
		t.Fatal(err)
	}
	// The harness delegates to an agent in a nested project with a smaller quota.
	if _, err := h.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root/rl", Name: "agent-7", Quota: map[string]float64{"sandboxes": 5}}); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("over-delegation: %v", err)
	}
	var ids []string
	for i := 0; i < 3; i++ {
		sb, err := h.Create(cx, spec)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, sb.Id)
	}
	if _, err := h.Create(cx, spec); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("want quota_exceeded, got %v", err)
	}
	// Operating on another project's sandbox is forbidden.
	other, _ := admin.Create(cx, spec)
	if _, err := h.Stop(cx, other.Id); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("cross-project stop: %v", err)
	}
	bad, _ := client.Dial(l.Cfg.APIServers[0].Addr, "dsk.harness.wrong", "root/rl")
	defer bad.Close()
	if _, err := bad.Create(cx, spec); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("bad token: %v", err)
	}
	for _, id := range ids {
		h.Stop(cx, id)
	}
	eventually(t, func() bool { return usage(t, admin, "root/rl")["sandboxes"] == 0 })
}

func TestNoCapacityReleasesQuota(t *testing.T) {
	_, c := start(t, 2, 2) // 4 slots in total
	for i := 0; i < 4; i++ {
		if _, err := c.Create(ctx(t), spec); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Create(ctx(t), spec); rpcutil.Reason(err) != rpcutil.NoCapacity {
		t.Fatalf("want no_capacity, got %v", err)
	}
	if u := usage(t, c, "root"); u["sandboxes"] != 4 {
		t.Fatalf("failed creation leaked quota: %v", u)
	}
}

func TestStaleSnapshotEdgeRejects(t *testing.T) {
	// Two apiservers share 1 edge x 3 slots. Neither sees the other's
	// placements, so they overshoot; the edge's admission is the backstop.
	l, c := start(t, 1, 3)
	c2, _ := client.Dial(l.Cfg.APIServers[1].Addr, l.AdminToken, "root")
	defer c2.Close()
	ok := 0
	for i := 0; i < 6; i++ {
		cl := c
		if i%2 == 1 {
			cl = c2
		}
		if _, err := cl.Create(ctx(t), spec); err == nil {
			ok++
		} else if rpcutil.Reason(err) != rpcutil.NoCapacity {
			t.Fatal(err)
		}
	}
	if ok != 3 {
		t.Fatalf("admitted %d, want 3", ok)
	}
}

func TestBatchAndTaskActions(t *testing.T) {
	l, c := start(t, 8, 1000)
	// Near-full: 8 edges x 64 slots (64 GB / 1 GB) = 512 slots for 500
	// sandboxes, created 256 at a time. The overlay must account for
	// in-flight placements or concurrent picks pile onto the same edges.
	res, err := c.CreateBatch(ctx(t), spec, 500)
	if err != nil {
		t.Fatal(err)
	}
	perEdge := map[string]int{}
	for _, r := range res {
		if r.ErrorReason != "" {
			t.Fatalf("batch item %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
		perEdge[r.Sandbox.EdgeId]++
	}
	if len(res) != 500 || len(perEdge) != 8 {
		t.Fatalf("results=%d edges=%v", len(res), perEdge)
	}
	for e, n := range perEdge {
		if n < 50 || n > 64 { // mean 62.5, cap 64
			t.Errorf("edge %s got %d sandboxes: poor balance %v", e, n, perEdge)
		}
	}
	other, _ := c.Create(ctx(t), &pb.SandboxSpec{Backend: "sim", TaskId: "job-2"})

	r, err := c.ApplyTaskAction(ctx(t), &pb.TaskActionRequest{Project: "root", TaskId: "job-1", Action: pb.TaskAction_TASK_PAUSE})
	if err != nil || r.Affected != 500 || r.Failed != 0 {
		t.Fatalf("pause: %v %v", r, err)
	}
	// Any request to a paused sandbox resumes it transparently.
	if s, err := c.TouchSandbox(ctx(t), &pb.SandboxRef{Id: res[0].Sandbox.Id}); err != nil || s.State != pb.SandboxState_RUNNING {
		t.Fatalf("touch: %v %v", s, err)
	}
	r, _ = c.ApplyTaskAction(ctx(t), &pb.TaskActionRequest{Project: "root", TaskId: "job-1", Action: pb.TaskAction_TASK_RESUME})
	if r.Affected != 500 {
		t.Fatalf("resume affected %d", r.Affected)
	}
	l.Settle()
	st, _ := c.ClusterStatus(ctx(t), &pb.Empty{})
	total := 0
	for _, e := range st.Edges {
		total += int(e.ByTask["job-1"])
	}
	if total != 500 {
		t.Fatalf("watcher by_task total = %d", total)
	}
	r, _ = c.ApplyTaskAction(ctx(t), &pb.TaskActionRequest{Project: "root", TaskId: "job-1", Action: pb.TaskAction_TASK_STOP})
	if r.Affected != 500 {
		t.Fatalf("stop affected %d", r.Affected)
	}
	list, err := c.ListSandboxes(ctx(t), &pb.SandboxFilter{Project: "root"})
	if err != nil || len(list.Sandboxes) != 1 || list.Sandboxes[0].Id != other.Id {
		t.Fatalf("list after stop: %d %v", len(list.GetSandboxes()), err)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 1 })
}

func TestEdgeFailure(t *testing.T) {
	l, c := start(t, 3, 100)
	var onDead []string
	for i := 0; i < 30; i++ {
		sb, err := c.Create(ctx(t), spec)
		if err != nil {
			t.Fatal(err)
		}
		if sb.EdgeId == "e000" {
			onDead = append(onDead, sb.Id)
		}
	}
	if len(onDead) == 0 {
		t.Fatal("nothing placed on e000")
	}
	// Simulate a crash: the edge disappears without stopping its sandboxes
	// or releasing their quota (a graceful stop would release it at once).
	ec, _ := l.Cfg.Edge("e000")
	ec.KeepSandboxesOnExit = true
	l.StopEdge("e000")
	for i := 0; i < l.Cfg.Watcher.UnhealthyAfter; i++ {
		l.Settle()
	}
	for _, e := range l.APIServers[0].Engine.Snapshot().Edges {
		if e.Id == "e000" && e.Healthy {
			t.Fatal("dead edge still healthy")
		}
	}
	for i := 0; i < 30; i++ {
		sb, err := c.Create(ctx(t), spec)
		if err != nil {
			t.Fatal(err)
		}
		if sb.EdgeId == "e000" {
			t.Fatal("placed on dead edge")
		}
	}
	// Within lost_edge_grace the dead edge keeps its quota (it may be restarting)...
	l.Watcher.Reconcile(context.Background())
	if u := usage(t, c, "root"); int(u["sandboxes"]) != 60 {
		t.Fatalf("quota released before lost_edge_grace: %v", u)
	}
	// ...after it, the dead edge's leases are reclaimed.
	time.Sleep(400 * time.Millisecond) // > lost_edge_grace and reconcile_min_age
	l.Watcher.Reconcile(context.Background())
	if u := usage(t, c, "root"); int(u["sandboxes"]) != 60-len(onDead) {
		t.Fatalf("usage %v, want %d", u, 60-len(onDead))
	}
	if _, err := c.GetSandbox(ctx(t), &pb.SandboxRef{Id: onDead[0]}); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("get on dead edge: %v", err)
	}
}

func TestIAMRestartRebuildsUsage(t *testing.T) {
	l, c := start(t, 2, 100)
	for i := 0; i < 5; i++ {
		c.Create(ctx(t), spec)
	}
	// Simulate an IAM restart losing in-memory usage: release everything.
	for _, s := range mustList(t, c) {
		_, lease, _ := ids.Parse(s.Id)
		l.IAM.Release(lease)
	}
	if usage(t, c, "root")["sandboxes"] != 0 {
		t.Fatal("setup")
	}
	l.Watcher.Reconcile(context.Background())
	if u := usage(t, c, "root"); u["sandboxes"] != 5 {
		t.Fatalf("usage not rebuilt: %v", u)
	}
}

func mustList(t *testing.T, c *client.Client) []*pb.Sandbox {
	l, err := c.ListSandboxes(ctx(t), &pb.SandboxFilter{Project: "root"})
	if err != nil {
		t.Fatal(err)
	}
	return l.Sandboxes
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

// TestDrainEdge: a cluster admin drains an edge for maintenance; new
// sandboxes go elsewhere, running ones stay; undrained, it takes them again.
// Admins of other projects cannot.
func TestDrainEdge(t *testing.T) {
	l, admin := start(t, 2, 100)
	cx := ctx(t)
	e0 := l.Cfg.Edges[0].ID
	if _, err := admin.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0, Draining: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		sb, err := admin.Create(cx, spec)
		if err != nil {
			t.Fatal(err)
		}
		if sb.EdgeId == e0 {
			t.Fatalf("sandbox placed on drained edge %s", e0)
		}
	}
	if _, err := admin.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		sb, err := admin.Create(cx, spec)
		return err == nil && sb.EdgeId == e0
	})
	// A project admin below root is no cluster admin.
	admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "team"})
	pr, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/team", Id: "lead", Kind: "service"})
	if err != nil {
		t.Fatal(err)
	}
	admin.Grant(cx, &pb.GrantRequest{Project: "root/team", Principal: "lead", Perms: []string{"project.admin"}})
	lead, _ := client.Dial(l.Cfg.APIServers[0].Addr, pr.Token, "root/team")
	defer lead.Close()
	if _, err := lead.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0, Draining: true}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("non-root admin drained an edge: %v", err)
	}
	if _, err := admin.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: "nope", Draining: true}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("unknown edge: %v", err)
	}
}

// TestAbandonedCreation (spec §36): an edge finishing a creation its caller
// gave up on, and placed on another edge (which moved the lease there),
// drops the sandbox, and its release leaves the lease, and the quota of the
// sandbox on the other edge, alone. Through the real IAM.
func TestAbandonedCreation(t *testing.T) {
	l, admin := start(t, 2, 100)
	var edges []string
	for id := range l.Edges {
		edges = append(edges, id)
	}
	sort.Strings(edges)
	slow, other := edges[0], edges[1]
	lease := ids.NewLease()
	res := &pb.Resources{CpuCores: 1, MemoryMb: 1024}
	newSpec := func() *pb.SandboxSpec {
		return &pb.SandboxSpec{Backend: "sim", Resources: proto.Clone(res).(*pb.Resources)}
	}
	// Admitted on the slow edge; the caller gave up and retried on the other.
	if err := l.IAM.ReserveOn(lease, "root", iam.ResourceMap(res), slow); err != nil {
		t.Fatal(err)
	}
	if err := l.IAM.ReserveOn(lease, "root", iam.ResourceMap(res), other); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Edges[other].Create(ctx(t), &pb.EdgeCreateRequest{Id: ids.Sandbox(other, lease), Project: "root",
		Principal: "admin", Spec: newSpec()}); err != nil {
		t.Fatal(err)
	}
	// The slow edge finishes its creation afterwards.
	_, err := l.Edges[slow].Create(ctx(t), &pb.EdgeCreateRequest{Id: ids.Sandbox(slow, lease), Project: "root",
		Principal: "admin", Spec: newSpec()})
	if rpcutil.Reason(err) != rpcutil.Unavailable || !strings.Contains(err.Error(), "created on edge "+other) {
		t.Fatalf("slow edge: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // the slow edge returns the lease (async)
	if held, edge := l.IAM.LeaseEdge(lease); !held || edge != other {
		t.Fatalf("lease held %v on %q", held, edge)
	}
	if u := usage(t, admin, "root"); u["sandboxes"] != 1 {
		t.Fatalf("usage %v: the slow edge's release freed the quota", u)
	}
	var live []string
	for _, sb := range mustList(t, admin) {
		if sb.State == pb.SandboxState_RUNNING {
			live = append(live, sb.Id)
		}
	}
	if len(live) != 1 || live[0] != ids.Sandbox(other, lease) {
		t.Fatalf("running: %v", live)
	}
}
