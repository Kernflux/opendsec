package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/nodeagent"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/release"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// fakeSystemd stands in for systemd on one simulated machine: units become
// active on restart unless the release they would run is marked bad.
type fakeSystemd struct {
	root string
	bad  func(release string) bool

	mu       sync.Mutex
	state    map[string]string
	restarts map[string]int // release -> unit restarts while it was current
}

func (f *fakeSystemd) current() string {
	t, _ := os.Readlink(filepath.Join(f.root, "current"))
	return filepath.Base(t)
}

func (f *fakeSystemd) DaemonReload(context.Context) error { return nil }

func (f *fakeSystemd) Run(_ context.Context, verb, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch verb {
	case "restart", "start":
		rel := f.current()
		f.restarts[rel]++
		if f.bad != nil && f.bad(rel) {
			f.state[unit] = "failed"
		} else {
			f.state[unit] = "active"
		}
	case "stop":
		f.state[unit] = "inactive"
	}
	return nil
}

func (f *fakeSystemd) ActiveState(_ context.Context, unit string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.state[unit]; ok {
		return s
	}
	return "active" // running before the agent started
}

func (f *fakeSystemd) RestartSelf(context.Context) error { return nil }

func (f *fakeSystemd) restartsOf(rel string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restarts[rel]
}

type simNode struct {
	name  string
	sd    *fakeSystemd
	agent *nodeagent.Agent
	root  string
	stop  context.CancelFunc
}

// makeRelease writes and packs a release directory; every release carries
// the same node agent binary, so the agents do not restart themselves.
// build tells two builds of one version apart.
func makeRelease(t *testing.T, version string, build ...string) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), version)
	for p, c := range map[string]string{
		"bin/opendsec-edge": "edge " + version + strings.Join(build, ""), "bin/opendsec-nodeagent": "agent",
		"units/opendsec-edge.service": "[Unit]\n# " + version + "\n",
		"deps.lock":                   "firecracker v1.17.0 url:https://example/fc.tgz " + strings.Repeat("0", 64) + " bin/firecracker\n",
	} {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := release.WriteSums(dir); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := release.Pack(dir, &b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func pushRelease(t *testing.T, f pb.FleetAdminClient, version string, tgz []byte) *pb.FleetRelease {
	t.Helper()
	sum := sha256.Sum256(tgz)
	up, err := f.PushRelease(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(tgz); i += 4096 {
		c := &pb.ReleaseChunk{Data: tgz[i:min(len(tgz), i+4096)]}
		if i == 0 {
			c.Version, c.Size, c.Sha256 = version, int64(len(tgz)), hex.EncodeToString(sum[:])
		}
		if err := up.Send(c); err != nil {
			t.Fatal(err)
		}
	}
	r, err := up.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestFleetRollouts runs a cluster with two fleet replicas and ten simulated
// machines (agents with a fake systemd), and drives the whole M1 flow:
// import, sync, a batched rollout across a leader failover, a failing node
// reverted and pinned, resume, and rollback (spec §28).
func TestFleetRollouts(t *testing.T) {
	cfg := cluster.SimConfig(8, 1, 16, 64*1024, 100)
	cfg.ServiceToken = ""
	cfg.Watcher.ProbeInterval = 0.2
	data := t.TempDir()
	cfg.Fleet = config.Fleet{Heartbeat: 0.3, LockTTL: 1.5, Replicas: []config.FleetReplica{
		{ID: "0", Addr: "127.0.0.1:0", DataDir: filepath.Join(data, "f0")},
		{ID: "1", Addr: "127.0.0.1:0", DataDir: filepath.Join(data, "f1")}}}
	for i := range cfg.Fleet.Replicas { // bound before the certificates are issued
		cfg.Fleet.Replicas[i].Addr = freeLocalAddr(t)
	}
	pkiDir := t.TempDir()
	if err := cluster.GeneratePKI(cfg, pkiDir, time.Hour); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := 0; i < 2; i++ {
		names = append(names, fmt.Sprintf("ctl%d", i))
	}
	for i := 0; i < 8; i++ {
		names = append(names, fmt.Sprintf("n%02d", i))
	}
	for _, n := range names {
		if err := ca.IssueTo(pkiDir, pki.Identity{Role: pki.RoleNode, ID: n}, []string{"127.0.0.1"}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	cfg.TLS.Dir = pkiDir
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := cluster.StartLocal(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root", client.WithCAFile(filepath.Join(pkiDir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	f := c.Fleet()

	// Ten machines: two control-plane nodes (ctl1's IAM replica leads, so it
	// must go after ctl0), eight edges over two failure domains.
	bad := map[string]map[string]bool{"n03": {"v3": true}}
	nodes := map[string]*simNode{}
	var imports []*pb.FleetNode
	for i, name := range names {
		root := t.TempDir()
		sd := &fakeSystemd{root: filepath.Join(root, "opt"), state: map[string]string{}, restarts: map[string]int{},
			bad: func(rel string) bool { return bad[name][rel] }}
		sec, err := cluster.Security(cfg, pki.Identity{Role: pki.RoleNode, ID: name})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := rpcutil.Dial(cfg.Fleet.ClientAddr(), sec, nil)
		if err != nil {
			t.Fatal(err)
		}
		isLeader := name == "ctl1"
		a := nodeagent.New(nodeagent.Options{Name: name, Addr: "127.0.0.1", Fleet: pb.NewFleetClient(conn), Version: "test",
			Root: sd.root, BinDir: filepath.Join(root, "bin"), Etc: filepath.Join(root, "etc"), UnitDir: filepath.Join(root, "units"),
			StateFile: filepath.Join(root, "agent.json"), Systemd: sd, Interval: 300 * time.Millisecond,
			Ready:     func(context.Context, string) error { return nil },
			IAMLeader: func(context.Context, string) bool { return isLeader },
			Log:       quiet})
		actx, cancel := context.WithCancel(context.Background())
		go a.Run(actx)
		t.Cleanup(cancel)
		nodes[name] = &simNode{name: name, sd: sd, agent: a, root: sd.root, stop: cancel}
		n := &pb.FleetNode{Name: name, Addr: "127.0.0.1", Release: "v1", ConfigGen: 1}
		if strings.HasPrefix(name, "ctl") {
			id := name[3:]
			n.Domain = "az1"
			n.Roles = map[string]string{"iam": id, "watcher": id, "apiserver": id, "fleet": id}
		} else {
			n.Domain = []string{"az1", "az2"}[i%2]
			n.Roles = map[string]string{"edge": fmt.Sprintf("e%03d", i-2)}
		}
		imports = append(imports, n)
	}

	// Releases and the first config.
	r1 := pushRelease(t, f, "v1", makeRelease(t, "v1"))
	if r1.Deps["firecracker"] != "v1.17.0" || len(r1.Replicas) != 2 {
		t.Fatalf("pushed release: %+v", r1)
	}
	r2 := pushRelease(t, f, "v2", makeRelease(t, "v2"))
	pushRelease(t, f, "v3", makeRelease(t, "v3"))
	// Another build of v2 is refused and leaves the stored v2 alone.
	rebuilt := makeRelease(t, "v2", " rebuilt")
	rsum := sha256.Sum256(rebuilt)
	if up, err := f.PushRelease(ctx(t)); err == nil {
		up.Send(&pb.ReleaseChunk{Version: "v2", Size: int64(len(rebuilt)), Sha256: hex.EncodeToString(rsum[:]), Data: rebuilt})
		if _, err := up.CloseAndRecv(); rpcutil.Reason(err) != rpcutil.Conflict {
			t.Fatalf("another build of v2: %v", err)
		}
	}
	for _, rep := range cfg.Fleet.Replicas {
		b, err := os.ReadFile(filepath.Join(rep.DataDir, "releases", "v2.tgz"))
		if sum := sha256.Sum256(b); err != nil || hex.EncodeToString(sum[:]) != r2.Sha256 {
			t.Fatalf("replica %s: stored v2 changed after a refused push (%v)", rep.ID, err)
		}
	}
	other := makeRelease(t, "v2-other")
	sum := sha256.Sum256(other)
	if up, err := f.PushRelease(ctx(t)); err == nil {
		up.Send(&pb.ReleaseChunk{Version: "v2", Size: int64(len(other)), Sha256: hex.EncodeToString(sum[:]), Data: other})
		if _, err := up.CloseAndRecv(); err == nil {
			t.Fatal("a tarball of another release was accepted as v2")
		}
	}
	pubCfg := *cfg
	cj, _ := json.Marshal(&pubCfg)
	if fc, err := f.PutConfig(ctx(t), &pb.FleetPutConfigRequest{ClusterJson: cj, Note: "initial"}); err != nil || fc.Gen != 1 {
		t.Fatalf("put config: %v %v", fc, err)
	}
	secret := pubCfg
	secret.ServiceToken = "oops"
	sj, _ := json.Marshal(&secret)
	if _, err := f.PutConfig(ctx(t), &pb.FleetPutConfigRequest{ClusterJson: sj}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("a config with a secret: %v", err)
	}

	// Import, then sync every node onto v1 (what accept does for a new one).
	if _, err := f.ImportNodes(ctx(t), &pb.FleetImportRequest{Nodes: imports}); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err := f.UpdateNode(ctx(t), &pb.FleetUpdateNodeRequest{Name: name, Action: "sync"}); err != nil {
			t.Fatal(err)
		}
	}
	allAt := func(rel string, except ...string) func() bool {
		return func() bool {
			for _, n := range nodes {
				if contains(except, n.name) {
					continue
				}
				if n.sd.current() != rel {
					return false
				}
			}
			return true
		}
	}
	eventuallyFor(t, 30*time.Second, allAt("v1"))
	if b, err := os.ReadFile(filepath.Join(nodes["n00"].root, "..", "etc", "edge.env")); err != nil || !strings.Contains(string(b), "OPENDSEC_EDGE_ID=e000") {
		t.Fatalf("edge.env: %q %v", b, err)
	}
	eventuallyFor(t, 10*time.Second, func() bool {
		l, err := f.ListNodes(ctx(t), &pb.FleetListNodesRequest{})
		if err != nil {
			return false
		}
		for _, n := range l.Nodes {
			if n.Sync || n.Status.GetCurrentRelease() != "v1" {
				return false
			}
		}
		return true
	})

	// Rollout v2: canary, then batches of 3 with at most 2 per domain; the
	// fleet leader is stopped in the middle and the other replica finishes.
	ro, err := f.CreateRollout(ctx(t), &pb.FleetCreateRolloutRequest{Release: "v2",
		Strategy: &pb.FleetStrategy{BakeS: 1, Batch: 3, MaxPerDomain: 2, PauseS: 0.5}})
	if err != nil {
		t.Fatal(err)
	}
	if ro.Batches != 4 { // canary + 7 edges in batches of 3
		t.Fatalf("batches: %d", ro.Batches)
	}
	if _, err := f.CreateRollout(ctx(t), &pb.FleetCreateRolloutRequest{Release: "v3"}); err == nil {
		t.Fatal("a second rollout started while one runs")
	}
	// The control plane goes first, the IAM leader (ctl1) after ctl0.
	eventuallyFor(t, 30*time.Second, func() bool { return nodes["ctl1"].sd.current() == "v2" })
	if nodes["ctl0"].sd.current() != "v2" {
		t.Fatal("ctl1, whose IAM replica leads, was upgraded before ctl0")
	}
	leader := -1
	for i, fs := range l.Fleets {
		if fs.IsLeader() {
			leader = i
		}
	}
	eventuallyFor(t, 30*time.Second, func() bool {
		g, err := f.GetRollout(ctx(t), &pb.FleetRolloutRef{Id: ro.Id})
		return err == nil && g.Batch >= 1
	})
	l.StopFleet(leader)
	eventuallyFor(t, 60*time.Second, func() bool {
		g, err := f.GetRollout(ctx(t), &pb.FleetRolloutRef{Id: ro.Id})
		return err == nil && g.State == "done"
	})
	if !allAt("v2")() {
		t.Fatal("not every node runs v2 after the rollout")
	}
	for _, n := range nodes { // each unit restarted once onto v2, despite the failover
		units := 1
		if strings.HasPrefix(n.name, "ctl") {
			units = 4
		}
		if got := n.sd.restartsOf("v2"); got != units {
			t.Fatalf("%s: %d unit restarts on v2, want %d", n.name, got, units)
		}
	}
	if err := l.StartFleet(leader); err != nil {
		t.Fatal(err)
	}

	// Rollout v3: n03 fails, is reverted to v2 and pinned; the rollout
	// pauses. Resuming finishes the others.
	ro3, err := f.CreateRollout(ctx(t), &pb.FleetCreateRolloutRequest{Release: "v3", Selector: &pb.FleetSelector{Roles: []string{"edge"}},
		Strategy: &pb.FleetStrategy{Canary: -1, Batch: 2, PauseS: 0.2, StepTimeoutS: 20}})
	if err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 60*time.Second, func() bool {
		g, err := f.GetRollout(ctx(t), &pb.FleetRolloutRef{Id: ro3.Id})
		return err == nil && g.State == "paused"
	})
	if got := nodes["n03"].sd.current(); got != "v2" {
		t.Fatalf("n03 runs %s after its failed upgrade, want v2", got)
	}
	n03, err := f.GetNode(ctx(t), &pb.FleetNodeRef{Name: "n03"})
	if err != nil || !n03.Pinned || n03.Release != "v2" {
		t.Fatalf("n03 after the revert: %+v %v", n03, err)
	}
	if _, err := f.ControlRollout(ctx(t), &pb.FleetControlRolloutRequest{Id: ro3.Id, Action: "resume"}); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 60*time.Second, func() bool {
		g, err := f.GetRollout(ctx(t), &pb.FleetRolloutRef{Id: ro3.Id})
		return err == nil && g.State == "done"
	})
	edgesAt := func(rel string) bool {
		for _, n := range nodes {
			if !strings.HasPrefix(n.name, "ctl") && n.name != "n03" && n.sd.current() != rel {
				return false
			}
		}
		return true
	}
	if !edgesAt("v3") {
		t.Fatal("edges besides n03 do not all run v3")
	}

	// Roll v3 back: every edge it upgraded returns to v2.
	rb, err := f.ControlRollout(ctx(t), &pb.FleetControlRolloutRequest{Id: ro3.Id, Action: "rollback"})
	if err != nil {
		t.Fatal(err)
	}
	if !rb.Rollback {
		t.Fatalf("rollback rollout: %+v", rb)
	}
	eventuallyFor(t, 60*time.Second, func() bool {
		g, err := f.GetRollout(ctx(t), &pb.FleetRolloutRef{Id: rb.Id})
		return err == nil && g.State == "done"
	})
	if !allAt("v2")() {
		t.Fatal("not every node is back on v2")
	}

	// Cordon drains the edge and keeps it drained; uncordon undoes it.
	if _, err := f.UpdateNode(ctx(t), &pb.FleetUpdateNodeRequest{Name: "n00", Action: "cordon"}); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 10*time.Second, func() bool { return l.Edges["e000"].Status(false).State.Draining })
	if _, err := f.UpdateNode(ctx(t), &pb.FleetUpdateNodeRequest{Name: "n00", Action: "uncordon"}); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 10*time.Second, func() bool { return !l.Edges["e000"].Status(false).State.Draining })

	// Retire refuses an edge that is not evacuated: not cordoned, or with
	// sandboxes left; it stops the components once the edge is empty.
	retire := func() error {
		_, err := f.UpdateNode(ctx(t), &pb.FleetUpdateNodeRequest{Name: "n00", Action: "retire"})
		return err
	}
	if err := retire(); rpcutil.Reason(err) != rpcutil.Invalid || !strings.Contains(err.Error(), "not cordoned") {
		t.Fatalf("retire an active node: %v", err)
	}
	var created, onE000 []string
	for i := 0; i < 40 && len(onE000) == 0; i++ {
		sb, err := c.Create(ctx(t), spec)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, sb.Id)
		if sb.EdgeId == "e000" {
			onE000 = append(onE000, sb.Id)
		}
	}
	if len(onE000) == 0 {
		t.Fatal("nothing placed on e000")
	}
	if _, err := f.UpdateNode(ctx(t), &pb.FleetUpdateNodeRequest{Name: "n00", Action: "cordon"}); err != nil {
		t.Fatal(err)
	}
	var lastErr error
	eventuallyFor(t, 10*time.Second, func() bool {
		lastErr = retire()
		return rpcutil.Reason(lastErr) == rpcutil.Invalid
	})
	if !strings.Contains(lastErr.Error(), "sandboxes still on edge e000") {
		t.Fatalf("retire with sandboxes left: %v", lastErr)
	}
	if st := nodes["n00"].sd.ActiveState(ctx(t), "opendsec-edge.service"); st != "active" {
		t.Fatalf("the edge was stopped by a refused retire: %s", st)
	}
	for _, id := range created {
		if _, err := c.Stop(ctx(t), id); err != nil {
			t.Fatal(err)
		}
	}
	eventuallyFor(t, 10*time.Second, func() bool { return retire() == nil })
	eventuallyFor(t, 10*time.Second, func() bool {
		return nodes["n00"].sd.ActiveState(ctx(t), "opendsec-edge.service") == "inactive"
	})

	// An agent may only report for its own node.
	sec, _ := cluster.Security(cfg, pki.Identity{Role: pki.RoleNode, ID: "n00"})
	conn, _ := rpcutil.Dial(cfg.Fleet.ClientAddr(), sec, nil)
	if _, err := pb.NewFleetClient(conn).Heartbeat(ctx(t), &pb.HeartbeatRequest{Node: "n01"}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("an agent reported for another node: %v", err)
	}
	conn.Close()
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
