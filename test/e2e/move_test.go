package e2e

import (
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/edge/host"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestMovePaused moves paused sandboxes between edges (spec §26.2) on sim
// backends: the control plane of a move (routing by id, the quota lease
// following the sandbox, the edge it left pointing to where it went).
func TestMovePaused(t *testing.T) {
	cfg := cluster.SimConfig(2, 2, 16, 64*1024, 100)
	cfg.Watcher.ReconcileMinAge = 0.1
	cfg.Watcher.LostEdgeGrace = 0.3
	cfg.ImageStore.Root = t.TempDir() // held snapshots are recorded in the store
	half := 0.5
	for i := range cfg.Edges {
		cfg.Edges[i].PausedMemCharge = &half
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer c.Close()
	c2, _ := client.Dial(cfg.APIServers[1].Addr, l.AdminToken, "root")
	defer c2.Close()
	cx := ctx(t)
	e0, e1 := cfg.Edges[0].ID, cfg.Edges[1].ID

	l.Edges[e1].SetDraining(true)
	l.Settle()
	sb, err := c.Create(cx, spec)
	l.Edges[e1].SetDraining(false)
	if err != nil || sb.EdgeId != e0 {
		t.Fatalf("create on %s: %v %v", e0, sb, err)
	}
	before := usage(t, c, "root")
	if s, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.State != pb.SandboxState_PAUSED {
		t.Fatalf("pause: %v %v", s, err)
	}

	// Its edge drains: resuming moves it, keeping its id and creation time.
	if _, err := c.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0, Draining: true}); err != nil {
		t.Fatal(err)
	}
	l.Settle()
	moved, err := c.ResumeSandbox(cx, &pb.SandboxRef{Id: sb.Id})
	if err != nil || moved.Id != sb.Id || moved.EdgeId != e1 || moved.State != pb.SandboxState_RUNNING || moved.CreatedAt != sb.CreatedAt {
		t.Fatalf("resume on a draining edge: %v %v", moved, err)
	}
	// The edge it left points to where it went; another apiserver follows.
	if _, err := l.Edges[e0].Get(sb.Id); rpcutil.MovedTo(err) != e1 {
		t.Fatalf("old edge: %v", err)
	}
	if s, err := c2.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.EdgeId != e1 {
		t.Fatalf("other apiserver: %v %v", s, err)
	}
	var n int
	for _, s := range mustList(t, c) {
		if s.Id == sb.Id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("listed %d times", n)
	}
	// The quota lease is the same, bound to the new edge: reconciles keep it.
	time.Sleep(500 * time.Millisecond)
	l.Settle()
	if u := usage(t, c, "root"); u["sandboxes"] != before["sandboxes"] || u["memory_mb"] != before["memory_mb"] {
		t.Fatalf("usage %v, was %v", u, before)
	}
	if got := l.IAM.EdgeLeases(); got[e1] != 1 || got[e0] != 0 {
		t.Fatalf("leases by edge: %v", got)
	}
	// Edges route it by their status too, once the watcher has it.
	eventually(t, func() bool {
		for _, e := range l.Watcher.Snapshot().Edges {
			if e.Id == e1 && len(e.MovedIn) == 1 && e.MovedIn[0] == sb.Id {
				return true
			}
		}
		return false
	})

	// Paused again, its new edge under memory pressure: a call that resumes
	// it moves it back.
	if _, err := c.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil {
		t.Fatal(err)
	}
	l.Edges[e1].Pressure = &host.Pressure{ReserveMB: 1 << 40}
	l.Settle()
	back, err := c2.TouchSandbox(cx, &pb.SandboxRef{Id: sb.Id})
	l.Edges[e1].Pressure = nil
	if err != nil || back.EdgeId != e0 || back.State != pb.SandboxState_RUNNING {
		t.Fatalf("resume under pressure: %v %v", back, err)
	}
	if s, err := c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.EdgeId != e0 {
		t.Fatalf("after moving back: %v %v", s, err)
	}

	// Only paused sandboxes move; a running one on a draining edge stays.
	c.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0, Draining: true})
	l.Settle()
	if s, err := c.TouchSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.EdgeId != e0 {
		t.Fatalf("touch of a running sandbox: %v %v", s, err)
	}
	c.DrainEdge(cx, &pb.DrainEdgeRequest{EdgeId: e0})
	if _, err := c.Stop(cx, sb.Id); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 0 })

	// The metrics saw it all (spec §26.3).
	m := metrics.Text()
	for _, want := range []string{
		`opendsec_apiserver_move_seconds_count{reason="ok"}`,
		`opendsec_rpc_server_handled_total{method="ResumeSandbox",reason="ok",service="DSec"}`,
		`opendsec_rpc_server_handled_total{method="BeginMove",reason="ok",service="Edge"}`,
		`opendsec_edge_op_seconds_count{backend="sim",op="pause",reason="ok"}`,
		`opendsec_edge_create_seconds_count{backend="sim",reason="ok"}`,
		`opendsec_edge_capacity{edge="` + e0 + `",resource="memory_mb"}`,
		`opendsec_iam_leader{replica=""} 1`,
		`opendsec_watcher_edges_healthy{watcher=`,
		`opendsec_host_mounts `,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if v := metricValue(m, `opendsec_apiserver_move_seconds_count{reason="ok"}`); v < 2 {
		t.Errorf("%v moves counted, want >= 2", v)
	}
}

// metricValue returns the value of the series named (with labels) series in
// a Prometheus text dump, or -1.
func metricValue(text, series string) float64 {
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err == nil {
				return v
			}
		}
	}
	return -1
}
