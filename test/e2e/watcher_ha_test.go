package e2e

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/pkg/client"
)

func TestWatcherHAAndDynamicEdge(t *testing.T) {
	cfg := cluster.SimConfig(2, 1, 16, 64*1024, 100)
	cfg.ServiceToken = ""
	cfg.Watcher.Replicas = []config.WatcherReplica{{ID: "0", Addr: "127.0.0.1:0"}, {ID: "1", Addr: "127.0.0.1:0"}}
	cfg.Watcher.LockTTL = 1.5
	cfg.Watcher.ProbeInterval = 0.2
	tmpl := cfg.Edges[0]
	tmpl.ID, tmpl.Addr = "", "127.0.0.1:0"
	cfg.EdgeTemplate = &tmpl
	pkiDir := t.TempDir()
	if err := cluster.GeneratePKI(cfg, pkiDir, time.Hour); err != nil {
		t.Fatal(err)
	}
	// A node joining later gets its certificate at provisioning time
	// (what `opendsecctl pki issue` does).
	ca, err := pki.LoadCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.IssueTo(pkiDir, pki.Identity{Role: pki.RoleEdge, ID: "dyn-1"}, []string{"127.0.0.1"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	cfg.TLS.Dir = pkiDir
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root", client.WithCAFile(filepath.Join(pkiDir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	leaders := func() (n, idx int) {
		idx = -1
		for i, w := range l.Watchers {
			if l.WatcherComps[i] != nil && w.IsLeader() {
				n++
				idx = i
			}
		}
		return
	}
	// Exactly one reconcile leader, and never two at once.
	eventuallyFor(t, 5*time.Second, func() bool { n, _ := leaders(); return n == 1 })
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if n, _ := leaders(); n > 1 {
			t.Fatal("two watchers lead reconciliation at once")
		}
	}

	// A dynamic edge (not in cfg.Edges) starts from the template and
	// registers with both watchers.
	dc, de, err := cluster.StartEdge(cfg, "dyn-1", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Stop()
	eventuallyFor(t, 5*time.Second, func() bool {
		for _, w := range l.Watchers {
			found := false
			for _, e := range w.Snapshot().Edges {
				found = found || (e.Id == "dyn-1" && e.Healthy)
			}
			if !found {
				return false
			}
		}
		return true
	})
	// Drain the static edges: new sandboxes must land on the dynamic one.
	for _, e := range l.Edges {
		e.SetDraining(true)
	}
	eventuallyFor(t, 5*time.Second, func() bool {
		l.APIServers[0].Refresh(ctx(t))
		sb, err := c.Create(ctx(t), &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 512}})
		return err == nil && sb.EdgeId == "dyn-1"
	})
	if de.Status(false).State.CountByBackend["sim"] == 0 {
		t.Fatal("nothing placed on the dynamic edge")
	}
	for _, e := range l.Edges {
		e.SetDraining(false)
	}

	// Kill the leader watcher: the other takes over within the lock TTL, and
	// the apiserver keeps getting fresh snapshots from the survivor.
	_, li := leaders()
	start := time.Now()
	l.StopWatcher(li)
	eventuallyFor(t, 5*time.Second, func() bool { n, i := leaders(); return n == 1 && i != li })
	t.Logf("reconcile leadership moved from watcher %d after %v", li, time.Since(start).Round(10*time.Millisecond))
	before := l.APIServers[0].Engine.Snapshot().TakenAt
	eventuallyFor(t, 5*time.Second, func() bool {
		l.APIServers[0].Refresh(ctx(t))
		return l.APIServers[0].Engine.Snapshot().TakenAt > before
	})
	if _, err := c.Create(ctx(t), &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 512}}); err != nil {
		t.Fatalf("create with one watcher down: %v", err)
	}

	// Started again, the watcher knows the dynamic edge from its peer at
	// once, not only when the edge registers again (every 10 s): its
	// snapshots never leave the edge out.
	start = time.Now()
	wc, w2, err := cluster.StartWatcher(cfg, li, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer wc.Stop()
	eventuallyFor(t, 3*time.Second, func() bool {
		for _, e := range w2.Snapshot().Edges {
			if e.Id == "dyn-1" {
				return true
			}
		}
		return false
	})
	t.Logf("restarted watcher knew the dynamic edge after %v", time.Since(start).Round(10*time.Millisecond))
}
