package e2e

import (
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestFnCall: the fncall backend (spec §22.3) is the container runtime
// with a warm pool: plain requests start in milliseconds, through the
// whole stack.
func TestFnCall(t *testing.T) {
	if agentDir == "" {
		t.Skip("container runtime unavailable")
	}
	storeRoot := t.TempDir()
	st, _ := images.NewStore(storeRoot)
	w, _, err := st.BeginLayer(layerID("fn-base"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	state, _ := os.MkdirTemp("", "opendsec")
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(1, 1, 8, 16*1024, 64)
	cfg.ImageStore.Root = storeRoot
	for i := range cfg.Edges {
		e := &cfg.Edges[i]
		e.StateDir, e.AgentDir = state, agentDir
		e.Capacity.DiskMB, e.DiskReserveMB = 64*256, 64
		e.Backends["fncall"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256,
			WarmPool: map[string]int{"root/fn:1": 4}}
		e.Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer c.Close()
	cx := ctx(t)
	if _, err := c.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/fn:1", Layers: []string{layerID("fn-base")}}}); err != nil {
		t.Fatal(err)
	}
	spec := &pb.SandboxSpec{Backend: "fncall", Image: "root/fn:1", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}}
	// The pool fills once the image exists.
	var warm time.Duration
	eventuallyFor(t, 20*time.Second, func() bool {
		start := time.Now()
		sb, err := c.Create(cx, spec)
		if err != nil {
			return false
		}
		defer c.Stop(cx, sb.Id)
		warm = time.Since(start)
		return warm < 50*time.Millisecond
	})
	var lat []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		sb, err := c.Create(cx, spec)
		if err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(start))
		if r := shell(t, c, sb.Id, "", "echo call"); string(r.Stdout) != "call\n" {
			t.Fatalf("fncall sandbox: %q %q", r.Stdout, r.Stderr)
		}
		c.Stop(cx, sb.Id)
	}
	t.Logf("fncall creations through the API: %v", lat)
	// Two container-runtime backends on one edge: after a restart each
	// adopts its own sandboxes and leaves the other's alone.
	fn, err := c.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/fn:1", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := l.Cfg.Edge(fn.EdgeId)
	ec.KeepSandboxesOnExit = true
	if err := l.RestartEdge(fn.EdgeId, nil); err != nil {
		t.Fatal(err)
	}
	ec.KeepSandboxesOnExit = false
	time.Sleep(time.Second) // a wrong cleanup shows as a lost channel
	for _, id := range []string{fn.Id, ct.Id} {
		eventuallyFor(t, 5*time.Second, func() bool {
			l.Settle()
			s, err := c.GetSandbox(cx, &pb.SandboxRef{Id: id})
			return err == nil && s.State == pb.SandboxState_RUNNING
		})
		if r := shell(t, c, id, "", "echo still"); string(r.Stdout) != "still\n" {
			t.Fatalf("%s after the edge restart: %q %q", id, r.Stdout, r.Stderr)
		}
		c.Stop(cx, id)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 0 })
}
