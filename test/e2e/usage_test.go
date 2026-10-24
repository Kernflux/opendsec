package e2e

import (
	"io"
	"log/slog"
	"math"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestUsageReport (spec §41): sandboxes' resource-hours per project through
// the API, ended and running ones; subprojects included; project.admin
// required.
func TestUsageReport(t *testing.T) {
	cfg := cluster.SimConfig(2, 1, 16, 64*1024, 100)
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	cx := ctx(t)
	admin, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, p := range [][2]string{{"root", "team"}, {"root/team", "a"}} {
		if _, err := admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: p[0], Name: p[1], Quota: map[string]float64{"sandboxes": 10}}); err != nil {
			t.Fatal(err)
		}
	}
	in := func(project string) *client.Client {
		c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, project)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	spec := &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 2, MemoryMb: 4096}}
	ended, err := in("root/team/a").Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in("root/team").Create(cx, spec); err != nil { // stays running
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := in("root/team/a").Stop(cx, ended.Id); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { // the lease is released by the edge after the stop
		rep, err := admin.GetUsage(cx, &pb.UsageRequest{Project: "root/team"})
		if err != nil || len(rep.Rows) != 2 {
			return false
		}
		for _, r := range rep.Rows {
			if r.SandboxesStarted != 1 || r.SandboxHours < 1.0/3600 ||
				math.Abs(r.CpuCoreHours-2*r.SandboxHours) > 1e-9 || math.Abs(r.MemoryGbHours-4*r.SandboxHours) > 1e-9 {
				return false
			}
		}
		return true
	})

	r, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/team", Id: "dev2", Kind: "user"})
	if err != nil {
		t.Fatal(err)
	}
	admin.Grant(cx, &pb.GrantRequest{Project: "root/team", Principal: "dev2", Perms: []string{"sandbox.create"}})
	dev, _ := client.Dial(cfg.APIServers[0].Addr, r.Token, "root/team")
	defer dev.Close()
	if _, err := dev.GetUsage(cx, &pb.UsageRequest{Project: "root/team"}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("without project.admin: %v", err)
	}
}
