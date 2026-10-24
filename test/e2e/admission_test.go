package e2e

import (
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestAdmissionPolicy: TTL defaults and cap, per-principal creation and
// request rates, and failed-authentication limiting (spec §18).
func TestAdmissionPolicy(t *testing.T) {
	cfg := cluster.SimConfig(2, 1, 16, 64*1024, 1000)
	a := &cfg.Admission
	a.DefaultTTLRunningStop, a.DefaultTTLMax, a.MaxTTLMax = 300, 3600, 7200
	a.CreateRate, a.CreateBurst = 50, 5
	a.RequestRate, a.RequestBurst = 1000, 1000
	a.AuthFailRate = 2 // burst 4
	cfg.Defaults()
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer c.Close()
	cx := ctx(t)

	// Defaults land in the sandbox's spec; explicit values are kept; the cap rejects.
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim"})
	if err != nil || sb.Spec.TtlRunningStopS != 300 || sb.Spec.TtlMaxS != 3600 {
		t.Fatalf("defaults: %v %v", sb.GetSpec(), err)
	}
	if sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim", TtlRunningStopS: 10, TtlMaxS: 7200}); err != nil || sb.Spec.TtlMaxS != 7200 {
		t.Fatalf("explicit: %v %v", sb.GetSpec(), err)
	}
	if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim", TtlMaxS: 7201}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("over the cap: %v", err)
	}

	// Single creations past the burst are rejected with rate_limited...
	time.Sleep(200 * time.Millisecond) // refill the burst of 5
	limited := 0
	for i := 0; i < 20; i++ {
		if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim"}); rpcutil.Reason(err) == rpcutil.RateLimited {
			limited++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if limited < 10 {
		t.Fatalf("only %d of 20 back-to-back creations rate limited (burst 5, 50/s)", limited)
	}
	// ...while a batch is paced instead: all of it succeeds, at about the rate.
	start := time.Now()
	res, err := c.CreateBatch(cx, &pb.SandboxSpec{Backend: "sim"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.ErrorReason != "" {
			t.Fatalf("batch item failed: %s %s", r.ErrorReason, r.ErrorMessage)
		}
	}
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Fatalf("30 creations at 50/s took only %v", d)
	}

	// Rates are per principal: another principal is not affected.
	c.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "other"})
	pr, err := c.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/other", Id: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	c.Grant(cx, &pb.GrantRequest{Project: "root/other", Principal: "bob", Perms: []string{"sandbox.create"}})
	bob, _ := client.Dial(cfg.APIServers[0].Addr, pr.Token, "root/other")
	defer bob.Close()
	for i := 0; i < 20; i++ { // drain admin's bucket
		c.Create(cx, &pb.SandboxSpec{Backend: "sim"})
	}
	if _, err := bob.Create(cx, &pb.SandboxSpec{Backend: "sim"}); err != nil {
		t.Fatalf("other principal limited: %v", err)
	}

	// Failed authentications are limited per client address: after the burst,
	// even a valid token from that address is refused for a moment.
	bad, _ := client.Dial(cfg.APIServers[0].Addr, "dsk.nobody.bad", "root")
	defer bad.Close()
	reasons := map[string]int{}
	for i := 0; i < 8; i++ {
		_, err := bad.Create(cx, &pb.SandboxSpec{Backend: "sim"})
		reasons[rpcutil.Reason(err)]++
	}
	if reasons[rpcutil.Unauthenticated] != 4 || reasons[rpcutil.RateLimited] != 4 {
		t.Fatalf("failed-auth limiting: %v", reasons)
	}
	// Cached (already authenticated) principals keep working.
	if _, err := c.WhoAmI(cx, &pb.Empty{}); err != nil {
		t.Fatalf("cached principal blocked by another client's failures: %v", err)
	}
}
