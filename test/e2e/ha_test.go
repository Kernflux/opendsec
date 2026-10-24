package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// startHA runs the whole control plane on a 3-replica Raft IAM with mTLS.
func startHA(t *testing.T) (*cluster.Local, *client.Client) {
	t.Helper()
	cfg := cluster.SimConfig(3, 2, 1024, 4096*1024, 20000)
	cfg.ServiceToken = ""
	cfg.IAM.AdminToken = "dsk.admin.ha-admin-secret"
	data := t.TempDir()
	for i := 0; i < 3; i++ {
		cfg.IAM.Replicas = append(cfg.IAM.Replicas, config.IAMReplica{
			ID: fmt.Sprint(i), Addr: "127.0.0.1:0", RaftAddr: "127.0.0.1:0", DataDir: filepath.Join(data, fmt.Sprint(i))})
	}
	cfg.Watcher.ReconcileMinAge = 0.1
	pkiDir := t.TempDir()
	if err := cluster.GeneratePKI(cfg, pkiDir, time.Hour); err != nil {
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
	t.Cleanup(func() { c.Close() })
	return l, c
}

func leaderIndex(l *cluster.Local) int {
	for i, m := range l.IAMReplicas {
		if m != nil && m.IsLeader() {
			return i
		}
	}
	return -1
}

func TestIAMFailoverUnderLoad(t *testing.T) {
	l, c := startHA(t)
	cx := ctx(t)
	if _, err := c.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "rl", Quota: map[string]float64{"sandboxes": 50000}}); err != nil {
		t.Fatal(err)
	}
	pr, err := c.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root", Id: "agent", Kind: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	c.Grant(cx, &pb.GrantRequest{Project: "root", Principal: "agent", Perms: []string{"sandbox.create", "sandbox.operate"}})
	revoked, _ := c.CreateToken(cx, &pb.CreateTokenRequest{Principal: "agent", TtlS: 3600})
	c.RevokeToken(cx, &pb.RevokeTokenRequest{Principal: "agent", TokenId: revoked.Info.Id})
	rl, _ := client.Dial(l.Cfg.APIServers[1].Addr, pr.Token, "root/rl", client.WithCAFile(filepath.Join(l.Cfg.TLS.Dir, "ca.crt")))
	defer rl.Close()

	// Create sandboxes continuously from 8 workers while the IAM leader dies.
	var created, failed atomic.Int64
	var mu sync.Mutex
	var errs []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_, err := rl.Create(cctx, &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 0.1, MemoryMb: 64}})
				cancel()
				if err != nil {
					failed.Add(1)
					mu.Lock()
					errs = append(errs, err.Error())
					mu.Unlock()
				} else {
					created.Add(1)
				}
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	old := leaderIndex(l)
	before := created.Load()
	start := time.Now()
	l.StopIAMReplica(old)
	// Wait for a new leader, then let the load run on it for a while.
	deadline := time.Now().Add(10 * time.Second)
	for leaderIndex(l) < 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	nl := leaderIndex(l)
	t.Logf("IAM leader %d killed; replica %d elected after %v", old, nl, time.Since(start).Round(time.Millisecond))
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
	t.Logf("created %d sandboxes (%d after the kill), %d failed", created.Load(), created.Load()-before, failed.Load())
	if nl < 0 {
		t.Fatal("no new IAM leader")
	}
	if failed.Load() > 0 {
		t.Fatalf("%d creations failed across the failover (client retries should hide it): %v", failed.Load(), errs[:min(3, len(errs))])
	}
	if created.Load()-before == 0 {
		t.Fatal("no progress after the failover")
	}

	// Quota usage is exact: it equals the number of live sandboxes.
	list, err := rl.ListSandboxes(cx, &pb.SandboxFilter{Project: "root/rl"})
	if err != nil {
		t.Fatal(err)
	}
	if u := usage(t, c, "root/rl"); int64(u["sandboxes"]) != created.Load() || len(list.Sandboxes) != int(created.Load()) {
		t.Fatalf("usage %v, live %d, created %d", u, len(list.Sandboxes), created.Load())
	}
	// Credentials and revocations survived the failover.
	bad, _ := client.Dial(l.Cfg.APIServers[0].Addr, revoked.Token, "root", client.WithCAFile(filepath.Join(l.Cfg.TLS.Dir, "ca.crt")))
	defer bad.Close()
	if _, err := bad.WhoAmI(cx, &pb.Empty{}); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("revoked token works after failover: %v", err)
	}

	// The killed replica restarts and catches up; quota stays exact after a
	// full reconcile pass (which now also binds every lease to its edge).
	if err := l.StartIAMReplica(old); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 10*time.Second, func() bool {
		v, err := l.IAMReplicas[old].GetProject("", "root/rl")
		return err == nil && int64(v.Usage["sandboxes"]) == created.Load()
	})
	l.Settle()
	l.Watcher.Reconcile(context.Background())
	if u := usage(t, c, "root/rl"); int64(u["sandboxes"]) != created.Load() {
		t.Fatalf("reconcile changed exact usage: %v vs %d", u, created.Load())
	}
	for e, n := range l.IAMLeader().EdgeLeases() {
		if e == "" && n > 0 {
			t.Fatalf("%d leases not bound to any edge", n)
		}
	}
}
