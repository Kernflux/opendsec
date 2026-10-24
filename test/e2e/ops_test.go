package e2e

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

func backupIAM(t *testing.T, c *client.Client) []byte {
	t.Helper()
	st, err := c.BackupIAM(ctx(t), &pb.IAMBackupRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := iam.RecvChunks(st.Recv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func restoreIAM(c *client.Client, data []byte) error {
	st, err := c.RestoreIAM(context.Background())
	if err != nil {
		return err
	}
	if err := iam.SendChunks(data, st.Send); err != nil && err != io.EOF {
		return err
	}
	_, err = st.CloseAndRecv()
	return err
}

// TestIAMOps (spec §27.2): readiness, backup and restore through the
// apiserver, and replacing a dead IAM replica with a new one on another
// address, which then carries the quorum.
func TestIAMOps(t *testing.T) {
	l, c := startHA(t)
	cx := ctx(t)
	eventually(t, func() bool { return metrics.Ready() == nil })

	// Backup, then changes, then restore: the changes are gone, the live
	// sandbox's quota lease is kept.
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 64}})
	if err != nil {
		t.Fatal(err)
	}
	data := backupIAM(t, c)
	if _, err := c.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "later"}); err != nil {
		t.Fatal(err)
	}
	pr, err := c.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root", Id: "later-agent", Kind: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	c.Grant(cx, &pb.GrantRequest{Project: "root", Principal: "later-agent", Perms: []string{"sandbox.create"}})
	agent, _ := client.Dial(l.Cfg.APIServers[1].Addr, pr.Token, "root", client.WithCAFile(filepath.Join(l.Cfg.TLS.Dir, "ca.crt")))
	defer agent.Close()
	if _, err := agent.WhoAmI(cx, &pb.Empty{}); err != nil {
		t.Fatal(err)
	}
	// Only cluster admins.
	if _, err := agent.IAMMembers(cx, &pb.IAMMemberRequest{}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("members as an agent: %v", err)
	}
	if err := restoreIAM(agent, data); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("restore as an agent: %v", err)
	}
	if err := restoreIAM(c, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetProject(cx, &pb.GetProjectRequest{Project: "root/later"}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("project created after the backup survived the restore: %v", err)
	}
	// The principal is gone on every apiserver at once (the epoch moved).
	if _, err := agent.WhoAmI(cx, &pb.Empty{}); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("principal created after the backup still authenticates: %v", err)
	}
	if u := usage(t, c, "root"); u["sandboxes"] != 1 {
		t.Fatalf("live sandbox's lease lost in the restore: %v", u)
	}
	if err := restoreIAM(c, []byte("not a backup")); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("garbage restore: %v", err)
	}

	// Replace a follower: it dies, is removed, and a new replica on a new
	// address joins.
	ms, err := c.IAMMembers(cx, &pb.IAMMemberRequest{})
	if err != nil || len(ms.Members) != 3 || !ms.Replicated {
		t.Fatalf("members: %v %v", ms, err)
	}
	lead := leaderIndex(l)
	dead := (lead + 1) % 3
	l.StopIAMReplica(dead)
	if _, err := c.RemoveIAMMember(cx, &pb.IAMMemberRequest{Id: fmt.Sprint(dead)}); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(l.Cfg.TLS.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.IssueTo(l.Cfg.TLS.Dir, pki.Identity{Role: pki.RoleIAM, ID: "3"}, []string{"127.0.0.1", "localhost"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err := l.JoinIAMReplica(config.IAMReplica{ID: "3", Addr: "127.0.0.1:0", RaftAddr: "127.0.0.1:0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	nr := l.Cfg.IAM.Replicas[n]
	// Without being added, the joiner neither leads nor bootstraps.
	time.Sleep(time.Second)
	if l.IAMReplicas[n].LeaderID() != "" {
		t.Fatalf("a -join replica found a leader before being added: %q", l.IAMReplicas[n].LeaderID())
	}
	ms, err = c.AddIAMMember(cx, &pb.IAMMemberRequest{Id: "3", RaftAddr: nr.RaftAddr, Addr: nr.Addr})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range ms.Members {
		ids[m.Id] = m.Voter
	}
	if len(ids) != 3 || !ids["3"] || ids[fmt.Sprint(dead)] {
		t.Fatalf("members after the replacement: %v", ms)
	}
	eventuallyFor(t, 10*time.Second, func() bool {
		v, err := l.IAMReplicas[n].GetProject("", "root")
		return err == nil && v.Usage["sandboxes"] == 1
	})

	// The new replica is a full voter: with the old leader gone, it and the
	// last original replica elect a leader and IAM keeps working.
	l.StopIAMReplica(lead)
	eventuallyFor(t, 10*time.Second, func() bool { return leaderIndex(l) >= 0 })
	if _, err := c.Create(cx, &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 64}}); err != nil {
		t.Fatalf("create after replacing a replica and losing the leader: %v", err)
	}
	if _, err := c.StopSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 1 }) // the stop releases asynchronously
	ms, err = c.IAMMembers(cx, &pb.IAMMemberRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("members: %v", ms.Members)
}
