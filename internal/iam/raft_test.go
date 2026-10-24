package iam

import (
	"fmt"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/kernflux/opendsec/internal/pki"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type replicaSet struct {
	t     *testing.T
	opts  []RaftOptions
	nodes []*IAM
}

func startReplicas(t *testing.T, n int, tlsDir string) *replicaSet {
	t.Helper()
	rs := &replicaSet{t: t}
	var peers []Peer
	for i := 0; i < n; i++ {
		peers = append(peers, Peer{ID: fmt.Sprint(i), RaftAddr: freeAddr(t)})
	}
	base := t.TempDir()
	for i := 0; i < n; i++ {
		o := RaftOptions{ID: peers[i].ID, RaftAddr: peers[i].RaftAddr, DataDir: filepath.Join(base, peers[i].ID), Peers: peers, LogLevel: "error"}
		if tlsDir != "" {
			m, err := pki.Load(tlsDir, pki.Identity{Role: pki.RoleIAM, ID: peers[i].ID})
			if err != nil {
				t.Fatal(err)
			}
			o.TLS = m
		}
		rs.opts = append(rs.opts, o)
		rs.nodes = append(rs.nodes, rs.start(i))
	}
	t.Cleanup(func() {
		for _, m := range rs.nodes {
			if m != nil {
				m.Shutdown()
			}
		}
	})
	return rs
}

func (rs *replicaSet) start(i int) *IAM {
	m, err := NewReplicated(rs.opts[i])
	if err != nil {
		rs.t.Fatal(err)
	}
	return m
}

func (rs *replicaSet) leader() (int, *IAM) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for i, m := range rs.nodes {
			if m != nil && m.IsLeader() {
				return i, m
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	rs.t.Fatal("no leader elected")
	return -1, nil
}

// converged waits until every live replica has applied the same index.
func (rs *replicaSet) converged() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var idx []uint64
		for _, m := range rs.nodes {
			if m != nil {
				idx = append(idx, m.AppliedIndex())
			}
		}
		same := true
		for _, x := range idx {
			same = same && x == idx[0]
		}
		if same && idx[0] > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	rs.t.Fatal("replicas did not converge")
}

func usageOf(t *testing.T, m *IAM, project string) map[string]float64 {
	t.Helper()
	v, err := m.GetProject("", project)
	if err != nil {
		t.Fatal(err)
	}
	return v.Usage
}

// onLeader runs a write on the current leader, and again on the next one
// if leadership moved meanwhile: under load (the whole suite running) an
// election can happen at any time.
func (rs *replicaSet) onLeader(f func(m *IAM) error) error {
	var err error
	for try := 0; try < 20; try++ {
		_, lead := rs.leader()
		if err = f(lead); rpcutil.Reason(err) != rpcutil.Unavailable {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func testRaftCluster(t *testing.T, tlsDir string) {
	rs := startReplicas(t, 3, tlsDir)
	if err := rs.onLeader(func(m *IAM) error {
		_, err := m.Bootstrap("admin", "dsk.admin.root-secret", map[string]float64{QSandboxes: 100})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rs.onLeader(func(m *IAM) error {
		_, err := m.CreateProject("admin", "root", "rl", map[string]float64{QSandboxes: 10})
		return err
	})
	var tok string
	if err := rs.onLeader(func(m *IAM) (err error) {
		tok, _, err = m.CreatePrincipal("admin", "root/rl", "agent", "agent", time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := rs.onLeader(func(m *IAM) error {
			return m.Reserve(fmt.Sprintf("l%d", i), "root/rl", map[string]float64{QSandboxes: 1})
		}); err != nil {
			t.Fatal(err)
		}
	}
	rs.converged()
	// Every replica holds the same principals, tokens and quota usage.
	for i, m := range rs.nodes {
		if _, err := m.Authenticate(tok); err != nil {
			t.Fatalf("replica %d: token: %v", i, err)
		}
		if u := usageOf(t, m, "root/rl"); u[QSandboxes] != 5 {
			t.Fatalf("replica %d: usage %v", i, u)
		}
	}
	// Followers refuse writes (the gRPC layer forwards them to the leader).
	for _, m := range rs.nodes {
		if !m.IsLeader() {
			if err := m.Reserve("x", "root/rl", map[string]float64{QSandboxes: 1}); err == nil && !m.IsLeader() {
				t.Fatal("follower accepted a write")
			}
		}
	}

	// Kill the leader: a new one is elected and the state is all there.
	li, _ := rs.leader()
	start := time.Now()
	rs.nodes[li].Shutdown()
	rs.nodes[li] = nil
	ni, nl := rs.leader()
	t.Logf("leader %d -> %d after %v", li, ni, time.Since(start).Round(time.Millisecond))
	if u := usageOf(t, nl, "root/rl"); u[QSandboxes] != 5 {
		t.Fatalf("usage lost on failover: %v", u)
	}
	if _, err := nl.Authenticate(tok); err != nil {
		t.Fatalf("token lost on failover: %v", err)
	}
	// Quota is still enforced across the failover: 5 more fit, the 11th does not.
	for i := 5; i < 10; i++ {
		if err := nl.Reserve(fmt.Sprintf("l%d", i), "root/rl", map[string]float64{QSandboxes: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := nl.Reserve("over", "root/rl", map[string]float64{QSandboxes: 1}); err == nil {
		t.Fatal("quota not enforced after failover")
	}
	_, info, _ := nl.CreateToken("admin", "agent", 0, "after failover")
	nl.RevokeToken("admin", "agent", info.ID)

	// The old leader restarts from its data dir and catches up. A follower
	// is eventually consistent: under load (the whole suite running) its
	// applied index can match the others' before its state does, so wait
	// for the state.
	rs.nodes[li] = rs.start(li)
	rs.converged()
	deadline := time.Now().Add(10 * time.Second)
	for {
		m := rs.nodes[li]
		v, err := m.GetProject("", "root/rl")
		if err == nil && v.Usage[QSandboxes] == 10 && m.SecurityEpoch() == nl.SecurityEpoch() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted replica did not catch up: project %v %v, security epoch %d (want %d)",
				v, err, m.SecurityEpoch(), nl.SecurityEpoch())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRaftCluster(t *testing.T) { testRaftCluster(t, "") }

func TestRaftClusterTLS(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca.Write(dir)
	for i := 0; i < 3; i++ {
		ca.IssueTo(dir, pki.Identity{Role: pki.RoleIAM, ID: fmt.Sprint(i)}, []string{"127.0.0.1"}, time.Hour)
	}
	// A non-IAM certificate must not be able to join replication.
	ca.IssueTo(dir, pki.Identity{Role: pki.RoleEdge, ID: "e1"}, []string{"127.0.0.1"}, time.Hour)
	testRaftCluster(t, dir)

	edge, _ := pki.Load(dir, pki.Identity{Role: pki.RoleEdge, ID: "e1"})
	rs := startReplicas(t, 1, dir)
	rs.leader()
	sl, err := newTLSStream("127.0.0.1:0", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	conn, err := sl.Dial(raftAddr(rs.opts[0].RaftAddr), time.Second)
	if err == nil {
		// The handshake completes lazily; the server rejects the edge identity.
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("edge certificate accepted by IAM replication")
	}
}

func raftAddr(s string) raft.ServerAddress { return raft.ServerAddress(s) }
