package iam

import (
	"path/filepath"
	"testing"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

func setup(t *testing.T) (*IAM, string) {
	t.Helper()
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Bootstrap("admin", "", map[string]float64{QSandboxes: 100, QCPU: 64})
	if err != nil {
		t.Fatal(err)
	}
	return m, tok
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := rpcutil.Reason(err); got != reason {
		t.Fatalf("want %s, got %v", reason, err)
	}
}

func TestAuthenticate(t *testing.T) {
	m, tok := setup(t)
	if p, err := m.Authenticate(tok); err != nil || p.ID != "admin" {
		t.Fatalf("auth: %v", err)
	}
	for _, bad := range []string{"", "dsk.admin", "dsk.admin.wrong", "dsk.nobody.x", tok + "x"} {
		_, err := m.Authenticate(bad)
		wantReason(t, err, rpcutil.Unauthenticated)
	}
}

func TestNestingAndInheritance(t *testing.T) {
	m, _ := setup(t)
	if _, err := m.CreateProject("admin", "root", "rl", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateProject("admin", "root/rl", "job-42", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.CreatePrincipal("admin", "root", "harness", "service", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Grant("admin", "root/rl", "harness", []string{SandboxCreate, ProjectAdmin}); err != nil {
		t.Fatal(err)
	}
	// Grant on root/rl applies to root/rl/job-42, not to root.
	if err := m.Authorize("harness", "root/rl/job-42", SandboxCreate); err != nil {
		t.Fatal(err)
	}
	wantReason(t, m.Authorize("harness", "root", SandboxCreate), rpcutil.Forbidden)
	// The harness can build deeper levels below its own subtree.
	if _, err := m.CreateProject("harness", "root/rl/job-42", "agent-7", nil); err != nil {
		t.Fatal(err)
	}
	_, err := m.CreateProject("harness", "root", "other", nil)
	wantReason(t, err, rpcutil.Forbidden)
}

func TestBoundedDelegation(t *testing.T) {
	m, _ := setup(t)
	m.CreateProject("admin", "root", "rl", map[string]float64{QSandboxes: 10})
	m.CreatePrincipal("admin", "root", "harness", "service", 0)
	m.CreatePrincipal("admin", "root", "agent", "agent", 0)
	m.Grant("admin", "root/rl", "harness", []string{SandboxCreate, ProjectAdmin})

	// Cannot grant a permission the actor does not hold.
	_, err := m.Grant("harness", "root/rl", "agent", []string{LayerPublish})
	wantReason(t, err, rpcutil.Forbidden)
	if _, err := m.Grant("harness", "root/rl", "agent", []string{SandboxCreate}); err != nil {
		t.Fatal(err)
	}
	// Subproject quota cannot exceed the parent, and unset keys are inherited.
	_, err = m.CreateProject("harness", "root/rl", "big", map[string]float64{QSandboxes: 11})
	wantReason(t, err, rpcutil.QuotaExceeded)
	p, err := m.CreateProject("harness", "root/rl", "small", map[string]float64{QSandboxes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if p.Quota[QCPU] != 64 || p.Quota[QSandboxes] != 5 {
		t.Fatalf("quota = %v", p.Quota)
	}
	_, err = m.CreateProject("harness", "root/rl", "bad", map[string]float64{"bogus": 1})
	wantReason(t, err, rpcutil.Invalid)
}

func TestHierarchicalQuota(t *testing.T) {
	m, _ := setup(t)
	m.CreateProject("admin", "root", "a", map[string]float64{QSandboxes: 3})
	m.CreateProject("admin", "root/a", "x", map[string]float64{QSandboxes: 3})
	m.CreateProject("admin", "root/a", "y", map[string]float64{QSandboxes: 3})
	one := map[string]float64{QSandboxes: 1, QCPU: 1}
	for _, l := range []string{"l1", "l2"} {
		if err := m.Reserve(l, "root/a/x", one); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Reserve("l3", "root/a/y", one); err != nil {
		t.Fatal(err)
	}
	// root/a is full (3) even though root/a/y alone has room.
	wantReason(t, m.Reserve("l4", "root/a/y", one), rpcutil.QuotaExceeded)
	// Failed reservations charge nothing.
	v, _ := m.GetProject("admin", "root/a/y")
	if v.Usage[QSandboxes] != 1 {
		t.Fatalf("y usage = %v", v.Usage)
	}
	// Idempotent reserve, idempotent release.
	if err := m.Reserve("l1", "root/a/x", one); err != nil {
		t.Fatal(err)
	}
	if !m.Release("l1") || m.Release("l1") {
		t.Fatal("release should succeed once")
	}
	if err := m.Reserve("l4", "root/a/y", one); err != nil {
		t.Fatal(err)
	}
	v, _ = m.GetProject("admin", "root")
	if v.Usage[QSandboxes] != 3 || v.Usage[QCPU] != 3 {
		t.Fatalf("root usage = %v", v.Usage)
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam.json")
	m, _ := New(path)
	tok, _ := m.Bootstrap("admin", "", nil)
	m.CreateProject("admin", "root", "rl", map[string]float64{QSandboxes: 7})
	agentTok, _, _ := m.CreatePrincipal("admin", "root/rl", "agent", "agent", 0)
	m.Grant("admin", "root/rl", "agent", []string{SandboxCreate})

	m2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Bootstrap("admin", tok, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Authenticate(agentTok); err != nil {
		t.Fatal(err)
	}
	if err := m2.Authorize("agent", "root/rl", SandboxCreate); err != nil {
		t.Fatal(err)
	}
	v, _ := m2.GetProject("admin", "root/rl")
	if v.Quota[QSandboxes] != 7 {
		t.Fatalf("quota = %v", v.Quota)
	}
}

// TestReleaseLeases: one command returns many leases, skips the ones not
// held, and leaves the usage of every ancestor right (spec §31).
func TestReleaseLeases(t *testing.T) {
	m, _ := setup(t)
	if _, err := m.CreateProject("admin", "root", "rl", nil); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"la", "lb", "lc"} {
		if err := m.ReserveOn(l, "root/rl", map[string]float64{QSandboxes: 1, QCPU: 2}, "e1"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := m.ReleaseLeases("", []string{"la", "lb", "nope", "la"})
	if err != nil || n != 2 {
		t.Fatalf("ReleaseLeases = %d, %v; want 2", n, err)
	}
	for _, p := range []string{"root", "root/rl"} {
		v, _ := m.GetProject("admin", p)
		if v.Usage[QSandboxes] != 1 || v.Usage[QCPU] != 2 {
			t.Fatalf("%s usage %v, want the one lease left", p, v.Usage)
		}
	}
	if got := m.EdgeLeases()["e1"]; got != 1 {
		t.Fatalf("e1 holds %d leases, want 1", got)
	}
	if n, err := m.ReleaseLeases("", []string{"la", "lb"}); err != nil || n != 0 {
		t.Fatalf("releasing again = %d, %v; want 0", n, err)
	}
	if n, err := m.ReleaseLeases("", nil); err != nil || n != 0 {
		t.Fatalf("empty = %d, %v", n, err)
	}
	_, err = m.ReleaseLeases("", make([]string, MaxReleaseLeases+1))
	wantReason(t, err, rpcutil.Invalid)
}

// TestReleaseFromEdge (spec §36): an edge returning a lease that a placement
// retry moved to another edge leaves it held; the edge it is bound to, an
// unbound lease, and the apiserver ("") release as before.
func TestReleaseFromEdge(t *testing.T) {
	m, _ := setup(t)
	m.CreateProject("admin", "root", "rl", nil)
	res := map[string]float64{QSandboxes: 1}
	m.ReserveOn("moved", "root/rl", res, "e1")
	m.ReserveOn("moved", "root/rl", res, "e2") // retried on e2
	if held, edge := m.LeaseEdge("moved"); !held || edge != "e2" {
		t.Fatalf("LeaseEdge = %v %q", held, edge)
	}
	if ok, err := m.ReleaseLease("moved", "e1"); err != nil || ok {
		t.Fatalf("e1 released a lease bound to e2: %v %v", ok, err)
	}
	if n, _ := m.ReleaseLeases("e1", []string{"moved"}); n != 0 {
		t.Fatal("e1 released it in a batch")
	}
	if v, _ := m.GetProject("admin", "root/rl"); v.Usage[QSandboxes] != 1 {
		t.Fatalf("usage %v", v.Usage)
	}
	if ok, _ := m.ReleaseLease("moved", "e2"); !ok {
		t.Fatal("e2 could not release its lease")
	}
	m.Reserve("unbound", "root/rl", res)
	m.ReserveOn("any", "root/rl", res, "e2")
	if n, _ := m.ReleaseLeases("e1", []string{"unbound"}); n != 1 {
		t.Fatal("an unbound lease was kept")
	}
	if ok, _ := m.ReleaseLease("any", ""); !ok {
		t.Fatal("a release from no edge was refused")
	}
	if held, _ := m.LeaseEdge("any"); held {
		t.Fatal("released lease still held")
	}
}
