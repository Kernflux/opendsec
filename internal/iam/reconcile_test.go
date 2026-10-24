package iam

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestReconcileEdge(t *testing.T) {
	m, _ := setup(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	one := map[string]float64{QSandboxes: 1}
	m.Reserve("a1", "root", one) // will be claimed by edge A
	m.Reserve("a2", "root", one) // claimed by A, then its sandbox disappears
	m.Reserve("orphan", "root", one)
	now = now.Add(2 * time.Minute) // the leases above are now older than minAge

	live := func(ls ...string) []LiveLease {
		var out []LiveLease
		for _, l := range ls {
			out = append(out, LiveLease{Lease: l, Project: "root", Res: one})
		}
		return out
	}
	// A reports a1, a2 and an unknown live lease (adopted, e.g. after a restore).
	r, err := m.ReconcileEdge("A", live("a1", "a2", "unknown"), time.Minute)
	if err != nil || r.Bound != 2 || r.Adopted != 1 || r.Released != 0 {
		t.Fatalf("first reconcile: %+v %v", r, err)
	}
	// Steady state: nothing changes, nothing is proposed.
	if r, _ := m.ReconcileEdge("A", live("a1", "a2", "unknown"), time.Minute); r != (ReconcileResult{}) {
		t.Fatalf("steady state: %+v", r)
	}
	// a2 disappears from A: released (it is older than minAge).
	if r, _ := m.ReconcileEdge("A", live("a1", "unknown"), time.Minute); r.Released != 1 {
		t.Fatalf("release: %+v", r)
	}
	// Another edge reporting A's lease is a conflict, not a takeover.
	if r, _ := m.ReconcileEdge("B", live("a1"), time.Minute); r.Conflicts != 1 || r.Bound != 0 {
		t.Fatalf("conflict: %+v", r)
	}
	// An edge that went away entirely: reconciling with no live leases frees
	// its quota, but only leases older than minAge (the adopted one is new).
	if r, _ := m.ReconcileEdge("A", nil, time.Minute); r.Released != 1 {
		t.Fatalf("lost edge (young adopted lease kept): %+v", r)
	}
	now = now.Add(2 * time.Minute)
	if r, _ := m.ReconcileEdge("A", nil, time.Minute); r.Released != 1 {
		t.Fatalf("lost edge: %+v", r)
	}
	m.Reserve("young", "root", one) // a new in-flight creation
	// Unclaimed leases: only the old orphan is swept; the in-flight one survives.
	n, err := m.SweepUnbound(time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got := m.EdgeLeases(); got[""] != 1 || len(got) != 1 {
		t.Fatalf("remaining leases: %v", got)
	}
	v, _ := m.GetProject("admin", "root")
	if v.Usage[QSandboxes] != 1 {
		t.Fatalf("usage = %v, want 1 (the young lease)", v.Usage)
	}
}

// Every replica must compute the same state from the same commands.
func TestCommandsAreDeterministic(t *testing.T) {
	// Build some state through the public API.
	m, _ := New("")
	m.Bootstrap("admin", "dsk.admin.secret", map[string]float64{QSandboxes: 10})
	m.CreateProject("admin", "root", "rl", map[string]float64{QSandboxes: 5})
	m.CreatePrincipal("admin", "root/rl", "agent", "agent", time.Hour)
	m.Grant("admin", "root/rl", "agent", []string{SandboxCreate})
	m.Reserve("l1", "root/rl", map[string]float64{QSandboxes: 1, QCPU: 2})
	m.ReconcileEdge("e1", []LiveLease{{Lease: "l1", Project: "root/rl"}}, 0)

	// Replay the same state through snapshot/restore on a fresh instance.
	s1 := snapshotBytes(t, m)
	m2 := newEmpty()
	if err := (*fsm)(m2).Restore(io.NopCloser(bytes.NewReader(s1))); err != nil {
		t.Fatal(err)
	}
	if s2 := snapshotBytes(t, m2); !jsonEqual(t, s1, s2) {
		t.Fatalf("restore is not faithful:\n%s\n%s", s1, s2)
	}
	v, _ := m2.GetProject("admin", "root")
	if v.Usage[QSandboxes] != 1 || v.Usage[QCPU] != 2 {
		t.Fatalf("usage not rebuilt from leases: %v", v.Usage)
	}
	if m2.EdgeLeases()["e1"] != 1 {
		t.Fatal("edge binding lost in snapshot")
	}

	// Applying one identical command log to two empty state machines gives
	// identical states.
	cmds := []*Command{
		{Op: opBootstrap, Now: 1, Principal: "admin", Hash: hashSecret("x"), Quota: map[string]float64{QSandboxes: 3}},
		{Op: opCreateProject, Now: 2, Actor: "admin", Parent: "root", Name: "p", Quota: map[string]float64{QCPU: 4}},
		{Op: opReserve, Now: 3, Lease: "a", Project: "root/p", Res: map[string]float64{QSandboxes: 1, QCPU: 3}},
		{Op: opReserve, Now: 4, Lease: "b", Project: "root/p", Res: map[string]float64{QSandboxes: 1, QCPU: 3}}, // fails: cpu
		{Op: opCreateToken, Now: 5, Actor: "admin", Principal: "admin", TokenID: "t1", Hash: "h", ExpiresAt: 99},
		{Op: opRelease, Now: 6, Lease: "a"},
	}
	a, b := newEmpty(), newEmpty()
	for _, c := range cmds {
		_, e1 := a.apply(c)
		_, e2 := b.apply(c)
		if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
			t.Fatalf("divergent results for %s: %v vs %v", c.Op, e1, e2)
		}
	}
	if !jsonEqual(t, snapshotBytes(t, a), snapshotBytes(t, b)) {
		t.Fatal("replicas diverged")
	}
}

func snapshotBytes(t *testing.T, m *IAM) []byte {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, err := json.Marshal(m.stateLocked(true))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jsonEqual compares two state snapshots ignoring slice order.
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	norm := func(x []byte) string {
		var s state
		json.Unmarshal(x, &s)
		m := newEmpty()
		m.restoreLocked(&s)
		// Re-marshal via maps, which encoding/json emits with sorted keys.
		out := map[string]any{"epoch": m.epoch}
		ps, pr, tk, rs := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
		for k, v := range m.principals {
			ps[k] = v
		}
		for k, v := range m.projects {
			pr[k] = map[string]any{"p": v, "usage": v.usage}
		}
		for k, v := range m.tokens {
			tk[k] = v
		}
		for k, v := range m.reservations {
			rs[k] = v
		}
		out["principals"], out["projects"], out["tokens"], out["reservations"] = ps, pr, tk, rs
		bb, _ := json.Marshal(out)
		return string(bb)
	}
	return norm(a) == norm(b)
}

func TestLeaseLock(t *testing.T) {
	m, _ := setup(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	r, err := m.AcquireLock("reconcile", "w0", 10*time.Second)
	if err != nil || !r.Acquired || r.Lock.Holder != "w0" {
		t.Fatalf("acquire: %+v %v", r, err)
	}
	if r, _ := m.AcquireLock("reconcile", "w1", 10*time.Second); r.Acquired || r.Lock.Holder != "w0" {
		t.Fatalf("w1 took a held lock: %+v", r)
	}
	now = now.Add(5 * time.Second)
	if r, _ := m.AcquireLock("reconcile", "w0", 10*time.Second); !r.Acquired {
		t.Fatal("holder could not renew")
	}
	now = now.Add(11 * time.Second) // w0 stopped renewing
	if r, _ := m.AcquireLock("reconcile", "w1", 10*time.Second); !r.Acquired || r.Lock.Holder != "w1" {
		t.Fatalf("expired lock not taken over: %+v", r)
	}
	m.ReleaseLock("reconcile", "w0") // not the holder: no effect
	if r, _ := m.AcquireLock("reconcile", "w0", 10*time.Second); r.Acquired {
		t.Fatal("release by a non-holder freed the lock")
	}
	m.ReleaseLock("reconcile", "w1")
	if r, _ := m.AcquireLock("reconcile", "w0", 10*time.Second); !r.Acquired {
		t.Fatal("lock not free after release")
	}
	// Locks survive snapshot/restore (replicated state).
	b := snapshotBytes(t, m)
	m2 := newEmpty()
	(*fsm)(m2).Restore(io.NopCloser(bytes.NewReader(b)))
	m2.now = m.now
	if r, _ := m2.AcquireLock("reconcile", "w1", 10*time.Second); r.Acquired || r.Lock.Holder != "w0" {
		t.Fatalf("lock lost in snapshot: %+v", r)
	}
}
