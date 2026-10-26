package iam

import "time"

// LiveLease is a lease an edge reports as backing a live sandbox.
type LiveLease struct {
	Lease, Project string
	Res            map[string]float64
}

type ReconcileResult struct {
	Adopted   int // live leases IAM did not know (e.g. after a restore): charged
	Bound     int // known leases now claimed by this edge
	Released  int // leases claimed by this edge whose sandbox is gone
	Conflicts int // leases reported by this edge but claimed by another one
}

// ReconcileEdge brings the leases claimed by one edge in line with what the
// edge reports as live (spec §15.2). Only the difference is proposed, so a
// steady-state reconcile writes nothing. Leases younger than minAge are never
// released (their sandbox may still be being created).
func (m *IAM) ReconcileEdge(edge string, live []LiveLease, minAge time.Duration) (ReconcileResult, error) {
	return m.ReconcileEdgeFenced(edge, live, minAge, nil)
}

// ReconcileEdgeFenced is ReconcileEdge applied only while f's holder holds
// its lock: a watcher that lost the reconcile lock cannot release leases
// from what an edge reported before.
func (m *IAM) ReconcileEdgeFenced(edge string, live []LiveLease, minAge time.Duration, f *Fence) (ReconcileResult, error) {
	now := unix(m.now())
	cutoff := now - minAge.Seconds()
	c := (&Command{Op: opReconcileEdge, Edge: edge, Now: now}).fence(f)
	var res ReconcileResult
	m.mu.RLock()
	seen := make(map[string]bool, len(live))
	for _, l := range live {
		seen[l.Lease] = true
		switch r := m.reservations[l.Lease]; {
		case r == nil:
			if m.projects[l.Project] != nil {
				c.Adopt = append(c.Adopt, &Reservation{Lease: l.Lease, Project: l.Project, Res: copyMap(l.Res), At: now, Edge: edge})
			}
		case r.Edge == "":
			c.Bind = append(c.Bind, l.Lease)
		case r.Edge != edge:
			res.Conflicts++
		}
	}
	for lease := range m.byEdge[edge] {
		if !seen[lease] && m.reservations[lease].At < cutoff {
			c.Release = append(c.Release, lease)
		}
	}
	m.mu.RUnlock()
	if len(c.Adopt)+len(c.Bind)+len(c.Release) == 0 {
		return res, nil
	}
	v, err := m.propose(c)
	if err != nil {
		return res, err
	}
	out := v.(ReconcileResult)
	out.Conflicts = res.Conflicts
	return out, nil
}

func (m *IAM) applyReconcileEdgeLocked(c *Command) ReconcileResult {
	var res ReconcileResult
	for _, r := range c.Adopt {
		if m.reservations[r.Lease] == nil && m.projects[r.Project] != nil {
			cp := *r
			cp.Res = copyMap(r.Res)
			m.addReservationLocked(&cp)
			res.Adopted++
		}
	}
	for _, l := range c.Bind {
		if r := m.reservations[l]; r != nil && r.Edge == "" {
			m.bindLocked(l, c.Edge)
			res.Bound++
		}
	}
	for _, l := range c.Release {
		if r := m.reservations[l]; r != nil && r.Edge == c.Edge && m.releaseLocked(l, c.Now) {
			res.Released++
		}
	}
	return res
}

// SweepUnbound releases leases that no edge has claimed for maxAge: their
// creation failed and the release was lost.
func (m *IAM) SweepUnbound(maxAge time.Duration) (int, error) {
	return m.SweepUnboundFenced(maxAge, nil)
}

// SweepUnboundFenced is SweepUnbound applied only while f's holder holds
// its lock.
func (m *IAM) SweepUnboundFenced(maxAge time.Duration, f *Fence) (int, error) {
	now := unix(m.now())
	cutoff := now - maxAge.Seconds()
	c := (&Command{Op: opReleaseUnbound, Now: now}).fence(f)
	m.mu.RLock()
	for lease, r := range m.reservations {
		if r.Edge == "" && r.At < cutoff {
			c.Release = append(c.Release, lease)
		}
	}
	m.mu.RUnlock()
	if len(c.Release) == 0 {
		return 0, nil
	}
	v, err := m.propose(c)
	if err != nil {
		return 0, err
	}
	return v.(int), nil
}

func (m *IAM) applyReleaseUnboundLocked(c *Command) int {
	n := 0
	for _, l := range c.Release {
		if r := m.reservations[l]; r != nil && r.Edge == "" && m.releaseLocked(l, c.Now) {
			n++
		}
	}
	return n
}

// EdgeLeases returns how many leases each edge has claimed (and "" for
// unclaimed ones); for tests and introspection.
func (m *IAM) EdgeLeases() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]int{}
	for _, r := range m.reservations {
		out[r.Edge]++
	}
	return out
}
