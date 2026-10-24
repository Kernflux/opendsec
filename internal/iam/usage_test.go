package iam

import (
	"testing"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// TestUsage (spec §41): a lease's resources times its time, split at UTC
// midnight, charged to its own project; leases still held count up to now;
// subprojects included, other projects not; days filtered; project.admin
// required; kept across snapshots; pruned after usageDays.
func TestUsage(t *testing.T) {
	m, _ := setup(t)
	now := time.Date(2026, 10, 22, 23, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	for _, p := range [][2]string{{"root", "rl"}, {"root/rl", "a"}, {"root", "other"}} {
		if _, err := m.CreateProject("admin", p[0], p[1], nil); err != nil {
			t.Fatal(err)
		}
	}
	res := map[string]float64{QSandboxes: 1, QCPU: 2, QMemory: 2048, QGPUs: 1}
	if err := m.Reserve("l1", "root/rl/a", res); err != nil { // 23:00 on the 22nd
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	m.Release("l1")                 // 01:00 on the 23rd: an hour each day
	m.Reserve("l2", "root/rl", res) // still held
	m.Reserve("o1", "root/other", res)
	now = now.Add(30 * time.Minute)

	rows, err := m.Usage("admin", "root/rl", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []UsageRow{
		{Project: "root/rl/a", Day: "2026-10-22", Started: 1, SandboxS: 3600, CPUS: 7200, MemMBS: 2048 * 3600, GPUS: 3600},
		{Project: "root/rl", Day: "2026-10-23", Started: 1, SandboxS: 1800, CPUS: 3600, MemMBS: 2048 * 1800, GPUS: 1800},
		{Project: "root/rl/a", Day: "2026-10-23", SandboxS: 3600, CPUS: 7200, MemMBS: 2048 * 3600, GPUS: 3600},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Fatalf("row %d: %+v, want %+v", i, rows[i], want[i])
		}
	}
	if rows, _ := m.Usage("admin", "root/rl", "2026-10-23", "2026-10-23"); len(rows) != 2 {
		t.Fatalf("one day: %+v", rows)
	}
	if rows, _ := m.Usage("admin", "root", "", "2026-10-22"); len(rows) != 1 || rows[0].Project != "root/rl/a" {
		t.Fatalf("from root, to the 22nd: %+v", rows)
	}

	// project.admin only.
	if _, _, err := m.CreatePrincipal("admin", "root/rl", "bob", "user", 0); err != nil {
		t.Fatal(err)
	}
	m.Grant("admin", "root/rl", "bob", []string{SandboxCreate})
	_, err = m.Usage("bob", "root/rl", "", "")
	wantReason(t, err, rpcutil.Forbidden)

	// Snapshots carry it.
	m.mu.RLock()
	s := m.stateLocked(true)
	m.mu.RUnlock()
	m2 := newEmpty()
	m2.now = m.now
	m2.restoreLocked(s)
	if rows2, _ := m2.Usage("admin", "root/rl", "", ""); len(rows2) != 3 || rows2[0] != want[0] || rows2[2] != want[2] {
		t.Fatalf("after restore: %+v", rows2)
	}

	// Rows older than usageDays go when a new day starts a row.
	now = now.Add((usageDays + 1) * 24 * time.Hour)
	m.Release("l2")
	m.Release("o1")
	m.Reserve("l3", "root/rl", res)
	m.Release("l3")
	if rows, _ := m.Usage("admin", "root", "", "2026-10-23"); len(rows) != 0 {
		t.Fatalf("not pruned: %+v", rows)
	}
	if rows, _ := m.Usage("admin", "root/rl", dayOf(unix(now)), ""); len(rows) != 1 || rows[0].Started != 1 {
		t.Fatalf("today: %+v", rows)
	}
}
