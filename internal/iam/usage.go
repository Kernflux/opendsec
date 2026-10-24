package iam

import (
	"sort"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Usage accounting (spec §41): what each project's sandboxes held, and for
// how long, per UTC day, from their quota leases. A lease adds its
// resources times the time it was held (running or paused: the capacity
// was its) when it is released, split at midnights; leases still held are
// added when usage is read. Rows are kept usageDays.

// UsageRow is one project's usage on one day; the time sums are seconds.
type UsageRow struct {
	Project  string  `json:"project"`
	Day      string  `json:"day"`     // 2006-01-02, UTC
	Started  int64   `json:"started"` // sandboxes started this day
	SandboxS float64 `json:"sandbox_s"`
	CPUS     float64 `json:"cpu_s"`    // core-seconds
	MemMBS   float64 `json:"mem_mb_s"` // MB-seconds
	GPUS     float64 `json:"gpu_s"`
}

// usageDays is how long rows are kept. A constant: replicas prune the same
// rows at the same commands.
const usageDays = 400

const dayLayout = "2006-01-02"

func dayOf(t float64) string { return time.Unix(int64(t), 0).UTC().Format(dayLayout) }

// accrue adds lease r held from r.At to end into rows (created as
// needed by row).
func accrue(r *Reservation, end float64, row func(project, day string) *UsageRow) {
	if end < r.At {
		end = r.At
	}
	row(r.Project, dayOf(r.At)).Started++
	for t := r.At; t < end; {
		day := time.Unix(int64(t), 0).UTC().Truncate(24 * time.Hour)
		next := float64(day.Add(24 * time.Hour).Unix())
		s := min(end, next) - t
		u := row(r.Project, day.Format(dayLayout))
		u.SandboxS += s
		u.CPUS += s * r.Res[QCPU]
		u.MemMBS += s * r.Res[QMemory]
		u.GPUS += s * r.Res[QGPUs]
		t = next
	}
}

// accrueLocked records released lease r's usage, at now (the command's
// time), pruning rows older than usageDays when it starts a new one.
func (m *IAM) accrueLocked(r *Reservation, now float64) {
	accrue(r, now, func(project, day string) *UsageRow {
		k := project + "|" + day
		u := m.usage[k]
		if u == nil {
			u = &UsageRow{Project: project, Day: day}
			m.usage[k] = u
			cutoff := dayOf(now - usageDays*86400)
			for k, x := range m.usage {
				if x.Day < cutoff {
					delete(m.usage, k)
				}
			}
		}
		return u
	})
}

// Usage returns project's and its subprojects' usage on the days from to
// to (inclusive, "" for no bound), with the leases held now counted up to
// now. The actor needs project.admin on project.
func (m *IAM) Usage(actor, project, from, to string) ([]UsageRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.projects[project] == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "project %q", project)
	}
	if err := m.authorizeLocked(actor, project, ProjectAdmin); err != nil {
		return nil, err
	}
	in := func(p, day string) bool {
		return (p == project || strings.HasPrefix(p, project+"/")) && (from == "" || day >= from) && (to == "" || day <= to)
	}
	rows := map[string]*UsageRow{}
	add := func(u UsageRow) {
		k := u.Project + "|" + u.Day
		x := rows[k]
		if x == nil {
			x = &UsageRow{Project: u.Project, Day: u.Day}
			rows[k] = x
		}
		x.Started += u.Started
		x.SandboxS += u.SandboxS
		x.CPUS += u.CPUS
		x.MemMBS += u.MemMBS
		x.GPUS += u.GPUS
	}
	for _, u := range m.usage {
		if in(u.Project, u.Day) {
			add(*u)
		}
	}
	now := unix(m.now())
	live := map[string]*UsageRow{}
	for _, r := range m.reservations {
		if r.Project == project || strings.HasPrefix(r.Project, project+"/") {
			accrue(r, now, func(p, day string) *UsageRow {
				k := p + "|" + day
				if live[k] == nil {
					live[k] = &UsageRow{Project: p, Day: day}
				}
				return live[k]
			})
		}
	}
	for _, u := range live {
		if in(u.Project, u.Day) {
			add(*u)
		}
	}
	out := make([]UsageRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].Project < out[j].Project
	})
	return out, nil
}
