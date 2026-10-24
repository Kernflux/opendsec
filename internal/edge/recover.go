package edge

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/ids"
)

// EnableStore turns on record persistence in dir.
func (e *Edge) EnableStore(dir string) error {
	s, err := newStore(dir)
	if err != nil {
		return err
	}
	e.store = s
	return nil
}

// RecoverStats summarizes a recovery pass.
type RecoverStats struct {
	Adopted int // sandboxes re-attached and serving again
	Failed  int // records whose sandbox could not be adopted (cleaned up, lease released)
	Errors  []error
}

// Recover runs once at startup, before the edge serves (spec §13.4). It
// re-adopts every persisted RUNNING/PAUSED sandbox through its backend,
// fails and releases the rest, then lets backends remove whatever remains
// on the node that no record accounts for.
func (e *Edge) Recover(ctx context.Context) RecoverStats {
	var st RecoverStats
	keep := map[string]map[string]bool{} // backend -> adopted leases
	for name := range e.backends {
		keep[name] = map[string]bool{}
	}
	if e.store != nil {
		recs, errs := e.store.load()
		st.Errors = append(st.Errors, errs...)
		for lease, sb := range recs {
			if err := e.recoverOne(ctx, lease, sb); err != nil {
				st.Failed++
				st.Errors = append(st.Errors, err)
				continue
			}
			st.Adopted++
			keep[sb.Spec.GetBackend()][lease] = true
		}
	}
	for name, b := range e.backends {
		if c, ok := b.(backend.Cleaner); ok {
			c.CleanupExcept(keep[name])
		}
	}
	if e.Net != nil {
		rules := map[string]map[string]bool{}
		e.mu.Lock()
		for _, r := range e.sbs {
			if !r.ended() {
				rules[r.lease] = r.sb.Spec.NetworkRules
				if rules[r.lease] == nil {
					rules[r.lease] = map[string]bool{}
				}
			}
		}
		e.mu.Unlock()
		e.Net.Restore(rules)
	}
	return st
}

func (e *Edge) recoverOne(ctx context.Context, lease string, sb *pb.Sandbox) error {
	// The id names this edge, or the one the sandbox moved from (spec §26.2).
	edgeID, l, err := ids.Parse(sb.Id)
	if err != nil || edgeID != e.cfg.ID && sb.EdgeId != e.cfg.ID || l != lease {
		e.store.remove(lease)
		return fmt.Errorf("record %s: id %q does not belong to this edge", lease, sb.Id)
	}
	be := e.backends[sb.Spec.GetBackend()]
	fail := func(reason string) error {
		e.store.remove(lease)
		if be != nil {
			be.Stop(ctx, &backend.Sandbox{ID: sb.Id, Project: sb.Project, Spec: sb.Spec})
		}
		e.Release(lease)
		// Keep it as ended for the stopped retention, as any other ended
		// sandbox: a client retrying the stop it sent before the crash gets
		// STOPPED, not not_found (spec §27.7).
		ended := proto.Clone(sb).(*pb.Sandbox)
		ended.State, ended.Message = pb.SandboxState_FAILED, "edge restarted: "+reason
		if sb.State == pb.SandboxState_STOPPING {
			ended.State, ended.Message = pb.SandboxState_STOPPED, "stopped (edge restarted while stopping)"
		}
		now := e.now()
		ended.EndedAt = float64(now.UnixNano()) / 1e9
		e.mu.Lock()
		if e.sbs[sb.Id] == nil {
			e.sbs[sb.Id] = &record{sb: ended, lease: lease, createdAt: time.Unix(0, int64(sb.CreatedAt*1e9)),
				lastActive: now, endedAt: now, released: true, op: make(chan struct{}, 1)}
		}
		e.mu.Unlock()
		return fmt.Errorf("sandbox %s: %s", sb.Id, reason)
	}
	if be == nil {
		return fail(fmt.Sprintf("backend %q no longer configured", sb.Spec.GetBackend()))
	}
	switch sb.State {
	case pb.SandboxState_RUNNING, pb.SandboxState_PAUSED:
	default:
		// Interrupted mid-transition (e.g. CREATING): the caller already saw
		// the operation fail, so do not resurrect it.
		return fail("interrupted in state " + sb.State.String())
	}
	ad, ok := be.(backend.Adopter)
	if !ok {
		return fail("backend cannot adopt sandboxes")
	}
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	paused, err := ad.Adopt(actx, &backend.Sandbox{ID: sb.Id, Project: sb.Project, Spec: sb.Spec, State: sb.State})
	if err != nil {
		return fail("adopt: " + err.Error())
	}
	now := e.now()
	sb.State = pb.SandboxState_RUNNING
	if paused {
		sb.State = pb.SandboxState_PAUSED // the backend's view wins over the record
	}
	r := &record{
		sb: sb, lease: lease,
		createdAt:  time.Unix(0, int64(sb.CreatedAt*1e9)),
		lastActive: now, // not persisted: give every adopted sandbox a fresh idle window
		op:         make(chan struct{}, 1),
	}
	e.mu.Lock()
	e.sbs[sb.Id] = r
	e.chargeLocked(sb.Spec, 1)
	if paused {
		e.rebateLocked(r, true)
	}
	e.mu.Unlock()
	e.persist(r)
	return nil
}
