package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Step phases. A step goes pending -> staging -> staged -> applying ->
// verifying -> ok; a failure while applying or verifying puts the node back
// (reverting -> reverted, and the node is pinned). A failure while staging
// leaves the node untouched (failed).
const (
	phPending   = "pending"
	phStaging   = "staging"
	phStaged    = "staged"
	phApplying  = "applying"
	phVerifying = "verifying"
	phOK        = "ok"
	phFailed    = "failed"
	phReverting = "reverting"
	phReverted  = "reverted"
	phSkipped   = "skipped"
)

func terminal(phase string) bool {
	return phase == phOK || phase == phFailed || phase == phReverted || phase == phSkipped
}

func inflight(phase string) bool {
	return phase == phApplying || phase == phVerifying || phase == phReverting
}

// Rollout states.
const (
	rsRunning  = "running"
	rsPaused   = "paused"
	rsAborting = "aborting" // no new steps; waiting for those in flight
	rsAborted  = "aborted"
	rsDone     = "done"
)

// active: the controller still drives it (only one at a time).
func active(state string) bool {
	return state == rsRunning || state == rsPaused || state == rsAborting
}

const maxEvents = 200

func (s *Server) event(ro *pb.FleetRollout, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ro.Events = append(ro.Events, &pb.FleetEvent{At: s.unix(), Message: msg})
	if len(ro.Events) > maxEvents {
		ro.Events = ro.Events[len(ro.Events)-maxEvents:]
	}
	s.log.Info("rollout "+ro.Id+": "+msg, "rollout", ro.Id)
}

// tick is one controller round (leader only).
func (s *Server) tick(ctx context.Context) {
	if s.opt.Watcher != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if snap, err := s.opt.Watcher.GetSnapshot(cctx, &pb.Empty{}); err == nil {
			s.mu.Lock()
			s.snap = snap
			s.mu.Unlock()
		}
		cancel()
	}
	if !s.warm() {
		return
	}
	nodes, err := s.nodes(ctx)
	if err != nil {
		s.log.Warn("controller: read nodes", "err", err)
		return
	}
	byName := map[string]rec[*pb.FleetNode]{}
	for _, n := range nodes {
		byName[n.V.Name] = n
	}
	ops := map[string]*pb.NodeOp{}
	busy := map[string]bool{}
	ros, err := s.store.Rollouts(ctx)
	if err != nil {
		s.log.Warn("controller: read rollouts", "err", err)
		return
	}
	stat := struct {
		state    string
		progress float64
	}{}
	for _, r := range ros {
		if !active(r.V.State) {
			continue
		}
		stat.state = r.V.State
		stat.progress = s.driveRollout(ctx, r, byName, ops, busy)
		break // one at a time; CreateRollout enforces it
	}
	s.mu.Lock()
	s.rolloutStat = stat
	s.mu.Unlock()
	s.driveNodes(ctx, byName, ops, busy)
	s.setOps(ops)
}

// ---- per-node work outside rollouts: sync, cordon, retire --------------------------------

func (s *Server) driveNodes(ctx context.Context, nodes map[string]rec[*pb.FleetNode], ops map[string]*pb.NodeOp, busy map[string]bool) {
	for _, name := range sortedKeys(nodes) {
		n := nodes[name].V
		if busy[name] {
			continue
		}
		switch {
		case n.State == "cordoned":
			s.ensureDrain(ctx, n, true)
		case n.State == "retired":
			continue
		}
		if !n.Sync || (n.State != "active" && n.State != "cordoned") {
			continue
		}
		opID := fmt.Sprintf("sync/%s/%d", name, nodes[name].Rev)
		st := s.statusOf(name)
		if st != nil && st.Op.GetOpId() == opID && st.Op.GetState() != "running" {
			ok := st.Op.GetState() == "ok"
			msg := fmt.Sprintf("synced to release %s, config %d", orNone(n.Release), n.ConfigGen)
			if !ok {
				msg = "sync failed: " + st.Op.GetMessage()
			}
			if _, err := s.store.UpdateNode(ctx, name, func(m *pb.FleetNode) error {
				m.Sync, m.Message = false, msg
				if ok {
					m.DeployedRoles = rolesOf(m)
				}
				return nil
			}); err != nil {
				s.log.Warn("record sync", "node", name, "err", err)
			}
			s.log.Info("node sync finished", "node", name, "ok", ok, "msg", msg)
			s.Kick()
			continue
		}
		op, err := s.applyOp(ctx, n, n.Release, n.ConfigGen, opID, 0)
		if err != nil {
			s.log.Warn("sync op", "node", name, "err", err)
			continue
		}
		ops[name] = op
	}
}

func orNone(s string) string {
	if s == "" {
		return "(unchanged)"
	}
	return s
}

// applyOp builds the operation that puts release (if set) and config
// generation gen (if set) on node n.
// Each unit gets timeoutS to become ready (0: 180s).
func (s *Server) applyOp(ctx context.Context, n *pb.FleetNode, rel string, gen uint64, opID string, timeoutS float64) (*pb.NodeOp, error) {
	if timeoutS <= 0 {
		timeoutS = 180
	}
	op := &pb.NodeOp{OpId: opID, Kind: "apply", Release: rel, ConfigGen: gen, Units: nodeUnits(n, s.opt.Cfg.ReadyPorts),
		TimeoutS: timeoutS}
	if rel != "" {
		r, err := s.releaseRec(ctx, rel)
		if err != nil {
			return nil, err
		}
		op.Sha256, op.Size = r.Sha256, r.Size
	}
	if gen != 0 {
		c, ok, err := s.store.Config(ctx, gen)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, rpcutil.Err(rpcutil.NotFound, "config generation %d", gen)
		}
		op.Files = append(op.Files, &pb.NodeFile{Name: "opendsec.json", Content: c.ClusterJson, Mode: 0o640})
	}
	if id, ok := n.Roles["edge"]; ok {
		env := fmt.Sprintf("OPENDSEC_EDGE_ID=%s\nOPENDSEC_EDGE_ADVERTISE=%s:%d\n", id, n.Addr, s.opt.Cfg.EdgePort)
		op.Files = append(op.Files, &pb.NodeFile{Name: "edge.env", Content: []byte(env), Mode: 0o644})
	}
	return op, nil
}

// unitTimeout splits a step's timeout over the node's units, leaving room
// for the agent to put the previous release back within the step.
func unitTimeout(ro *pb.FleetRollout, n *pb.FleetNode) float64 {
	units := max(1, len(n.Roles))
	return min(180, max(5, ro.Strategy.StepTimeoutS/float64(2*units)))
}

func stageOp(r *pb.FleetRelease, opID string) *pb.NodeOp {
	return &pb.NodeOp{OpId: opID, Kind: "stage", Release: r.Version, Sha256: r.Sha256, Size: r.Size}
}

// ---- edges ------------------------------------------------------------------------------

func (s *Server) edgeState(id string) *pb.EdgeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil {
		return nil
	}
	for _, e := range s.snap.Edges {
		if e.Id == id {
			return e
		}
	}
	return nil
}

// ensureDrain sets the node's edge to draining (or not), if it has one and
// the watcher shows it in the other state.
func (s *Server) ensureDrain(ctx context.Context, n *pb.FleetNode, draining bool) error {
	id, ok := n.Roles["edge"]
	if !ok || s.opt.Watcher == nil {
		return nil
	}
	e := s.edgeState(id)
	if e == nil || !e.Healthy || e.Draining == draining {
		return nil
	}
	return s.drain(ctx, e, draining)
}

func (s *Server) drain(ctx context.Context, e *pb.EdgeState, draining bool) error {
	conn, err := s.opt.Pool.GetEdge(e.Addr, e.Id)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = pb.NewEdgeClient(conn).Drain(cctx, &pb.DrainRequest{Draining: draining})
	if err == nil {
		s.mu.Lock()
		e.Draining = draining // until the next snapshot
		s.mu.Unlock()
	}
	return err
}

// deployed is n as its units were last applied: roles added since are not
// running yet, and must not hold back the rollouts that would deploy them
// (each node's waits on the health of the others).
func deployed(n *pb.FleetNode) *pb.FleetNode {
	if len(n.DeployedRoles) == 0 {
		return n
	}
	roles := map[string]string{}
	for _, r := range n.DeployedRoles {
		if id, ok := n.Roles[r]; ok {
			roles[r] = id
		}
	}
	return &pb.FleetNode{Name: n.Name, Roles: roles}
}

// rolesOf is n's role names, sorted (deployed_roles).
func rolesOf(n *pb.FleetNode) []string {
	return sortedKeys(n.Roles)
}

// healthy reports whether node n runs well: every unit ready in its last
// (fresh) heartbeat and, for an edge, healthy in the watcher's snapshot.
func (s *Server) healthy(n *pb.FleetNode) (bool, string) {
	if !s.fresh(n.Name) {
		return false, "no recent heartbeat"
	}
	st := s.statusOf(n.Name)
	want := map[string]bool{}
	for _, u := range nodeUnits(n, s.opt.Cfg.ReadyPorts) {
		want[u.Unit] = true
	}
	for _, u := range st.Units {
		if want[u.Unit] {
			delete(want, u.Unit)
			if !u.Ready {
				return false, fmt.Sprintf("%s not ready: %s", u.Unit, u.Reason)
			}
		}
	}
	for u := range want {
		return false, u + " not reported"
	}
	if id, ok := n.Roles["edge"]; ok && s.opt.Watcher != nil {
		if e := s.edgeState(id); e == nil || !e.Healthy {
			return false, "edge " + id + " not healthy in the watcher snapshot"
		}
	}
	return true, ""
}

func (s *Server) iamLeader(n *pb.FleetNode) bool {
	st := s.statusOf(n.Name)
	if st == nil {
		return false
	}
	for _, u := range st.Units {
		if u.IamLeader {
			return true
		}
	}
	return false
}

// ---- rollouts ---------------------------------------------------------------------------

type stepRec = rec[*pb.FleetStep]

// driveRollout advances the active rollout by one round and returns its
// progress (finished steps / steps).
func (s *Server) driveRollout(ctx context.Context, rr rec[*pb.FleetRollout], nodes map[string]rec[*pb.FleetNode],
	ops map[string]*pb.NodeOp, busy map[string]bool) float64 {
	ro := proto.Clone(rr.V).(*pb.FleetRollout)
	steps, err := s.store.Steps(ctx, ro.Id)
	if err != nil {
		s.log.Warn("rollout: read steps", "rollout", ro.Id, "err", err)
		return 0
	}
	st := ro.Strategy
	timeout := config.Seconds(st.StepTimeoutS)
	now := s.unix()
	changed := false // the rollout record itself
	save := func(i int) bool {
		rev, err := s.store.PutStep(ctx, ro.Id, steps[i].V, steps[i].Rev)
		if err != nil {
			s.log.Warn("rollout: save step", "rollout", ro.Id, "node", steps[i].V.Node, "err", err)
			return false
		}
		steps[i].Rev = rev
		return true
	}
	setPhase := func(i int, phase, msg string) {
		v := steps[i].V
		v.Phase, v.Message = phase, msg
		if terminal(phase) {
			v.Finished = now
		}
		if save(i) && (phase == phFailed || phase == phReverted) {
			s.event(ro, "%s: %s (%s)", v.Node, phase, msg)
			changed = true
		}
	}
	nodeOf := func(i int) *pb.FleetNode {
		if n, ok := nodes[steps[i].V.Node]; ok {
			return n.V
		}
		return nil
	}

	// 1. Results of operations handed out earlier, and timeouts.
	for i := range steps {
		v := steps[i].V
		if terminal(v.Phase) || v.Phase == phPending || v.Phase == phStaged {
			continue
		}
		busy[v.Node] = true
		n := nodeOf(i)
		if n == nil {
			setPhase(i, phSkipped, "node removed")
			continue
		}
		if s.unix()-v.Started > timeout.Seconds() {
			switch v.Phase {
			case phStaging:
				setPhase(i, phFailed, "staging timed out")
			case phReverting:
				s.pin(ctx, n.Name, "revert timed out in rollout "+ro.Id)
				setPhase(i, phFailed, "revert timed out")
			default:
				s.startRevert(ctx, ro, &steps[i], n, "timed out after "+timeout.String(), ops, save)
			}
			continue
		}
		res := s.statusOf(v.Node).GetOp()
		done := res != nil && res.OpId == v.OpId && res.State != "running"
		switch v.Phase {
		case phStaging:
			if done {
				if res.State == "ok" {
					setPhase(i, phStaged, "")
				} else {
					setPhase(i, phFailed, "staging: "+res.Message)
				}
			}
		case phApplying:
			if done {
				if res.State == "ok" {
					setPhase(i, phVerifying, "")
				} else {
					s.startRevert(ctx, ro, &steps[i], n, res.Message, ops, save)
				}
			}
		case phVerifying:
			if ok, _ := s.healthy(n); ok {
				s.recordTarget(ctx, n.Name, v)
				if n.State != "cordoned" {
					if err := s.ensureDrain(ctx, n, false); err != nil {
						s.log.Warn("undrain", "node", n.Name, "err", err)
						continue
					}
				}
				setPhase(i, phOK, "")
			}
		case phReverting:
			if done {
				s.pin(ctx, n.Name, fmt.Sprintf("reverted by rollout %s: %s", ro.Id, v.Message))
				if res.State == "ok" {
					if n.State != "cordoned" {
						s.ensureDrain(ctx, n, false)
					}
					setPhase(i, phReverted, v.Message)
				} else {
					setPhase(i, phFailed, v.Message+"; revert failed: "+res.Message)
				}
			}
		}
	}

	// 2. Hand out the operations of steps in flight (again: agents dedupe).
	for i := range steps {
		v := steps[i].V
		n := nodeOf(i)
		if n == nil || v.OpId == "" {
			continue
		}
		switch v.Phase {
		case phStaging:
			if r, err := s.releaseRec(ctx, v.ToRelease); err == nil {
				ops[v.Node] = stageOp(r, v.OpId)
			}
		case phApplying:
			if op, err := s.applyOp(ctx, n, v.ToRelease, v.ToGen, v.OpId, unitTimeout(ro, n)); err == nil {
				ops[v.Node] = op
			}
		case phReverting:
			if op, err := s.applyOp(ctx, n, v.FromRelease, v.FromGen, v.OpId, unitTimeout(ro, n)); err == nil {
				ops[v.Node] = op
			}
		}
	}

	failures := 0
	finished := 0
	for _, x := range steps {
		if x.V.Phase == phFailed || x.V.Phase == phReverted {
			failures++
		}
		if terminal(x.V.Phase) {
			finished++
		}
	}
	progress := 1.0
	if len(steps) > 0 {
		progress = float64(finished) / float64(len(steps))
	}
	if ro.State == rsRunning && int32(failures) > st.MaxFailures {
		ro.State = rsPaused
		ro.Message = fmt.Sprintf("paused: %d failed nodes (max_failures %d)", failures, st.MaxFailures)
		s.event(ro, "%s", ro.Message)
		changed = true
	}

	// 3. Start new work while running.
	if ro.State == rsRunning {
		s.stageAhead(ctx, ro, steps, nodes, ops, busy, save)
		if s.advance(ctx, ro, steps, nodes, ops, busy, save) {
			changed = true
		}
	}

	// 4. Finish.
	anyInflight := false
	for _, x := range steps {
		anyInflight = anyInflight || inflight(x.V.Phase) || x.V.Phase == phStaging
	}
	if ro.State == rsAborting && !anyInflight {
		ro.State, ro.FinishedAt = rsAborted, now
		s.event(ro, "aborted")
		changed = true
	}
	if ro.State == rsRunning && finished == len(steps) {
		ro.State, ro.FinishedAt = rsDone, now
		if failures > 0 {
			ro.Message = fmt.Sprintf("done with %d failed nodes (pinned)", failures)
		} else {
			ro.Message = "done"
		}
		s.event(ro, "%s", ro.Message)
		changed = true
	}
	if changed {
		if _, err := s.store.PutRollout(ctx, ro, rr.Rev); err != nil {
			s.log.Warn("rollout: save", "rollout", ro.Id, "err", err)
		}
	}
	return progress
}

// recordTarget makes the step's target the node's desired state.
func (s *Server) recordTarget(ctx context.Context, node string, v *pb.FleetStep) {
	if _, err := s.store.UpdateNode(ctx, node, func(n *pb.FleetNode) error {
		if v.ToRelease != "" {
			n.Release = v.ToRelease
		}
		if v.ToGen != 0 {
			n.ConfigGen = v.ToGen
		}
		n.DeployedRoles = rolesOf(n)
		return nil
	}); err != nil {
		s.log.Warn("record node target", "node", node, "err", err)
	}
	s.Kick()
}

func (s *Server) pin(ctx context.Context, node, reason string) {
	if _, err := s.store.UpdateNode(ctx, node, func(n *pb.FleetNode) error {
		n.Pinned, n.PinnedReason = true, reason
		return nil
	}); err != nil {
		s.log.Warn("pin node", "node", node, "err", err)
	}
	s.Kick()
}

// startRevert puts the node of a failed step back where it was. A rollback
// rollout does not revert (that would redo the upgrade): it pins.
func (s *Server) startRevert(ctx context.Context, ro *pb.FleetRollout, sr *stepRec, n *pb.FleetNode, why string,
	ops map[string]*pb.NodeOp, save func(int) bool) {
	v := sr.V
	if ro.Rollback {
		v.Phase, v.Message, v.Finished = phFailed, why, s.unix()
		s.pin(ctx, n.Name, "rollback "+ro.Id+" failed: "+why)
	} else {
		v.Attempt++
		v.Phase, v.Message = phReverting, why
		v.OpId = fmt.Sprintf("%s/%s/revert/%d", ro.Id, v.Node, v.Attempt)
		v.Started = s.unix()
		if op, err := s.applyOp(ctx, n, v.FromRelease, v.FromGen, v.OpId, unitTimeout(ro, n)); err == nil {
			ops[v.Node] = op
		}
	}
	if rev, err := s.store.PutStep(ctx, ro.Id, v, sr.Rev); err == nil {
		sr.Rev = rev
		s.event(ro, "%s failed: %s; %s", v.Node, why, map[bool]string{true: "pinned", false: "reverting"}[ro.Rollback])
	} else {
		s.log.Warn("rollout: save step", "err", err)
	}
}

// stageAhead keeps downloads going for the next nodes, in batch order,
// bounded by what the replicas serve at once.
func (s *Server) stageAhead(ctx context.Context, ro *pb.FleetRollout, steps []stepRec, nodes map[string]rec[*pb.FleetNode],
	ops map[string]*pb.NodeOp, busy map[string]bool, save func(int) bool) {
	limit := s.opt.Cfg.MaxDownloads * max(1, len(s.peers))
	staging := 0
	for _, x := range steps {
		if x.V.Phase == phStaging {
			staging++
		}
	}
	order := make([]int, 0, len(steps))
	for i := range steps {
		order = append(order, i)
	}
	sort.SliceStable(order, func(a, b int) bool { return batchOrder(ro, steps[order[a]].V) < batchOrder(ro, steps[order[b]].V) })
	for _, i := range order {
		v := steps[i].V
		if v.Phase != phPending {
			continue
		}
		if v.ToRelease == "" { // config only: nothing to download
			v.Phase = phStaged
			save(i)
			continue
		}
		if staging >= limit {
			break
		}
		if !s.fresh(v.Node) {
			continue // offline: it fails when its batch comes
		}
		r, err := s.releaseRec(ctx, v.ToRelease)
		if err != nil {
			continue
		}
		v.Attempt++
		v.Phase, v.Started = phStaging, s.unix()
		v.OpId = fmt.Sprintf("%s/%s/stage/%d", ro.Id, v.Node, v.Attempt)
		if save(i) {
			ops[v.Node] = stageOp(r, v.OpId)
			busy[v.Node] = true
			staging++
		}
	}
}

// batchOrder sorts steps by when they run: the control plane first (last
// for a rollback), then edge batches in order.
func batchOrder(ro *pb.FleetRollout, v *pb.FleetStep) int {
	if v.Batch < 0 {
		if ro.Rollback {
			return 1 << 20
		}
		return -1
	}
	return int(v.Batch)
}

// advance starts the next node or batch when the previous ones are done and
// the gates pass. It reports whether the rollout record changed.
func (s *Server) advance(ctx context.Context, ro *pb.FleetRollout, steps []stepRec, nodes map[string]rec[*pb.FleetNode],
	ops map[string]*pb.NodeOp, busy map[string]bool, save func(int) bool) bool {
	st := ro.Strategy
	// Anything in flight: wait for it.
	for _, x := range steps {
		if inflight(x.V.Phase) {
			return false
		}
	}
	control := func() bool { // the control-plane phase, one node at a time
		var cand []int
		for i, x := range steps {
			if x.V.Batch < 0 && !terminal(x.V.Phase) {
				cand = append(cand, i)
			}
		}
		if len(cand) == 0 {
			return true
		}
		// The IAM leader goes last: it is restarted after its followers.
		sort.SliceStable(cand, func(a, b int) bool {
			la := s.iamLeader(nodes[steps[cand[a]].V.Node].V)
			lb := s.iamLeader(nodes[steps[cand[b]].V.Node].V)
			return !la && lb
		})
		i := cand[0]
		if steps[i].V.Phase != phStaged {
			if steps[i].V.Phase == phPending && !s.fresh(steps[i].V.Node) {
				steps[i].V.Phase, steps[i].V.Message, steps[i].V.Finished = phFailed, "no heartbeat from the node", s.unix()
				save(i)
			}
			return false
		}
		if ok, why := s.clusterHealthy(steps, nodes, steps[i].V.Node); !ok {
			s.waitMsg(ro, "waiting before "+steps[i].V.Node+": "+why)
			return false
		}
		s.startApply(ctx, ro, &steps[i], nodes, ops, busy, save, i)
		return false
	}
	edges := func() bool { // edge batches, one after the other
		for ro.Batch < ro.Batches {
			var cur []int
			for i, x := range steps {
				if x.V.Batch == ro.Batch {
					cur = append(cur, i)
				}
			}
			allDone, lastFinish := true, 0.0
			for _, i := range cur {
				allDone = allDone && terminal(steps[i].V.Phase)
				lastFinish = max(lastFinish, steps[i].V.Finished)
			}
			if allDone {
				wait := st.PauseS
				if ro.Batch == 0 && st.Canary > 0 {
					wait = st.BakeS
				}
				if len(cur) > 0 && s.unix() < lastFinish+wait {
					if s.gatePaused(ctx, ro) {
						return false
					}
					s.waitMsg(ro, fmt.Sprintf("batch %d done; next in %.0fs", ro.Batch, lastFinish+wait-s.unix()))
					return false
				}
				ro.Batch++
				if ro.Batch < ro.Batches {
					s.event(ro, "starting batch %d of %d", ro.Batch, ro.Batches-1)
				}
				continue
			}
			// Start the batch, all its nodes at once, when all are staged.
			for _, i := range cur {
				v := steps[i].V
				if v.Phase == phPending && !s.fresh(v.Node) {
					v.Phase, v.Message, v.Finished = phFailed, "no heartbeat from the node", s.unix()
					save(i)
					s.event(ro, "%s: failed (no heartbeat)", v.Node)
					continue
				}
				if v.Phase == phPending || v.Phase == phStaging {
					s.waitMsg(ro, fmt.Sprintf("batch %d: waiting for downloads", ro.Batch))
					return false
				}
			}
			if ok, why := s.clusterHealthy(steps, nodes, ""); !ok {
				s.waitMsg(ro, fmt.Sprintf("waiting before batch %d: %s", ro.Batch, why))
				return false
			}
			starting := false
			for _, i := range cur {
				starting = starting || steps[i].V.Phase == phStaged
			}
			// The gates are read again as the batch starts: the bake may
			// have ended between two reads, or have been none (pause 0).
			if starting && s.gatePaused(ctx, ro) {
				return false
			}
			for _, i := range cur {
				if steps[i].V.Phase == phStaged {
					s.startApply(ctx, ro, &steps[i], nodes, ops, busy, save, i)
				}
			}
			if starting {
				ro.GatesWaived = false
			}
			s.waitMsg(ro, fmt.Sprintf("batch %d of %d running", ro.Batch, ro.Batches-1))
			return false
		}
		return true
	}
	before := ro.Batch
	beforeMsg := ro.Message
	if ro.Rollback {
		if edges() {
			control()
		}
	} else if control() {
		edges()
	}
	return ro.Batch != before || ro.Message != beforeMsg || ro.State != rsRunning
}

// waitMsg sets the rollout's status line (saved only if it changed).
func (s *Server) waitMsg(ro *pb.FleetRollout, msg string) { ro.Message = msg }

func (s *Server) startApply(ctx context.Context, ro *pb.FleetRollout, sr *stepRec, nodes map[string]rec[*pb.FleetNode],
	ops map[string]*pb.NodeOp, busy map[string]bool, save func(int) bool, i int) {
	v := sr.V
	n := nodes[v.Node].V
	if id, ok := n.Roles["edge"]; ok && s.opt.Watcher != nil {
		if e := s.edgeState(id); e != nil && e.Healthy && !e.Draining {
			if err := s.drain(ctx, e, true); err != nil {
				s.log.Warn("drain before apply", "node", n.Name, "err", err)
				return
			}
		}
	}
	op, err := s.applyOp(ctx, n, v.ToRelease, v.ToGen, "", unitTimeout(ro, n))
	if err != nil {
		v.Phase, v.Message, v.Finished = phFailed, err.Error(), s.unix()
		save(i)
		return
	}
	v.Attempt++
	v.Phase, v.Started, v.Message = phApplying, s.unix(), ""
	v.OpId = fmt.Sprintf("%s/%s/apply/%d", ro.Id, v.Node, v.Attempt)
	op.OpId = v.OpId
	if save(i) {
		ops[v.Node] = op
		busy[v.Node] = true
	}
}

// clusterHealthy is the gate before the next node or batch: every node this
// rollout already upgraded still runs well, and so does every control-plane
// node (except, optionally, the one about to restart).
func (s *Server) clusterHealthy(steps []stepRec, nodes map[string]rec[*pb.FleetNode], except string) (bool, string) {
	for _, x := range steps {
		if x.V.Phase != phOK {
			continue
		}
		n, ok := nodes[x.V.Node]
		if !ok {
			continue
		}
		if ok, why := s.healthy(deployed(n.V)); !ok {
			return false, x.V.Node + ": " + why
		}
	}
	for _, name := range sortedKeys(nodes) {
		n := nodes[name].V
		if name == except || !isControl(n) || n.State != "active" || n.Pinned {
			continue
		}
		if ok, why := s.healthy(deployed(n)); !ok {
			return false, name + ": " + why
		}
	}
	return true, ""
}

// gatePaused pauses ro if a gate fails, and says so. A rollback is never
// stopped by them (the metrics are often why it runs), nor a rollout the
// operator resumed after a gate paused it, until its next batch started.
func (s *Server) gatePaused(ctx context.Context, ro *pb.FleetRollout) bool {
	if ro.Rollback || ro.GatesWaived {
		return false
	}
	msg := s.gates(ctx)
	if msg == "" {
		return false
	}
	ro.State = rsPaused
	ro.Message = "paused: " + msg
	s.event(ro, "%s", ro.Message)
	return true
}

// gates evaluates the configured Prometheus queries; it returns why one
// failed ("" if all pass or none are configured). A gate that cannot be
// read fails: an unknown state is no reason to go on. A query with no
// samples reads as 0 (a gate counts something bad; none happened).
func (s *Server) gates(ctx context.Context) string {
	for _, g := range s.opt.Cfg.Gates {
		v, err := promQuery(ctx, s.opt.Cfg.PrometheusURL, g.Query)
		if err != nil {
			return fmt.Sprintf("gate %s unreadable: %v", g.Name, err)
		}
		if math.IsNaN(v) || v > g.Max {
			return fmt.Sprintf("gate %s: %g > %g", g.Name, v, g.Max)
		}
	}
	return ""
}

// promQuery runs an instant query and returns the largest sample value.
func promQuery(ctx context.Context, base, q string) (float64, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", base+"/api/v1/query?query="+url.QueryEscape(q), nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Status != "success" {
		return 0, fmt.Errorf("prometheus: %s %s", resp.Status, b)
	}
	best := 0.0
	for _, x := range r.Data.Result {
		if len(x.Value) == 2 {
			if s, ok := x.Value[1].(string); ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					best = max(best, f)
				}
			}
		}
	}
	return best, nil
}
