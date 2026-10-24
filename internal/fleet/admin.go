package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Management calls (spec §28.8). A replica that does not lead forwards them
// to the leader, which holds the heartbeats they report and serializes
// changes with its controller. Every change kicks the controller.

func (s *Server) admin() (pb.FleetAdminClient, error) {
	if s.IsLeader() {
		return nil, nil
	}
	_, a, err := s.leaderConn()
	return a, err
}

var nodeStates = map[string]bool{"pending": true, "active": true, "cordoned": true, "retired": true}

func (s *Server) ListNodes(ctx context.Context, r *pb.FleetListNodesRequest) (*pb.FleetNodeList, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.ListNodes(forwardCtx(ctx), r)
	}
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.FleetNodeList{}
	for _, n := range ns {
		if r.State != "" && n.V.State != r.State || r.Domain != "" && n.V.Domain != r.Domain {
			continue
		}
		if _, ok := n.V.Roles[r.Role]; r.Role != "" && !ok {
			continue
		}
		out.Nodes = append(out.Nodes, s.withStatus(n.V))
	}
	return out, nil
}

func (s *Server) GetNode(ctx context.Context, r *pb.FleetNodeRef) (*pb.FleetNode, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.GetNode(forwardCtx(ctx), r)
	}
	n, ok, err := s.store.Node(ctx, r.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "node %q", r.Name)
	}
	return s.withStatus(n.V), nil
}

func validRoles(roles map[string]string) error {
	for r, id := range roles {
		switch r {
		case "iam", "watcher", "apiserver", "e2b", "fleet":
			if id == "" {
				return rpcutil.Err(rpcutil.Invalid, "role %s needs an instance id (e.g. %s=0)", r, r)
			}
		case "edge":
			if !validName(id) {
				return rpcutil.Err(rpcutil.Invalid, "edge id %q must match [a-z0-9-]{1,32}", id)
			}
		case "monitor":
		default:
			return rpcutil.Err(rpcutil.Invalid, "unknown role %q", r)
		}
	}
	return nil
}

// evacuated checks that retiring node n loses no sandbox (spec §28.7): the
// agent stops the edge at once, so it must be cordoned, draining and empty.
// The edge itself is asked: the watcher snapshot may predate a creation.
// A machine that stopped reporting has nothing left to stop and may go.
func (s *Server) evacuated(ctx context.Context, n *pb.FleetNode) error {
	id, ok := n.Roles["edge"]
	if !ok {
		return nil
	}
	hint := fmt.Sprintf("run `opendsecctl fleet node evacuate %s` first", n.Name)
	if n.State != "cordoned" {
		return rpcutil.Err(rpcutil.Invalid, "node %s is %s, not cordoned: %s", n.Name, n.State, hint)
	}
	e := s.edgeState(id)
	if e == nil || !e.Healthy {
		if !s.fresh(n.Name) {
			return nil
		}
		return rpcutil.Err(rpcutil.Unavailable, "the watcher does not report edge %s as healthy, so its sandboxes cannot be counted; retry once it is healthy, or once the machine stops reporting", id)
	}
	conn, err := s.opt.Pool.GetEdge(e.Addr, e.Id)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := pb.NewEdgeClient(conn).Status(cctx, &pb.EdgeStatusRequest{})
	if err != nil {
		return rpcutil.Err(rpcutil.Unavailable, "edge %s: %v", id, err)
	}
	if !st.State.GetDraining() {
		return rpcutil.Err(rpcutil.Unavailable, "edge %s is not draining yet; retry in a few seconds", id)
	}
	var left int32
	for _, k := range st.State.GetCountByBackend() {
		left += k
	}
	if left > 0 {
		return rpcutil.Err(rpcutil.Invalid, "%d sandboxes still on edge %s: %s", left, id, hint)
	}
	return nil
}

func (s *Server) UpdateNode(ctx context.Context, r *pb.FleetUpdateNodeRequest) (*pb.FleetNode, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.UpdateNode(forwardCtx(ctx), r)
	}
	if err := validRoles(r.Roles); err != nil {
		return nil, err
	}
	s.ctl.Lock()
	defer s.ctl.Unlock()
	actor := actorOf(ctx)
	var defRelease string
	var defGen uint64
	if r.Action == "accept" {
		var err error
		if defRelease, defGen, err = s.clusterDefaults(ctx); err != nil {
			return nil, err
		}
	}
	n, err := s.store.UpdateNode(ctx, r.Name, func(n *pb.FleetNode) error {
		set := func() {
			if r.Addr != "" {
				n.Addr = r.Addr
			}
			if r.Domain != "" {
				n.Domain = r.Domain
			}
			if len(r.Roles) > 0 {
				n.Roles = r.Roles
			}
			for k, v := range r.Labels {
				if n.Labels == nil {
					n.Labels = map[string]string{}
				}
				if v == "" {
					delete(n.Labels, k)
				} else {
					n.Labels[k] = v
				}
			}
		}
		switch r.Action {
		case "set":
			set()
		case "accept":
			if n.State != "pending" {
				return rpcutil.Err(rpcutil.Invalid, "node %s is %s, not pending", n.Name, n.State)
			}
			set()
			if len(n.Roles) == 0 {
				return rpcutil.Err(rpcutil.Invalid, "accept needs the node's roles (e.g. -roles edge=%s)", n.Name)
			}
			if n.Release == "" {
				n.Release = defRelease
			}
			if n.ConfigGen == 0 {
				n.ConfigGen = defGen
			}
			n.State, n.Sync, n.Message = "active", true, "accepted by "+actor
		case "cordon":
			if n.State != "active" {
				return rpcutil.Err(rpcutil.Invalid, "node %s is %s, not active", n.Name, n.State)
			}
			n.State = "cordoned"
		case "uncordon":
			if n.State != "cordoned" {
				return rpcutil.Err(rpcutil.Invalid, "node %s is %s, not cordoned", n.Name, n.State)
			}
			n.State = "active"
		case "retire":
			if isControl(n) {
				return rpcutil.Err(rpcutil.Invalid, "node %s runs control-plane components (%v): move them first", n.Name, n.Roles)
			}
			if err := s.evacuated(ctx, n); err != nil {
				return err
			}
			n.State, n.Sync = "retired", false
		case "pin":
			n.Pinned, n.PinnedReason = true, "pinned by "+actor+": "+r.Reason
		case "unpin":
			n.Pinned, n.PinnedReason = false, ""
		case "sync":
			if n.State != "active" && n.State != "cordoned" {
				return rpcutil.Err(rpcutil.Invalid, "node %s is %s", n.Name, n.State)
			}
			n.Sync, n.Message = true, "sync requested by "+actor
		default:
			return rpcutil.Err(rpcutil.Invalid, "unknown action %q (accept|cordon|uncordon|retire|pin|unpin|sync|set)", r.Action)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.nodesInvalid = true // the next round sees the new state
	s.mu.Unlock()
	s.log.Info("node updated", "node", r.Name, "action", r.Action, "by", actor)
	switch r.Action {
	case "cordon":
		if err := s.ensureDrain(ctx, n, true); err != nil {
			s.log.Warn("cordon: drain", "node", n.Name, "err", err)
		}
	case "uncordon":
		if err := s.ensureDrain(ctx, n, false); err != nil {
			s.log.Warn("uncordon: undrain", "node", n.Name, "err", err)
		}
	}
	s.Kick()
	return s.withStatus(n), nil
}

// clusterDefaults is what a newly accepted node runs: the release most
// active nodes are meant to run, and the latest config generation.
func (s *Server) clusterDefaults(ctx context.Context) (string, uint64, error) {
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return "", 0, err
	}
	count := map[string]int{}
	for _, n := range ns {
		if n.V.State == "active" && n.V.Release != "" {
			count[n.V.Release]++
		}
	}
	best := ""
	for _, r := range sortedKeys(count) {
		if count[r] > count[best] {
			best = r
		}
	}
	c, _, err := s.store.Config(ctx, 0)
	if err != nil {
		return "", 0, err
	}
	return best, c.Gen, nil
}

func (s *Server) ImportNodes(ctx context.Context, r *pb.FleetImportRequest) (*pb.FleetNodeList, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.ImportNodes(forwardCtx(ctx), r)
	}
	actor := actorOf(ctx)
	out := &pb.FleetNodeList{}
	for _, in := range r.Nodes {
		if !validName(in.Name) {
			return nil, rpcutil.Err(rpcutil.Invalid, "bad node name %q", in.Name)
		}
		if err := validRoles(in.Roles); err != nil {
			return nil, err
		}
		if in.Release != "" {
			if _, err := s.releaseRec(ctx, in.Release); err != nil {
				return nil, err
			}
		}
		cur, ok, err := s.store.Node(ctx, in.Name)
		if err != nil {
			return nil, err
		}
		n := proto.Clone(in).(*pb.FleetNode)
		n.Status = nil
		if n.State == "" {
			n.State = "active"
		}
		if !nodeStates[n.State] {
			return nil, rpcutil.Err(rpcutil.Invalid, "bad state %q", n.State)
		}
		if ok {
			n.CreatedAt, n.CreatedBy = cur.V.CreatedAt, cur.V.CreatedBy
		} else {
			n.CreatedAt, n.CreatedBy = s.unix(), actor
		}
		n.Message = "imported by " + actor
		if _, err := s.store.PutNode(ctx, n, cur.Rev); err != nil {
			return nil, err
		}
		out.Nodes = append(out.Nodes, n)
	}
	s.log.Info("nodes imported", "count", len(out.Nodes), "by", actor)
	s.Kick()
	return out, nil
}

func (s *Server) ListReleases(ctx context.Context, _ *pb.Empty) (*pb.FleetReleaseList, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.ListReleases(forwardCtx(ctx), &pb.Empty{})
	}
	rels, err := s.store.Releases(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	count := map[string]int32{}
	for _, n := range ns {
		if n.V.State != "retired" {
			count[n.V.Release]++
		}
	}
	out := &pb.FleetReleaseList{}
	for _, r := range rels {
		v := proto.Clone(r.V).(*pb.FleetRelease)
		v.Nodes = count[v.Version]
		out.Releases = append(out.Releases, v)
	}
	sort.Slice(out.Releases, func(i, j int) bool { return out.Releases[i].CreatedAt > out.Releases[j].CreatedAt })
	return out, nil
}

// PutConfig stores a new cluster config generation. It must parse as a
// cluster config, validate, and carry no secrets (spec §27.3): the config
// reaches every node.
func (s *Server) PutConfig(ctx context.Context, r *pb.FleetPutConfigRequest) (*pb.FleetConfig, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.PutConfig(forwardCtx(ctx), r)
	}
	var c config.Cluster
	dec := json.NewDecoder(bytes.NewReader(r.ClusterJson))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "cluster config: %v", err)
	}
	if c.ServiceToken != "" || c.IAM.AdminToken != "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "cluster config carries a secret (service_token or iam.admin_token): use tls and iam.admin_token_file")
	}
	check := c
	check.Defaults()
	if check.IAM.AdminTokenFile != "" && len(check.IAM.Replicas) > 0 {
		check.IAM.AdminToken = "set-by-file" // Validate wants one of the two
	}
	if err := check.Validate(); err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "cluster config: %v", err)
	}
	fc, err := s.store.AddConfig(ctx, &pb.FleetConfig{ClusterJson: r.ClusterJson, CreatedAt: s.unix(), CreatedBy: actorOf(ctx), Note: r.Note})
	if err != nil {
		return nil, err
	}
	s.log.Info("config stored", "gen", fc.Gen, "by", fc.CreatedBy)
	return fc, nil
}

func (s *Server) GetConfig(ctx context.Context, r *pb.FleetGetConfigRequest) (*pb.FleetConfig, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.GetConfig(forwardCtx(ctx), r)
	}
	c, ok, err := s.store.Config(ctx, r.Gen)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "config generation %d", r.Gen)
	}
	return c, nil
}

// ---- rollouts -------------------------------------------------------------------------

func (s *Server) CreateRollout(ctx context.Context, r *pb.FleetCreateRolloutRequest) (*pb.FleetRollout, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.CreateRollout(forwardCtx(ctx), r)
	}
	if r.Release == "" && r.ConfigGen == 0 {
		return nil, rpcutil.Err(rpcutil.Invalid, "a rollout needs a release, a config generation, or both")
	}
	if r.Release != "" {
		if _, err := s.releaseRec(ctx, r.Release); err != nil {
			return nil, err
		}
	}
	if r.ConfigGen != 0 {
		if _, ok, err := s.store.Config(ctx, r.ConfigGen); err != nil {
			return nil, err
		} else if !ok {
			return nil, rpcutil.Err(rpcutil.NotFound, "config generation %d", r.ConfigGen)
		}
	}
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	var picked []*pb.FleetNode
	for _, n := range ns {
		if (n.V.State == "active" || n.V.State == "cordoned") && !n.V.Pinned && Selects(r.Selector, n.V) {
			if (r.Release == "" || n.V.Release == r.Release) && (r.ConfigGen == 0 || n.V.ConfigGen == r.ConfigGen) {
				continue // already there
			}
			picked = append(picked, n.V)
		}
	}
	if len(picked) == 0 {
		return nil, rpcutil.Err(rpcutil.Invalid, "no active, unpinned node selected needs this change")
	}
	edges := 0
	for _, n := range picked {
		if !isControl(n) {
			edges++
		}
	}
	return s.createRollout(ctx, r, picked, Strategy(r.Strategy, edges), false, nil)
}

// createRollout plans and stores a rollout. For a rollback, from maps each
// node to its step in the rollout being undone.
func (s *Server) createRollout(ctx context.Context, r *pb.FleetCreateRolloutRequest, picked []*pb.FleetNode,
	st *pb.FleetStrategy, rollback bool, from map[string]*pb.FleetStep) (*pb.FleetRollout, error) {
	ros, err := s.store.Rollouts(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range ros {
		if active(x.V.State) {
			return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s is %s: finish, abort or wait for it first", x.V.Id, x.V.State)
		}
	}
	steps, batches := Plan(picked, st)
	byName := map[string]*pb.FleetNode{}
	for _, n := range picked {
		byName[n.Name] = n
	}
	id := rolloutID(s.unix(), int(s.rolloutSeq.Add(1)))
	for _, step := range steps {
		n := byName[step.Node]
		if rollback {
			f := from[step.Node]
			step.FromRelease, step.FromGen = f.ToRelease, f.ToGen
			step.ToRelease, step.ToGen = f.FromRelease, f.FromGen
		} else {
			step.FromRelease, step.FromGen = n.Release, n.ConfigGen
			step.ToRelease, step.ToGen = r.Release, r.ConfigGen
		}
		if _, err := s.store.PutStep(ctx, id, step, 0); err != nil {
			return nil, err
		}
	}
	ro := &pb.FleetRollout{Id: id, Release: r.Release, ConfigGen: r.ConfigGen, Selector: r.Selector, Strategy: st,
		State: rsRunning, CreatedAt: s.unix(), CreatedBy: actorOf(ctx), Batches: int32(batches), Note: r.Note,
		Rollback: rollback}
	s.event(ro, "created by %s: %d nodes (%d control plane), %d edge batches", ro.CreatedBy, len(steps),
		len(steps)-countBatched(steps), batches)
	if _, err := s.store.PutRollout(ctx, ro, 0); err != nil {
		return nil, err
	}
	s.Kick()
	return ro, nil
}

func countBatched(steps []*pb.FleetStep) int {
	n := 0
	for _, s := range steps {
		if s.Batch >= 0 {
			n++
		}
	}
	return n
}

func (s *Server) ControlRollout(ctx context.Context, r *pb.FleetControlRolloutRequest) (*pb.FleetRollout, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.ControlRollout(forwardCtx(ctx), r)
	}
	rr, ok, err := s.store.Rollout(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "rollout %q", r.Id)
	}
	ro := rr.V
	actor := actorOf(ctx)
	switch r.Action {
	case "pause":
		if ro.State != rsRunning {
			return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s is %s", ro.Id, ro.State)
		}
		ro.State, ro.Message = rsPaused, "paused by "+actor
	case "resume":
		if ro.State != rsPaused {
			return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s is %s", ro.Id, ro.State)
		}
		ro.State, ro.Message = rsRunning, "resumed by "+actor
		// Failures so far are accepted by resuming: raise the budget past them.
		steps, err := s.store.Steps(ctx, ro.Id)
		if err != nil {
			return nil, err
		}
		failed := int32(0)
		for _, x := range steps {
			if x.V.Phase == phFailed || x.V.Phase == phReverted {
				failed++
			}
		}
		ro.Strategy.MaxFailures = max(ro.Strategy.MaxFailures, failed)
	case "abort":
		if !active(ro.State) {
			return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s is %s", ro.Id, ro.State)
		}
		ro.State, ro.Message = rsAborting, "aborted by "+actor
	case "rollback":
		return s.rollback(ctx, rr, actor)
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "unknown action %q (pause|resume|abort|rollback)", r.Action)
	}
	s.event(ro, "%s", ro.Message)
	if _, err := s.store.PutRollout(ctx, ro, rr.Rev); err != nil {
		return nil, err
	}
	s.Kick()
	return ro, nil
}

// rollback stops rollout rr if needed and starts one that puts every node
// it upgraded back, in reverse order: edges first, the control plane last.
func (s *Server) rollback(ctx context.Context, rr rec[*pb.FleetRollout], actor string) (*pb.FleetRollout, error) {
	ro := rr.V
	if ro.Rollback {
		return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s is itself a rollback", ro.Id)
	}
	steps, err := s.store.Steps(ctx, ro.Id)
	if err != nil {
		return nil, err
	}
	for _, x := range steps {
		if inflight(x.V.Phase) {
			return nil, rpcutil.Err(rpcutil.Unavailable, "rollout %s has nodes in flight: pause it and retry when they finish", ro.Id)
		}
	}
	if active(ro.State) {
		ro.State, ro.FinishedAt, ro.Message = rsAborted, s.unix(), "rolled back by "+actor
		s.event(ro, "%s", ro.Message)
		if _, err := s.store.PutRollout(ctx, ro, rr.Rev); err != nil {
			return nil, err
		}
	}
	ns, err := s.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]*pb.FleetNode{}
	for _, n := range ns {
		byName[n.V.Name] = n.V
	}
	from := map[string]*pb.FleetStep{}
	var picked []*pb.FleetNode
	for _, x := range steps {
		if x.V.Phase != phOK {
			continue
		}
		n := byName[x.V.Node]
		if n == nil || n.State == "retired" {
			continue
		}
		from[n.Name] = x.V
		picked = append(picked, n)
	}
	if len(picked) == 0 {
		return nil, rpcutil.Err(rpcutil.Invalid, "rollout %s upgraded no node: nothing to roll back", ro.Id)
	}
	st := proto.Clone(ro.Strategy).(*pb.FleetStrategy)
	st.Canary, st.BakeS = -1, -1 // going back to what ran before: no canary
	req := &pb.FleetCreateRolloutRequest{Note: fmt.Sprintf("rollback of %s by %s", ro.Id, actor), Selector: ro.Selector}
	return s.createRollout(ctx, req, picked, Strategy(st, len(picked)), true, from)
}

func (s *Server) ListRollouts(ctx context.Context, _ *pb.Empty) (*pb.FleetRolloutList, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.ListRollouts(forwardCtx(ctx), &pb.Empty{})
	}
	ros, err := s.store.Rollouts(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.FleetRolloutList{}
	for _, r := range ros {
		v := proto.Clone(r.V).(*pb.FleetRollout)
		if len(v.Events) > 3 {
			v.Events = v.Events[len(v.Events)-3:]
		}
		out.Rollouts = append(out.Rollouts, v)
	}
	return out, nil
}

func (s *Server) GetRollout(ctx context.Context, r *pb.FleetRolloutRef) (*pb.FleetRollout, error) {
	if a, err := s.admin(); a != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return a.GetRollout(forwardCtx(ctx), r)
	}
	rr, ok, err := s.store.Rollout(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "rollout %q", r.Id)
	}
	ro := proto.Clone(rr.V).(*pb.FleetRollout)
	steps, err := s.store.Steps(ctx, ro.Id)
	if err != nil {
		return nil, err
	}
	ro.Phases = map[string]int32{}
	for _, x := range steps {
		ro.Steps = append(ro.Steps, x.V)
		ro.Phases[x.V.Phase]++
	}
	sort.SliceStable(ro.Steps, func(i, j int) bool { return batchOrder(ro, ro.Steps[i]) < batchOrder(ro, ro.Steps[j]) })
	return ro, nil
}
