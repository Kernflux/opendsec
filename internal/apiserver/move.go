package apiserver

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/placement"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Sandboxes that moved (spec §26.2). A sandbox id names the edge it was
// created on; one that moved runs elsewhere under the same id. Its edge is
// known from the edges' status (moved_in), from moves this apiserver made,
// and from the edge it left, which answers with where it went.

// edgeOf returns the edge running sandbox id, as far as this apiserver knows.
func (s *Server) edgeOf(id string) (string, error) {
	if e, ok := s.routes.Load(id); ok {
		return e.(string), nil
	}
	if e, ok := (*s.movedIn.Load())[id]; ok {
		return e, nil
	}
	edgeID, _, err := ids.Parse(id)
	if err != nil {
		return "", rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	return edgeID, nil
}

// indexMoved rebuilds the moved-sandbox index from a watcher snapshot, and
// drops local routes it now covers.
func (s *Server) indexMoved(snap *pb.Snapshot) {
	m := map[string]string{}
	for _, e := range snap.Edges {
		for _, id := range e.MovedIn {
			m[id] = e.Id
		}
	}
	s.movedIn.Store(&m)
	s.routes.Range(func(k, v any) bool {
		if m[k.(string)] == v.(string) {
			s.routes.Delete(k)
		}
		return true
	})
}

// onEdge runs call against the edge running sandbox id (after the usual
// authentication and sandbox.operate check), following the sandbox if it
// moved.
func onEdge[T any](s *Server, ctx context.Context, id string, call func(pb.EdgeClient) (T, error)) (T, error) {
	ec, err := s.sandboxEdge(ctx, id)
	if err != nil {
		var zero T
		return zero, err
	}
	v, err := call(ec)
	for hop := 0; hop < 3; hop++ {
		to := rpcutil.MovedTo(err)
		if to == "" {
			break
		}
		s.routes.Store(id, to)
		if ec, err = s.edgeClient(to); err != nil {
			return v, err
		}
		v, err = call(ec)
	}
	return v, err
}

// sandboxAt returns sandbox id and a client of the edge running it.
func (s *Server) sandboxAt(ctx context.Context, id string) (*pb.Sandbox, pb.EdgeClient, error) {
	sb, err := onEdge(s, ctx, id, func(ec pb.EdgeClient) (*pb.Sandbox, error) {
		return ec.GetSandbox(ctx, &pb.SandboxRef{Id: id})
	})
	if err != nil {
		return nil, nil, err
	}
	ec, err := s.edgeClient(sb.EdgeId)
	return sb, ec, err
}

// canMove reports whether this apiserver can move sandboxes: held
// snapshots are recorded in the image store.
func (s *Server) canMove() bool { return s.Images != nil }

// cannotResume reports whether err, from resuming a sandbox (or a call that
// resumes it), means its edge cannot fit it.
func cannotResume(err error) bool { return rpcutil.Reason(err) == rpcutil.NoCapacity }

// draining reports whether the edge running sandbox id is draining: a paused
// sandbox resumes elsewhere, letting the edge empty.
func (s *Server) draining(id string) bool {
	edgeID, err := s.edgeOf(id)
	if err != nil {
		return false
	}
	for _, e := range s.Engine.Snapshot().Edges {
		if e.Id == edgeID {
			return e.Draining
		}
	}
	return false
}

// moveTimeout bounds a move: the target edge fetches the snapshot and
// restores it.
const moveTimeout = 2 * time.Minute

// move resumes paused sandbox id on another edge (spec §26.2): its edge
// freezes it as a snapshot held there, another edge starts it from that
// (same id, same quota lease, rebound to that edge) and has the first let
// go of it. On failure the sandbox stays paused where it was.
func (s *Server) move(ctx context.Context, id string) (*pb.Sandbox, error) {
	t0 := time.Now()
	sb, err := s.moveOnce(ctx, id)
	if rpcutil.Reason(err) != rpcutil.Invalid { // not just "not paused"
		metrics.Move(rpcutil.ReasonOf(err), time.Since(t0))
	}
	return sb, err
}

func (s *Server) moveOnce(ctx context.Context, id string) (*pb.Sandbox, error) {
	ctx, cancel := context.WithTimeout(ctx, moveTimeout)
	defer cancel()
	from, err := s.edgeOf(id)
	if err != nil {
		return nil, err
	}
	ec, err := s.edgeClient(from)
	if err != nil {
		return nil, err
	}
	sb, err := ec.GetSandbox(ctx, &pb.SandboxRef{Id: id})
	if err != nil {
		return nil, err
	}
	if sb.State != pb.SandboxState_PAUSED {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, sb.State)
	}
	addr := (*s.addrs.Load())[from]
	snapID := images.NewSnapshotID()
	t0 := time.Now()
	if _, err := ec.BeginMove(ctx, &pb.BeginMoveRequest{SandboxId: id, SnapshotId: snapID}); err != nil {
		return nil, err
	}
	defer s.Images.DeleteSnapshot(snapID) // copies hold their own links
	_, lease, _ := ids.Parse(id)
	spec := proto.Clone(sb.Spec).(*pb.SandboxSpec)
	spec.Snapshot = snapID
	token := rpcutil.BearerToken(ctx)
	rebind := func(edge string) error {
		_, err := s.admit(context.WithoutCancel(ctx), token, &pb.AdmitRequest{Project: sb.Project,
			Perms: []string{iam.SandboxOperate}, Lease: lease, Resources: spec.Resources, Edge: edge})
		return err
	}
	req := placement.Request{Backend: spec.Backend, Res: spec.Resources, GPUMode: spec.GpuMode, Image: spec.Image, Snapshot: snapID,
		Runtime: s.snapshotRuntime(snapID)}
	exclude := map[string]bool{from: true}
	var lastErr error
	for attempt := 0; attempt < s.pcfg.MaxAttempts && ctx.Err() == nil; attempt++ {
		d, err := s.Engine.Pick(req, exclude)
		if err != nil {
			lastErr = err
			break
		}
		// The lease follows the sandbox, so the new edge's reconcile keeps it
		// (Admit on a held lease only rebinds it).
		if lastErr = rebind(d.Edge.Id); lastErr != nil {
			s.Engine.Cancel(d)
			break
		}
		var out *pb.Sandbox
		tc, err := s.edgeClient(d.Edge.Id)
		if err == nil {
			out, err = tc.CreateSandbox(ctx, &pb.EdgeCreateRequest{Id: id, Project: sb.Project, Principal: sb.Principal,
				Spec: spec, SnapshotPeer: &pb.EdgePeer{Id: from, Addr: addr}, Move: true, CreatedAt: sb.CreatedAt})
		}
		if err == nil {
			s.routes.Store(id, d.Edge.Id)
			s.log.Info("sandbox moved", "id", id, "from", from, "to", d.Edge.Id, "took", time.Since(t0))
			return out, nil
		}
		s.Engine.Cancel(d)
		lastErr = err
		switch rpcutil.Reason(err) {
		case rpcutil.NoCapacity, rpcutil.Unavailable:
			s.Engine.Penalize(d.Edge.Id)
			exclude[d.Edge.Id] = true
			continue
		}
		break
	}
	// Abort; the edge may have handed it off after all (a lost reply).
	_, aerr := ec.EndMove(context.WithoutCancel(ctx), &pb.EndMoveRequest{SandboxId: id})
	if to := rpcutil.MovedTo(aerr); to != "" {
		rebind(to)
		s.routes.Store(id, to)
		if tc, err := s.edgeClient(to); err == nil {
			return tc.GetSandbox(context.WithoutCancel(ctx), &pb.SandboxRef{Id: id})
		}
	}
	if err := rebind(from); err != nil {
		s.log.Warn("move: rebinding the lease failed; reconcile fixes it", "id", id, "err", err)
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, rpcutil.Err(rpcutil.NoCapacity, "sandbox %s cannot resume on edge %s, nor move: %s", id, from, rpcutil.Message(lastErr))
}

// resumeOrMove resumes sandbox id with call, moving it to another edge
// first when its own cannot (spec §26.2).
func (s *Server) resumeOrMove(ctx context.Context, id string, call func(pb.EdgeClient) (*pb.Sandbox, error)) (*pb.Sandbox, error) {
	if _, err := s.sandboxEdge(ctx, id); err != nil { // authenticates; checks sandbox.operate
		return nil, err
	}
	if s.canMove() && s.draining(id) {
		if sb, err := s.move(ctx, id); err == nil {
			return sb, nil
		} // not paused, or nowhere to go: resume in place
	}
	sb, err := onEdge(s, ctx, id, call)
	if s.canMove() && cannotResume(err) {
		if moved, merr := s.move(ctx, id); merr == nil {
			return moved, nil
		} else if rpcutil.Reason(merr) != rpcutil.Invalid {
			return nil, merr
		}
	}
	return sb, err
}
