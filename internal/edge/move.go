package edge

import (
	"context"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/peerfile"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Edge to edge (spec §26): snapshots kept on the edge that took them, and
// paused sandboxes moving to another edge.

const (
	// moveTimeout: a sandbox frozen for a move that neither completes nor is
	// aborted (its apiserver died) is usable here again after this.
	moveTimeout = createTimeout + time.Minute
	// movedRetention: how long calls for a sandbox that moved away are told
	// where it went; by then every apiserver routes it from the edges' status.
	movedRetention = 10 * time.Minute
)

type moved struct {
	to string
	at time.Time
}

// peerSource fetches snapshot files from another edge.
type peerSource struct{ c pb.EdgeClient }

func (p peerSource) FetchFile(ctx context.Context, id, name, dst string, reuse func(string) string) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // also ends the stream when the file was reused
	st, err := p.c.FetchSnapshot(ctx, &pb.FetchSnapshotRequest{SnapshotId: id, File: name})
	if err != nil {
		return "", err
	}
	var n int64
	recv := func() (*pb.SnapshotChunk, error) {
		c, err := st.Recv()
		if c != nil {
			n += int64(len(c.Data))
		}
		return c, err
	}
	cid, err := peerfile.Receive(recv, dst, reuse)
	metrics.TransferBytes("fetched", n)
	return cid, err
}

// FetchSnapshot streams a file of a snapshot one of this edge's backends
// holds.
func (s *Service) FetchSnapshot(r *pb.FetchSnapshotRequest, st pb.Edge_FetchSnapshotServer) error {
	for _, b := range s.Edge.backends {
		ps, ok := b.(backend.PeerSnapshotter)
		if !ok {
			continue
		}
		path, cid, err := ps.SnapshotFile(r.SnapshotId, r.File)
		if err != nil {
			continue
		}
		return peerfile.Send(path, cid, st.Send)
	}
	return rpcutil.Err(rpcutil.NotFound, "edge %s holds no file %s of snapshot %s", s.Edge.cfg.ID, r.File, r.SnapshotId)
}

// BeginMove freezes paused sandbox id for a move: it stays paused here,
// rejecting calls, while snapshot snapID (held here) starts it on the edge
// it moves to, which then ends the move.
func (e *Edge) BeginMove(ctx context.Context, id, snapID string) (*pb.EdgeSnapshotResponse, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	ps, ok := e.backends[r.sb.Spec.Backend].(backend.PeerSnapshotter)
	if !ok {
		return nil, rpcutil.Err(rpcutil.Invalid, "backend %q cannot move sandboxes", r.sb.Spec.Backend)
	}
	if !images.ValidSnapshotID(snapID) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", snapID)
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	if st := e.state(r); st != pb.SandboxState_PAUSED {
		return nil, rpcutil.Err(rpcutil.Invalid, "only paused sandboxes move; %s is %s", id, st)
	}
	snap, err := ps.SnapshotHeld(context.WithoutCancel(ctx), e.bsb(r), snapID)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	r.moving = e.now()
	e.mu.Unlock()
	return &pb.EdgeSnapshotResponse{SnapshotId: snap.ID, Memory: true, SizeBytes: snap.Size, Held: true}, nil
}

// EndMove completes the move of sandbox id to edge to (it runs there now:
// it is dropped here, its quota lease staying with to), or aborts it (to
// empty: usable here again).
func (e *Edge) EndMove(ctx context.Context, id, to string) error {
	e.mu.Lock()
	r := e.sbs[id]
	if r == nil {
		_, done := e.moved[id]
		e.mu.Unlock()
		if done {
			return nil // a retried EndMove
		}
		return rpcutil.Err(rpcutil.NotFound, "sandbox %s", id)
	}
	if r.moving.IsZero() {
		e.mu.Unlock()
		return rpcutil.Err(rpcutil.Invalid, "sandbox %s is not moving", id)
	}
	if to == "" {
		r.moving = time.Time{}
		e.mu.Unlock()
		return nil
	}
	r.handedOff = true
	e.moved[id] = moved{to: to, at: e.now()}
	delete(e.sbs, id)
	e.mu.Unlock()
	if err := lock(ctx, r); err != nil {
		return err
	}
	defer func() { <-r.op }()
	e.setState(r, pb.SandboxState_STOPPING)
	e.backends[r.sb.Spec.Backend].Stop(context.WithoutCancel(ctx), e.bsb(r))
	e.terminate(r, pb.SandboxState_STOPPED, "moved to edge "+to)
	return nil
}

// endMove has the edge a sandbox moved from let go of it, retrying briefly.
func (e *Edge) endMove(ctx context.Context, from *pb.EdgePeer, id string) error {
	c, err := e.Peers(from)
	if err != nil {
		return err
	}
	for try := 0; ; try++ {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_, err = c.EndMove(cctx, &pb.EndMoveRequest{SandboxId: id, ToEdge: e.cfg.ID})
		cancel()
		if err == nil || try == 2 || rpcutil.Reason(err) != rpcutil.Unavailable {
			return err
		}
		time.Sleep(time.Duration(try+1) * 200 * time.Millisecond)
	}
}

func (s *Service) BeginMove(ctx context.Context, r *pb.BeginMoveRequest) (*pb.EdgeSnapshotResponse, error) {
	return s.Edge.BeginMove(ctx, r.SandboxId, r.SnapshotId)
}

func (s *Service) EndMove(ctx context.Context, r *pb.EndMoveRequest) (*pb.Empty, error) {
	return &pb.Empty{}, s.Edge.EndMove(ctx, r.SandboxId, r.ToEdge)
}
