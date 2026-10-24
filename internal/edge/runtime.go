package edge

import (
	"context"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// runtime prepares a runtime call on sandbox id: it resumes the sandbox if
// paused (transparent resume, paper §5), checks it is running, refreshes its
// idle TTL and pins it against idle reaping until done() is called.
func (e *Edge) runtime(ctx context.Context, id string) (rt pb.RuntimeClient, done func(), err error) {
	r, err := e.get(id)
	if err != nil {
		return nil, nil, err
	}
	be, ok := e.backends[r.sb.Spec.Backend].(backend.Runtime)
	if !ok {
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "backend %q has no runtime API", r.sb.Spec.Backend)
	}
	if err := lock(ctx, r); err != nil {
		return nil, nil, err
	}
	if e.state(r) == pb.SandboxState_PAUSED {
		if _, err := e.resumeLocked(ctx, r); err != nil {
			<-r.op
			return nil, nil, err
		}
	}
	if st := e.state(r); st != pb.SandboxState_RUNNING {
		<-r.op
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, st)
	}
	e.mu.Lock()
	r.lastActive = e.now()
	r.inflight++
	e.mu.Unlock()
	<-r.op // release before the (possibly long) call: other sessions may run concurrently
	rt, err = be.Runtime(id)
	done = func() {
		e.mu.Lock()
		r.inflight--
		r.lastActive = e.now() // a long command counts as activity until it ends
		e.mu.Unlock()
	}
	if err != nil {
		done()
		return nil, nil, err
	}
	return rt, done, nil
}

// unary runs one runtime call through runtime().
func unary[Req, Resp any](e *Edge, ctx context.Context, id string, req Req,
	call func(pb.RuntimeClient, context.Context, Req) (Resp, error)) (Resp, error) {
	var zero Resp
	rt, done, err := e.runtime(ctx, id)
	if err != nil {
		return zero, err
	}
	defer done()
	return call(rt, ctx, req)
}

func (s *Service) Exec(ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
		return c.Exec(ctx, r)
	})
}

func (s *Service) GetOutput(ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
		return c.GetOutput(ctx, r)
	})
}

func (s *Service) ReadFile(ctx context.Context, r *pb.FileRequest) (*pb.FileData, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileData, error) {
		return c.ReadFile(ctx, r)
	})
}

func (s *Service) WriteFile(ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
		return c.WriteFile(ctx, r)
	})
}

func (s *Service) ListDir(ctx context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
		return c.ListDir(ctx, r)
	})
}

func (s *Service) Stat(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
		return c.Stat(ctx, r)
	})
}

func (s *Service) Remove(ctx context.Context, r *pb.FileRequest) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.FileRequest) (*pb.Empty, error) {
		return c.Remove(ctx, r)
	})
}

func (s *Service) Http(ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
		return c.Http(ctx, r)
	})
}

func (s *Service) ListSessions(ctx context.Context, r *pb.SessionRef) (*pb.SessionList, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.SessionRef) (*pb.SessionList, error) {
		return c.ListSessions(ctx, r)
	})
}

func (s *Service) CloseSession(ctx context.Context, r *pb.SessionRef) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.SessionRef) (*pb.Empty, error) {
		return c.CloseSession(ctx, r)
	})
}

func (s *Service) ExecStream(r *pb.ExecRequest, st pb.Edge_ExecStreamServer) error {
	ctx := st.Context()
	rt, done, err := s.Edge.runtime(ctx, r.SandboxId)
	if err != nil {
		return err
	}
	defer done()
	up, err := rt.ExecStream(ctx, r)
	if err != nil {
		return err
	}
	return rpcutil.PipeEvents(up, st)
}

// PackDiff snapshots sandbox r's writable layer as a store layer. It holds
// the sandbox's operation lock so no pause/resume/stop interleaves.
func (e *Edge) PackDiff(ctx context.Context, id, layerID string, scrub []string) (*pb.EdgePackDiffResponse, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	pk, ok := e.backends[r.sb.Spec.Backend].(backend.Packer)
	if !ok {
		return nil, rpcutil.Err(rpcutil.Invalid, "backend %q cannot pack_diff", r.sb.Spec.Backend)
	}
	if !images.ValidLayerID(layerID) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad layer id %q", layerID)
	}
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	switch st := e.state(r); st {
	case pb.SandboxState_RUNNING, pb.SandboxState_PAUSED:
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, st)
	}
	all := append(append([]string{}, images.DefaultScrub...), scrub...)
	meta, err := pk.PackDiff(context.WithoutCancel(ctx), e.bsb(r), layerID, all)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	r.lastActive = e.now()
	e.mu.Unlock()
	return &pb.EdgePackDiffResponse{LayerId: meta.ID, SizeBytes: meta.Size}, nil
}

func (s *Service) PackDiff(ctx context.Context, r *pb.EdgePackDiffRequest) (*pb.EdgePackDiffResponse, error) {
	return s.Edge.PackDiff(ctx, r.SandboxId, r.LayerId, r.Scrub)
}

// Snapshot records sandbox id as snapshot snapID (spec §19), under the
// sandbox's operation lock like PackDiff. The backend pauses the sandbox for
// the duration; a paused sandbox stays paused.
// With ephemeral, a memory snapshot stays on this edge if the backend can
// keep it (spec §26.1).
func (e *Edge) Snapshot(ctx context.Context, id, snapID string, memory, preferMemory, ephemeral bool) (*pb.EdgeSnapshotResponse, error) {
	r, err := e.get(id)
	if err != nil {
		return nil, err
	}
	sn, ok := e.backends[r.sb.Spec.Backend].(backend.Snapshotter)
	if !ok {
		return nil, rpcutil.Err(rpcutil.Invalid, "backend %q cannot snapshot or fork", r.sb.Spec.Backend)
	}
	if !images.ValidSnapshotID(snapID) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", snapID)
	}
	memory = memory || preferMemory && sn.MemorySnapshots()
	if err := lock(ctx, r); err != nil {
		return nil, err
	}
	defer func() { <-r.op }()
	switch st := e.state(r); st {
	case pb.SandboxState_RUNNING, pb.SandboxState_PAUSED:
	default:
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", id, st)
	}
	var snap *images.Snapshot
	ps, held := sn.(backend.PeerSnapshotter)
	err = e.timed(r, "snapshot", func() (err error) {
		if held = held && ephemeral && memory; held {
			snap, err = ps.SnapshotHeld(context.WithoutCancel(ctx), e.bsb(r), snapID)
		} else {
			snap, err = sn.Snapshot(context.WithoutCancel(ctx), e.bsb(r), snapID, memory)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	r.lastActive = e.now()
	e.mu.Unlock()
	return &pb.EdgeSnapshotResponse{SnapshotId: snap.ID, Memory: snap.Memory, SizeBytes: snap.Size, Held: held}, nil
}

func (s *Service) Snapshot(ctx context.Context, r *pb.EdgeSnapshotRequest) (*pb.EdgeSnapshotResponse, error) {
	return s.Edge.Snapshot(ctx, r.SandboxId, r.SnapshotId, r.Memory, r.PreferMemory, r.Ephemeral)
}

func (s *Service) MakeDir(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
		return c.MakeDir(ctx, r)
	})
}

func (s *Service) Move(ctx context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
		return c.Move(ctx, r)
	})
}

// ---- processes (spec §37) ------------------------------------------------------------

func (s *Service) StartProcess(r *pb.StartProcessRequest, st pb.Edge_StartProcessServer) error {
	return processStream(s.Edge, st.Context(), r.SandboxId, st, func(c pb.RuntimeClient, ctx context.Context) (pb.Runtime_StartProcessClient, error) {
		return c.StartProcess(ctx, r)
	})
}

func (s *Service) ConnectProcess(r *pb.ProcessRef, st pb.Edge_ConnectProcessServer) error {
	return processStream(s.Edge, st.Context(), r.SandboxId, st, func(c pb.RuntimeClient, ctx context.Context) (pb.Runtime_ConnectProcessClient, error) {
		return c.ConnectProcess(ctx, r)
	})
}

type eventStream interface {
	Recv() (*pb.ProcessEvent, error)
}

// processStream relays a process's events; the sandbox counts as active
// while it is attached.
func processStream[S eventStream](e *Edge, ctx context.Context, id string,
	down interface{ Send(*pb.ProcessEvent) error }, open func(pb.RuntimeClient, context.Context) (S, error)) error {
	rt, done, err := e.runtime(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	up, err := open(rt, ctx)
	if err != nil {
		return err
	}
	return rpcutil.Pipe[*pb.ProcessEvent](up, down)
}

func (s *Service) ListProcesses(ctx context.Context, r *pb.ProcessRef) (*pb.ProcessList, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ProcessRef) (*pb.ProcessList, error) {
		return c.ListProcesses(ctx, r)
	})
}

func (s *Service) SendProcessInput(ctx context.Context, r *pb.ProcessInput) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ProcessInput) (*pb.Empty, error) {
		return c.SendProcessInput(ctx, r)
	})
}

func (s *Service) CloseProcessStdin(ctx context.Context, r *pb.ProcessRef) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ProcessRef) (*pb.Empty, error) {
		return c.CloseProcessStdin(ctx, r)
	})
}

func (s *Service) SignalProcess(ctx context.Context, r *pb.ProcessSignal) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ProcessSignal) (*pb.Empty, error) {
		return c.SignalProcess(ctx, r)
	})
}

func (s *Service) ResizeProcess(ctx context.Context, r *pb.ProcessResize) (*pb.Empty, error) {
	return unary(s.Edge, ctx, r.SandboxId, r, func(c pb.RuntimeClient, ctx context.Context, r *pb.ProcessResize) (*pb.Empty, error) {
		return c.ResizeProcess(ctx, r)
	})
}

// ConnectPort relays a connection to a port of the sandbox named by the
// first message (spec §37.8); the sandbox counts as active while it is open.
func (s *Service) ConnectPort(st pb.Edge_ConnectPortServer) error {
	first, err := st.Recv()
	if err != nil {
		return err
	}
	ctx := st.Context()
	rt, done, err := s.Edge.runtime(ctx, first.SandboxId)
	if err != nil {
		return err
	}
	defer done()
	up, err := rt.ConnectPort(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(first); err != nil {
		return err
	}
	return rpcutil.PipePortStreams(st, up)
}
