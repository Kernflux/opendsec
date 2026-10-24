package apiserver

import (
	"context"
	"io"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Runtime operations: authorize sandbox.operate on the sandbox's project,
// then forward to its edge (which forwards to aether). A paused sandbox is
// resumed by its edge, or moved to another one when its edge cannot fit it
// (spec §26.2).

func forward[Req, Resp any](s *Server, ctx context.Context, id string, req Req,
	call func(pb.EdgeClient, context.Context, Req) (Resp, error)) (Resp, error) {
	do := func(ec pb.EdgeClient) (Resp, error) { return call(ec, ctx, req) }
	v, err := onEdge(s, ctx, id, do)
	if s.canMove() && cannotResume(err) {
		if _, merr := s.move(ctx, id); merr == nil {
			return onEdge(s, ctx, id, do)
		}
	}
	return v, err
}

func (s *Server) Exec(ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
		return c.Exec(ctx, r)
	})
}

func (s *Server) GetOutput(ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
		return c.GetOutput(ctx, r)
	})
}

func (s *Server) ReadFile(ctx context.Context, r *pb.FileRequest) (*pb.FileData, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileData, error) {
		return c.ReadFile(ctx, r)
	})
}

func (s *Server) WriteFile(ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
		return c.WriteFile(ctx, r)
	})
}

func (s *Server) ListDir(ctx context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
		return c.ListDir(ctx, r)
	})
}

func (s *Server) Stat(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
		return c.Stat(ctx, r)
	})
}

func (s *Server) Remove(ctx context.Context, r *pb.FileRequest) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.FileRequest) (*pb.Empty, error) {
		return c.Remove(ctx, r)
	})
}

func (s *Server) Http(ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
		return c.Http(ctx, r)
	})
}

func (s *Server) ListSessions(ctx context.Context, r *pb.SessionRef) (*pb.SessionList, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.SessionRef) (*pb.SessionList, error) {
		return c.ListSessions(ctx, r)
	})
}

func (s *Server) CloseSession(ctx context.Context, r *pb.SessionRef) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.SessionRef) (*pb.Empty, error) {
		return c.CloseSession(ctx, r)
	})
}

func (s *Server) ExecStream(r *pb.ExecRequest, st pb.DSec_ExecStreamServer) error {
	ctx := st.Context()
	open := func(ec pb.EdgeClient) (pb.Edge_ExecStreamClient, error) {
		up, err := ec.ExecStream(ctx, r)
		if err != nil {
			return nil, err
		}
		// The edge reports errors (a move, no capacity to resume) on the
		// first receive: wait for it before piping.
		first, err := up.Recv()
		if err != nil {
			return nil, err
		}
		return &prefixed{Edge_ExecStreamClient: up, first: first}, nil
	}
	up, err := onEdge(s, ctx, r.SandboxId, open)
	if s.canMove() && cannotResume(err) {
		if _, merr := s.move(ctx, r.SandboxId); merr == nil {
			up, err = onEdge(s, ctx, r.SandboxId, open)
		}
	}
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return rpcutil.PipeEvents(up, st)
}

// prefixed is a stream whose first event was already received.
type prefixed struct {
	pb.Edge_ExecStreamClient
	first *pb.ExecEvent
}

func (p *prefixed) Recv() (*pb.ExecEvent, error) {
	if ev := p.first; ev != nil {
		p.first = nil
		return ev, nil
	}
	return p.Edge_ExecStreamClient.Recv()
}

func (s *Server) MakeDir(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
		return c.MakeDir(ctx, r)
	})
}

func (s *Server) Move(ctx context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
		return c.Move(ctx, r)
	})
}

// ---- processes (spec §37) ------------------------------------------------------------

func (s *Server) StartProcess(r *pb.StartProcessRequest, st pb.DSec_StartProcessServer) error {
	return forwardStream(s, st.Context(), r.SandboxId, st, func(ec pb.EdgeClient, ctx context.Context) (eventStream[*pb.ProcessEvent], error) {
		return ec.StartProcess(ctx, r)
	})
}

func (s *Server) ConnectProcess(r *pb.ProcessRef, st pb.DSec_ConnectProcessServer) error {
	return forwardStream(s, st.Context(), r.SandboxId, st, func(ec pb.EdgeClient, ctx context.Context) (eventStream[*pb.ProcessEvent], error) {
		return ec.ConnectProcess(ctx, r)
	})
}

type eventStream[T any] interface{ Recv() (T, error) }

// forwardStream is forward for a server stream: the edge reports errors (a
// move, no capacity to resume) on the first receive, so that one is awaited
// before piping, and a sandbox that cannot resume where it is is moved.
func forwardStream[T any](s *Server, ctx context.Context, id string, down interface{ Send(T) error },
	call func(pb.EdgeClient, context.Context) (eventStream[T], error)) error {
	var first T
	open := func(ec pb.EdgeClient) (eventStream[T], error) {
		up, err := call(ec, ctx)
		if err != nil {
			return nil, err
		}
		if first, err = up.Recv(); err != nil {
			return nil, err
		}
		return up, nil
	}
	up, err := onEdge(s, ctx, id, open)
	if s.canMove() && cannotResume(err) {
		if _, merr := s.move(ctx, id); merr == nil {
			up, err = onEdge(s, ctx, id, open)
		}
	}
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if err := down.Send(first); err != nil {
		return err
	}
	return rpcutil.Pipe(up, down)
}

func (s *Server) ListProcesses(ctx context.Context, r *pb.ProcessRef) (*pb.ProcessList, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ProcessRef) (*pb.ProcessList, error) {
		return c.ListProcesses(ctx, r)
	})
}

func (s *Server) SendProcessInput(ctx context.Context, r *pb.ProcessInput) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ProcessInput) (*pb.Empty, error) {
		return c.SendProcessInput(ctx, r)
	})
}

func (s *Server) CloseProcessStdin(ctx context.Context, r *pb.ProcessRef) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ProcessRef) (*pb.Empty, error) {
		return c.CloseProcessStdin(ctx, r)
	})
}

func (s *Server) SignalProcess(ctx context.Context, r *pb.ProcessSignal) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ProcessSignal) (*pb.Empty, error) {
		return c.SignalProcess(ctx, r)
	})
}

func (s *Server) ResizeProcess(ctx context.Context, r *pb.ProcessResize) (*pb.Empty, error) {
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.ProcessResize) (*pb.Empty, error) {
		return c.ResizeProcess(ctx, r)
	})
}

// ConnectPort relays a connection to a port of a sandbox (spec §37.8),
// after the usual sandbox.operate check on the sandbox the first message
// names.
func (s *Server) ConnectPort(st pb.DSec_ConnectPortServer) error {
	first, err := st.Recv()
	if err != nil {
		return err
	}
	ctx := st.Context()
	up, err := onEdge(s, ctx, first.SandboxId, func(ec pb.EdgeClient) (pb.Edge_ConnectPortClient, error) {
		up, err := ec.ConnectPort(ctx)
		if err != nil {
			return nil, err
		}
		return up, up.Send(first)
	})
	if err != nil {
		return err
	}
	return rpcutil.PipePortStreams(st, up)
}
