package edge

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Service exposes an Edge over gRPC (internal API, service-token protected).
type Service struct {
	pb.UnimplementedEdgeServer
	Edge *Edge
}

func (s *Service) Status(_ context.Context, r *pb.EdgeStatusRequest) (*pb.EdgeStatusResponse, error) {
	return s.Edge.Status(r.IncludeLeases), nil
}

func (s *Service) CreateSandbox(ctx context.Context, r *pb.EdgeCreateRequest) (*pb.Sandbox, error) {
	return s.Edge.Create(ctx, r)
}

func (s *Service) GetSandbox(_ context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.Edge.Get(r.Id)
}

func (s *Service) ListSandboxes(_ context.Context, f *pb.SandboxFilter) (*pb.SandboxList, error) {
	return &pb.SandboxList{Sandboxes: s.Edge.List(f)}, nil
}

func (s *Service) StopSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.Edge.Stop(ctx, r.Id)
}

func (s *Service) UpdateNetwork(ctx context.Context, r *pb.UpdateNetworkRequest) (*pb.Sandbox, error) {
	return s.Edge.UpdateNetwork(ctx, r.SandboxId, r.Rules, r.Replace)
}

func (s *Service) PauseSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.Edge.Pause(ctx, r.Id)
}

func (s *Service) ResumeSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.Edge.Resume(ctx, r.Id)
}

func (s *Service) TouchSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.Edge.Touch(ctx, r.Id)
}

func (s *Service) SetSandboxTimeout(ctx context.Context, r *pb.SetTimeoutRequest) (*pb.Sandbox, error) {
	return s.Edge.SetTimeout(ctx, r.SandboxId, time.Duration(r.TimeoutS)*time.Second, time.Duration(r.MaxLifetimeS)*time.Second)
}

func (s *Service) ApplyTaskAction(ctx context.Context, r *pb.EdgeTaskActionRequest) (*pb.TaskActionResult, error) {
	if r.TaskId == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "task_id required")
	}
	return s.Edge.TaskAction(ctx, r.Project, r.TaskId, r.Action), nil
}

func (s *Service) Drain(_ context.Context, r *pb.DrainRequest) (*pb.Empty, error) {
	s.Edge.SetDraining(r.Draining)
	return &pb.Empty{}, nil
}

// IAMReleaser returns a Release func that returns leases to IAM in the
// background, in batches (spec §31): leases queue up and go out as one
// ReleaseLeases call, one Raft commit, per releaseBatch leases or after
// releaseDelay, one call at a time. Ending a large task therefore costs IAM a
// few commits instead of one per sandbox, which used to stall creations
// cluster-wide. A failed batch is queued again and retried with backoff;
// leases still held when the edge goes away are reclaimed by the
// watcher-driven reconcile. An IAM without ReleaseLeases (older release) gets
// the leases one by one, and ReleaseLeases is tried again every
// releaseRetryBatch: in a rolling upgrade the edges on the IAM machines are
// upgraded before the IAM leader is.
func IAMReleaser(iam pb.IAMClient, edge string, log *slog.Logger) func(string) {
	r := &releaser{iam: iam, edge: edge, log: log, kick: make(chan struct{}, 1)}
	go r.loop()
	return r.add
}

const (
	releaseBatch    = 1000
	releaseDelay    = 50 * time.Millisecond
	releaseTimeout  = 15 * time.Second
	releaseMaxPause = 5 * time.Second
)

// releaseRetryBatch is how long an edge returns leases one by one after
// IAM answered that it has no ReleaseLeases. A var for tests.
var releaseRetryBatch = time.Minute

type releaser struct {
	iam  pb.IAMClient
	edge string // a lease bound to another edge is kept (spec §36)
	log  *slog.Logger
	kick chan struct{}

	mu      sync.Mutex
	pending []string
	single  time.Time // until then, release one by one (IAM had no ReleaseLeases)
}

func (r *releaser) add(lease string) {
	r.mu.Lock()
	r.pending = append(r.pending, lease)
	r.mu.Unlock()
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// take removes up to releaseBatch leases from the queue.
func (r *releaser) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := min(len(r.pending), releaseBatch)
	b := r.pending[:n:n]
	r.pending = r.pending[n:]
	if len(r.pending) == 0 {
		r.pending = nil // let the backing array go
	}
	return b
}

func (r *releaser) queued() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *releaser) loop() {
	pause := time.Duration(0)
	for range r.kick {
		if r.queued() < releaseBatch {
			time.Sleep(releaseDelay) // let a burst of ends gather
		}
		for b := r.take(); len(b) > 0; b = r.take() {
			if rest, err := r.send(b); err != nil {
				r.mu.Lock()
				r.pending = append(rest, r.pending...)
				n := len(r.pending)
				r.mu.Unlock()
				pause = min(max(2*pause, 200*time.Millisecond), releaseMaxPause)
				r.log.Warn("returning leases to IAM failed; retrying", "leases", n, "retry_in", pause, "err", err)
				time.Sleep(pause)
				continue
			}
			pause = 0
		}
	}
}

// send returns the leases of b to IAM; on failure, the ones still held.
func (r *releaser) send(b []string) ([]string, error) {
	if time.Now().After(r.single) {
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		_, err := r.iam.ReleaseLeases(ctx, &pb.ReleaseLeasesRequest{Leases: b, Edge: r.edge})
		cancel()
		if err == nil {
			return nil, nil
		}
		if status.Code(err) != codes.Unimplemented {
			return b, err
		}
		r.single = time.Now().Add(releaseRetryBatch)
		r.log.Info("IAM has no ReleaseLeases (older release): returning leases one by one", "retry_batch_in", releaseRetryBatch)
	}
	for i, l := range b {
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		_, err := r.iam.Release(ctx, &pb.ReleaseRequest{Lease: l, Edge: r.edge})
		cancel()
		if err != nil {
			return b[i:], err
		}
	}
	return nil, nil
}

// IAMLeaseEdge returns a LeaseEdge func asking IAM (spec §36). An IAM
// without LeaseEdge (an older release, in a rolling upgrade) is noted once:
// new sandboxes are then kept, as before.
func IAMLeaseEdge(iam pb.IAMClient, log *slog.Logger) func(context.Context, string) (bool, string, error) {
	var older sync.Once
	return func(ctx context.Context, lease string) (bool, string, error) {
		r, err := iam.LeaseEdge(ctx, &pb.LeaseEdgeRequest{Lease: lease})
		switch {
		case status.Code(err) == codes.Unimplemented:
			older.Do(func() {
				log.Info("IAM has no LeaseEdge (older release): new sandboxes are kept without checking their lease")
			})
			return false, "", err
		case err != nil:
			log.Warn("could not check the lease of a new sandbox; keeping it", "lease", lease, "err", err)
			return false, "", err
		}
		return r.Held, r.Edge, nil
	}
}

// RegisterLoop announces this edge to the watcher every interval so a
// restarted watcher rediscovers it.
func RegisterLoop(ctx context.Context, w pb.WatcherClient, id, addr, zone string, every time.Duration, log *slog.Logger) {
	for {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := w.Register(rctx, &pb.RegisterEdgeRequest{Id: id, Addr: addr, Zone: zone})
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Debug("register with watcher failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
