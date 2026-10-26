// Package apiserver implements the public OpenDsec API (paper §3, spec §3.3).
//
// The apiserver is the only ingress into the cluster and keeps no per-sandbox
// state: a sandbox id encodes its edge, so any instance can route any request.
// Each instance embeds its own placement engine fed by watcher snapshots.
package apiserver

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/placement"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const (
	MaxBatch         = 32768 // paper: a single job requests up to 32K sandboxes
	batchConcurrency = 256
	authCacheTTL     = 30 * time.Second
	authzCacheTTL    = 5 * time.Second
	projectCacheMax  = 1 << 20
)

type Server struct {
	pb.UnimplementedDSecServer
	cfg     config.APIServer
	pcfg    config.Placement
	iam     pb.IAMClient
	watcher pb.WatcherClient
	pool    *rpcutil.Pool
	Engine  *placement.Engine
	log     *slog.Logger

	addrs atomic.Pointer[map[string]string] // edge id -> addr
	// gone: edges missing from the latest snapshot, still routed to until
	// edgeAddrGrace after they left it.
	goneMu  sync.Mutex
	gone    map[string]goneEdge
	movedIn atomic.Pointer[map[string]string] // sandbox id -> edge, for sandboxes that moved (spec §26.2)
	routes  sync.Map                          // the same, learned since the last snapshot

	cacheMu   sync.Mutex
	authn     map[string]authnEntry // token -> principal
	authz     map[string]time.Time  // principal|project|perm -> expiry
	sbProject map[string]string     // sandbox id -> project (immutable)
	epoch     uint64                // IAM security epoch the caches were filled under
	epochSeen bool

	// Audit, if set, records every public call (spec §14.4).
	Audit *Auditor
	// Images is the shared image store (nil: store images unavailable).
	Images *images.Store

	// Admission policy (SetAdmission; spec §18).
	adm           config.Admission
	reqLimit      *limiter
	createLimit   *limiter
	authFailLimit *limiter
	inflight      chan struct{}

	lastIAM, lastSnap atomic.Int64 // unix ns of the last IAM answer and watcher snapshot (Ready)
}

type goneEdge struct {
	addr  string
	since time.Time
}

// edgeAddrGrace: an edge that drops out of the watcher snapshot keeps its
// address this long. A watcher that just restarted publishes snapshots
// without the edges it has not heard from yet; calls to their sandboxes
// meanwhile would fail as not_found, which callers do not retry.
const edgeAddrGrace = 2 * time.Minute

type authnEntry struct {
	principal string
	exp       time.Time
	byExt     bool // authenticated by an extension (ext): IAM does not know the token
}

func New(cfg config.APIServer, pcfg config.Placement, iamc pb.IAMClient, w pb.WatcherClient, pool *rpcutil.Pool, log *slog.Logger) *Server {
	s := &Server{
		cfg: cfg, pcfg: pcfg, iam: iamc, watcher: w, pool: pool,
		Engine: placement.New(pcfg), log: log,
		authn: map[string]authnEntry{}, authz: map[string]time.Time{}, sbProject: map[string]string{},
		gone: map[string]goneEdge{},
	}
	empty, none := map[string]string{}, map[string]string{}
	s.addrs.Store(&empty)
	s.movedIn.Store(&none)
	return s
}

// Run refreshes the watcher snapshot and watches the IAM security epoch
// until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	go s.watchEpoch(ctx)
	t := time.NewTicker(config.Seconds(s.cfg.SnapshotRefresh))
	defer t.Stop()
	for {
		s.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// readyStale is how long the apiserver may go without hearing from IAM or a
// watcher before it reports itself not ready (spec §27.1).
const readyStale = 15 * time.Second

// Ready reports whether the apiserver can serve: it has heard from IAM and
// got a watcher snapshot recently.
func (s *Server) Ready() error {
	now := time.Now().UnixNano()
	if t := s.lastIAM.Load(); t == 0 || now-t > int64(readyStale) {
		return errors.New("no answer from IAM")
	}
	if t := s.lastSnap.Load(); t == 0 || now-t > int64(readyStale) {
		return errors.New("no snapshot from a watcher")
	}
	return nil
}

func (s *Server) Refresh(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	snap, err := s.watcher.GetSnapshot(cctx, &pb.Empty{})
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("snapshot refresh failed; keeping last snapshot", "err", err)
		}
		return
	}
	s.lastSnap.Store(time.Now().UnixNano())
	prev := s.Engine.Snapshot()
	wasHealthy := make(map[string]bool, len(prev.Edges))
	for _, e := range prev.Edges {
		wasHealthy[e.Id] = e.Healthy
	}
	s.Engine.UpdateSnapshot(snap)
	s.goneMu.Lock()
	defer s.goneMu.Unlock()
	m := make(map[string]string, len(snap.Edges))
	for _, e := range snap.Edges {
		m[e.Id] = e.Addr
		delete(s.gone, e.Id)
		if e.Healthy && !wasHealthy[e.Id] {
			s.pool.ResetBackoff(e.Addr) // edge is back: reconnect now, not after backoff
		}
	}
	now := time.Now()
	for id, addr := range *s.addrs.Load() {
		if _, ok := m[id]; !ok {
			if _, ok := s.gone[id]; !ok {
				s.gone[id] = goneEdge{addr, now}
			}
		}
	}
	for id, g := range s.gone {
		if now.Sub(g.since) < edgeAddrGrace {
			m[id] = g.addr
		} else {
			delete(s.gone, id)
		}
	}
	s.addrs.Store(&m)
	s.indexMoved(snap)
}

// ---- auth ----------------------------------------------------------------------

// watchEpoch drops the auth caches whenever IAM reports a revocation, so a
// revoked token or grant stops working on every apiserver within ~1s
// instead of after the cache TTL (spec §14.3).
func (s *Server) watchEpoch(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		r, err := s.iam.SecurityEpoch(cctx, &pb.Empty{})
		cancel()
		if err == nil {
			s.lastIAM.Store(time.Now().UnixNano())
			s.cacheMu.Lock()
			if !s.epochSeen || r.Epoch != s.epoch {
				s.authn = map[string]authnEntry{}
				s.authz = map[string]time.Time{}
				s.epoch, s.epochSeen = r.Epoch, true
			}
			s.cacheMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// flushAuth drops cached authentication and authorization results.
func (s *Server) flushAuth() {
	s.cacheMu.Lock()
	s.authn = map[string]authnEntry{}
	s.authz = map[string]time.Time{}
	s.cacheMu.Unlock()
}

// principal authenticates the call's bearer token.
func (s *Server) principal(ctx context.Context) (string, error) {
	e, err := s.identify(ctx, rpcutil.BearerToken(ctx))
	return e.principal, err
}

// identify resolves tok to its principal, through the authentication cache.
func (s *Server) identify(ctx context.Context, tok string) (authnEntry, error) {
	if tok == "" {
		return authnEntry{}, rpcutil.Err(rpcutil.Unauthenticated, "missing bearer token")
	}
	now := time.Now()
	s.cacheMu.Lock()
	if e, ok := s.authn[tok]; ok && now.Before(e.exp) {
		s.cacheMu.Unlock()
		noteActor(ctx, e.principal)
		return e, nil
	}
	s.cacheMu.Unlock()
	e, err := s.authenticate(ctx, tok)
	if err != nil {
		return authnEntry{}, err
	}
	if exp := now.Add(authCacheTTL); e.exp.IsZero() || exp.Before(e.exp) {
		e.exp = exp // never cache a token past its own lifetime
	}
	s.cacheMu.Lock()
	if len(s.authn) > 100000 {
		s.authn = map[string]authnEntry{}
	}
	s.authn[tok] = e
	s.cacheMu.Unlock()
	noteActor(ctx, e.principal)
	return e, nil
}

// authenticate resolves a token to its principal and the token's expiry
// (zero: none): the extensions' authenticators first (ext; none in
// the open-source build), then IAM.
func (s *Server) authenticate(ctx context.Context, tok string) (authnEntry, error) {
	for _, a := range ext.Authenticators() {
		id, exp, ok, err := a.Authenticate(ctx, tok)
		if err != nil {
			return authnEntry{}, rpcutil.Err(rpcutil.Unauthenticated, "%v", err)
		}
		if ok {
			return authnEntry{principal: id, exp: exp, byExt: true}, nil
		}
	}
	p, err := s.iam.Authenticate(ctx, &pb.AuthenticateRequest{Token: tok})
	if err != nil {
		return authnEntry{}, err
	}
	e := authnEntry{principal: p.Id}
	if p.TokenExpiresAt > 0 {
		e.exp = time.Unix(0, int64(p.TokenExpiresAt*1e9))
	}
	return e, nil
}

// admit is IAM's Admit for the caller with token tok: by the token, or, for
// a token an extension authenticated (IAM does not know it), by its
// principal.
func (s *Server) admit(ctx context.Context, tok string, r *pb.AdmitRequest) (*pb.AdmitResponse, error) {
	r.Token = tok
	if len(ext.Authenticators()) > 0 {
		e, err := s.identify(ctx, tok)
		if err != nil {
			return nil, err
		}
		if e.byExt {
			r.Token, r.Principal = "", e.principal
		}
	}
	return s.iam.Admit(ctx, r)
}

func (s *Server) authorize(ctx context.Context, principal, project, perm string) error {
	key := principal + "|" + project + "|" + perm
	now := time.Now()
	s.cacheMu.Lock()
	if exp, ok := s.authz[key]; ok && now.Before(exp) {
		s.cacheMu.Unlock()
		return nil
	}
	s.cacheMu.Unlock()
	if _, err := s.iam.Authorize(ctx, &pb.AuthorizeRequest{Principal: principal, Project: project, Perm: perm}); err != nil {
		return err
	}
	s.cacheMu.Lock()
	if len(s.authz) > 100000 {
		s.authz = map[string]time.Time{}
	}
	s.authz[key] = now.Add(authzCacheTTL)
	s.cacheMu.Unlock()
	return nil
}

// ---- routing -------------------------------------------------------------------

func (s *Server) edgeClient(edgeID string) (pb.EdgeClient, error) {
	addr, ok := (*s.addrs.Load())[edgeID]
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "unknown edge %q", edgeID)
	}
	conn, err := s.pool.GetEdge(addr, edgeID)
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s: %v", edgeID, err)
	}
	return pb.NewEdgeClient(conn), nil
}

// sandboxEdge authenticates the caller, resolves the sandbox's edge and checks
// sandbox.operate on the sandbox's project.
func (s *Server) sandboxEdge(ctx context.Context, id string) (pb.EdgeClient, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	edgeID, err := s.edgeOf(id)
	if err != nil {
		return nil, err
	}
	ec, err := s.edgeClient(edgeID)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	project, ok := s.sbProject[id]
	s.cacheMu.Unlock()
	if !ok {
		sb, err := ec.GetSandbox(ctx, &pb.SandboxRef{Id: id})
		for hop := 0; hop < 3 && rpcutil.MovedTo(err) != ""; hop++ {
			to := rpcutil.MovedTo(err)
			s.routes.Store(id, to)
			if ec, err = s.edgeClient(to); err == nil {
				sb, err = ec.GetSandbox(ctx, &pb.SandboxRef{Id: id})
			}
		}
		if err != nil {
			return nil, err
		}
		project = sb.Project
		s.rememberProject(id, project)
	}
	if err := s.authorize(ctx, p, project, iam.SandboxOperate); err != nil {
		return nil, err
	}
	return ec, nil
}

func (s *Server) rememberProject(id, project string) {
	s.cacheMu.Lock()
	if len(s.sbProject) >= projectCacheMax {
		s.sbProject = map[string]string{}
	}
	s.sbProject[id] = project
	s.cacheMu.Unlock()
}

// ---- creation ---------------------------------------------------------------------

func validateSpec(sp *pb.SandboxSpec) error {
	if sp == nil {
		return rpcutil.Err(rpcutil.Invalid, "spec required")
	}
	if sp.Backend == "" {
		return rpcutil.Err(rpcutil.Invalid, "spec.backend required (sim|container|microvm|fullvm|fncall)")
	}
	r := sp.Resources
	if r.GetCpuCores() < 0 || r.GetMemoryMb() < 0 || r.GetGpus() < 0 {
		return rpcutil.Err(rpcutil.Invalid, "resources must be >= 0")
	}
	if sp.TtlRunningStopS < 0 || sp.TtlMaxS < 0 {
		return rpcutil.Err(rpcutil.Invalid, "ttls must be >= 0")
	}
	switch sp.Qos {
	case "", "LS", "BE":
	default:
		return rpcutil.Err(rpcutil.Invalid, "qos must be LS or BE")
	}
	switch sp.GpuMode {
	case "", "shared", "exclusive":
	default:
		return rpcutil.Err(rpcutil.Invalid, "gpu_mode must be shared or exclusive")
	}
	if sp.Snapshot != "" {
		return rpcutil.Err(rpcutil.Invalid, "spec.snapshot is set by ForkSandbox; create from a snapshot image instead")
	}
	if sp.Resources == nil {
		sp.Resources = &pb.Resources{}
	}
	return nil
}

func (s *Server) CreateSandbox(ctx context.Context, r *pb.CreateSandboxRequest) (*pb.Sandbox, error) {
	if err := validateSpec(r.Spec); err != nil {
		return nil, err
	}
	if err := s.applyTTLs(r.Spec); err != nil {
		return nil, err
	}
	if err := s.checkImageUse(ctx, r.Spec.Image); err != nil {
		return nil, err
	}
	s.snapshotShape(r.Spec)
	lease := r.Lease
	if r.Retry && lease != "" {
		sb, err := s.findRetried(ctx, r.Project, lease)
		if err != nil {
			return nil, err
		}
		if sb != nil && sb.State != pb.SandboxState_FAILED {
			return sb, nil
		}
		if sb != nil { // the first attempt failed (its edge crashed mid-creation): make a new one
			lease = ids.NewLease()
		}
	}
	return s.create(ctx, rpcutil.BearerToken(ctx), r.Project, r.Spec, lease, r.Retry, false, "", nil)
}

// findRetried looks for the sandbox an earlier attempt of a create with this
// lease made (spec §27.5): a client that lost the answer (an apiserver
// restart, a dropped connection) retries without creating a second one.
// The caller must be allowed to create in the project, as for the create.
func (s *Server) findRetried(ctx context.Context, project, lease string) (*pb.Sandbox, error) {
	if !ids.ValidLease(lease) {
		return nil, rpcutil.Err(rpcutil.Invalid, "lease must be 16-32 lowercase base32 chars")
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	found := make(chan *pb.Sandbox, 1)
	var wg sync.WaitGroup
	for id, ec := range s.healthyEdges() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sb, err := ec.GetSandbox(cctx, &pb.SandboxRef{Id: ids.Sandbox(id, lease)})
			if err == nil && sb.Project == project {
				select {
				case found <- sb:
				default:
				}
			}
		}()
	}
	wg.Wait()
	select {
	case sb := <-found:
		adm, err := s.admit(ctx, rpcutil.BearerToken(ctx), &pb.AdmitRequest{Project: project, Perms: []string{iam.SandboxCreate}})
		if err != nil {
			return nil, err
		}
		noteActor(ctx, adm.Principal)
		if sb.State == pb.SandboxState_STOPPED {
			return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s from this lease already ended (%s): %s", sb.Id, sb.State, sb.Message)
		}
		return sb, nil // FAILED included: the caller creates a new one
	default:
		return nil, nil
	}
}

// create runs the creation flow: rate limit -> placement -> IAM admit
// (authn + authz + quota) -> edge admission, retrying other edges on
// rejection. retry says the call retries one that may have gone through,
// so its lease may be held already. inBatch paces the creation instead of rejecting it when the
// caller is over its creation rate; prefer is an edge to place on if it can;
// peer, if set, holds the files of spec.snapshot (spec §26.1).
func (s *Server) create(ctx context.Context, token, project string, spec *pb.SandboxSpec, lease string, retry, inBatch bool,
	prefer string, peer *pb.EdgePeer) (*pb.Sandbox, error) {
	t0 := time.Now()
	sb, err := s.place(ctx, token, project, spec, lease, retry, inBatch, prefer, peer)
	metrics.APICreate(spec.Backend, rpcutil.ReasonOf(err), time.Since(t0))
	return sb, err
}

func (s *Server) place(ctx context.Context, token, project string, spec *pb.SandboxSpec, lease string, retry, inBatch bool,
	prefer string, peer *pb.EdgePeer) (*pb.Sandbox, error) {
	if token == "" {
		return nil, rpcutil.Err(rpcutil.Unauthenticated, "missing bearer token")
	}
	if s.createLimit != nil {
		p, err := s.principal(ctx)
		if err != nil {
			return nil, err
		}
		if err := s.limitCreate(ctx, p, inBatch); err != nil {
			return nil, err
		}
	}
	if err := s.acquireCreate(ctx); err != nil {
		return nil, err
	}
	defer s.releaseCreate()
	if lease == "" {
		lease = ids.NewLease()
	} else if !ids.ValidLease(lease) {
		return nil, rpcutil.Err(rpcutil.Invalid, "lease must be 16-32 lowercase base32 chars")
	}
	// Placement first, so the quota lease is bound to the chosen edge at
	// admission (a crash of that edge then releases it even before the first
	// reconcile; spec §15.2). A retry on another edge re-admits the same
	// lease, which only moves the binding.
	snapID := s.startSnapshot(spec)
	req := placement.Request{Backend: spec.Backend, Res: spec.Resources, GPUMode: spec.GpuMode, Image: spec.Image, PreferEdge: prefer,
		Snapshot: snapID, Runtime: s.snapshotRuntime(snapID)}
	exclude := map[string]bool{}
	admitted := false
	var lastErr error
	for attempt := 0; attempt < s.pcfg.MaxAttempts; attempt++ {
		d, err := s.Engine.Pick(req, exclude)
		if err != nil {
			// Out of edges after some refused: their reason says more
			// than "no edge can host" (spec §33.2).
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		// Only a retry may find its lease held (by the attempt it retries);
		// later attempts of this call move the binding.
		adm, err := s.admit(ctx, token, &pb.AdmitRequest{Project: project,
			Perms: []string{iam.SandboxCreate}, Lease: lease, Resources: spec.Resources, Edge: d.Edge.Id, Fresh: !retry && !admitted})
		if err != nil {
			s.Engine.Cancel(d)
			if admitted {
				s.releaseLease(lease)
			}
			return nil, err
		}
		admitted = true
		noteActor(ctx, adm.Principal)
		ec, err := s.edgeClient(d.Edge.Id)
		if err == nil {
			var sb *pb.Sandbox
			sb, err = ec.CreateSandbox(ctx, &pb.EdgeCreateRequest{
				Id: ids.Sandbox(d.Edge.Id, lease), Project: project, Principal: adm.Principal, Spec: spec, SnapshotPeer: peer})
			if err == nil {
				s.rememberProject(sb.Id, project)
				return sb, nil
			}
		}
		s.Engine.Cancel(d)
		lastErr = err
		switch rpcutil.Reason(err) {
		case rpcutil.NoCapacity, rpcutil.Unavailable:
			s.log.Warn("edge refused a creation; trying another", "edge", d.Edge.Id, "backend", spec.Backend,
				"reason", rpcutil.Reason(err), "err", rpcutil.Message(err))
			metrics.PlacementRetry(rpcutil.Reason(err))
			s.Engine.Penalize(d.Edge.Id)
			exclude[d.Edge.Id] = true
			if ctx.Err() != nil {
				attempt = s.pcfg.MaxAttempts
			}
			continue
		}
		break
	}
	if !admitted {
		// Nothing fit; still report auth/authz/quota-project errors first
		// (no lease: this is a read-only check).
		adm, err := s.admit(ctx, token, &pb.AdmitRequest{Project: project,
			Perms: []string{iam.SandboxCreate}})
		if err != nil {
			return nil, err
		}
		noteActor(ctx, adm.Principal)
		return nil, lastErr
	}
	s.releaseLease(lease)
	if rpcutil.Reason(lastErr) == rpcutil.Unavailable {
		return nil, rpcutil.Err(rpcutil.NoCapacity, "no edge accepted the sandbox: %s", rpcutil.Message(lastErr))
	}
	return nil, lastErr
}

func (s *Server) releaseLease(lease string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.iam.Release(ctx, &pb.ReleaseRequest{Lease: lease}); err != nil {
		s.log.Warn("lease release failed; reconcile will reclaim it", "lease", lease, "err", err)
	}
}

func (s *Server) CreateSandboxes(r *pb.CreateSandboxesRequest, stream pb.DSec_CreateSandboxesServer) error {
	if err := validateSpec(r.Spec); err != nil {
		return err
	}
	if r.Count <= 0 || r.Count > MaxBatch {
		return rpcutil.Err(rpcutil.Invalid, "count must be in [1, %d]", MaxBatch)
	}
	if err := s.applyTTLs(r.Spec); err != nil {
		return err
	}
	if err := s.checkImageUse(stream.Context(), r.Spec.Image); err != nil {
		return err
	}
	s.snapshotShape(r.Spec)
	b, err := s.newBatch(stream.Context(), r.Project, r.RequestId, r.Retry, r.Count)
	if err != nil {
		return err
	}
	return s.createMany(stream.Context(), stream.Send, r.Project, r.Spec, b, "", nil)
}

// batch is what createMany creates: count items, each with its lease when
// the call has an idempotency key. A retry of a keyed call first finds what
// the earlier attempts made (done), and gives items whose sandbox failed a
// new lease (redo).
type batch struct {
	count int32
	key   string
	retry bool // a retry of a keyed call: an item's lease may be held already
	done  map[int32]*pb.Sandbox
	redo  map[int32]bool
}

func (b *batch) remaining() int32 { return b.count - int32(len(b.done)) }

func (b *batch) lease(i int32) string {
	if b.key == "" || b.redo[i] {
		return ""
	}
	return ids.ItemLease(b.key, i)
}

func (s *Server) newBatch(ctx context.Context, project, key string, retry bool, count int32) (*batch, error) {
	b := &batch{count: count, key: key, retry: retry}
	if key == "" {
		return b, nil
	}
	if !ids.ValidRequestID(key) {
		return nil, rpcutil.Err(rpcutil.Invalid, "request_id must be 16-29 lowercase base32 chars")
	}
	if !retry {
		return b, nil
	}
	// Returning the sandboxes needs the same right as creating them.
	if _, err := s.admit(ctx, rpcutil.BearerToken(ctx), &pb.AdmitRequest{Project: project,
		Perms: []string{iam.SandboxCreate}}); err != nil {
		return nil, err
	}
	b.done, b.redo = map[int32]*pb.Sandbox{}, map[int32]bool{}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for id, ec := range s.healthyEdges() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := ec.ListSandboxes(cctx, &pb.SandboxFilter{Project: project, IncludeEnded: true})
			if err != nil {
				s.log.Warn("batch retry: edge list failed", "edge", id, "err", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, sb := range l.Sandboxes {
				_, lease, err := ids.Parse(sb.Id)
				if err != nil || sb.Project != project {
					continue
				}
				i, ok := ids.ItemIndex(key, lease)
				if !ok || i >= count {
					continue
				}
				switch sb.State {
				case pb.SandboxState_FAILED, pb.SandboxState_STOPPED:
					// The first attempt's sandbox failed or has been
					// stopped: a new one, with a new lease, takes its place.
					if b.done[i] == nil {
						b.redo[i] = true
					}
				default:
					b.done[i] = sb
					delete(b.redo, i)
				}
			}
		}()
	}
	wg.Wait()
	return b, nil
}

// createMany creates the items of b concurrently, sending one result per
// item as each completes (the ones an earlier attempt made first).
func (s *Server) createMany(ctx context.Context, send func(*pb.CreateSandboxResult) error, project string,
	spec *pb.SandboxSpec, b *batch, prefer string, peer *pb.EdgePeer) error {
	token := rpcutil.BearerToken(ctx)
	var (
		sendMu  sync.Mutex
		sendErr error
		wg      sync.WaitGroup
	)
	for i := int32(0); i < b.count; i++ {
		if sb := b.done[i]; sb != nil {
			if err := send(&pb.CreateSandboxResult{Index: i, Sandbox: sb}); err != nil {
				return err
			}
		}
	}
	sem := make(chan struct{}, batchConcurrency)
	for i := int32(0); i < b.count; i++ {
		if ctx.Err() != nil {
			break
		}
		if b.done[i] != nil {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int32) {
			defer func() { <-sem; wg.Done() }()
			sb, err := s.create(ctx, token, project, spec, b.lease(i), b.retry, true, prefer, peer)
			res := &pb.CreateSandboxResult{Index: i, Sandbox: sb}
			if err != nil {
				res.ErrorReason, res.ErrorMessage = rpcutil.Reason(err), rpcutil.Message(err)
			}
			sendMu.Lock()
			defer sendMu.Unlock()
			if sendErr == nil {
				sendErr = send(res)
			}
		}(i)
	}
	wg.Wait()
	return sendErr
}

// ---- per-sandbox operations -------------------------------------------------------

func (s *Server) GetSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return onEdge(s, ctx, r.Id, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.GetSandbox(ctx, r) })
}

func (s *Server) StopSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return onEdge(s, ctx, r.Id, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.StopSandbox(ctx, r) })
}

// UpdateNetwork changes a sandbox's network rules (spec §20); needs
// sandbox.operate, like the other operations on it.
func (s *Server) UpdateNetwork(ctx context.Context, r *pb.UpdateNetworkRequest) (*pb.Sandbox, error) {
	return onEdge(s, ctx, r.SandboxId, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.UpdateNetwork(ctx, r) })
}

func (s *Server) PauseSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return onEdge(s, ctx, r.Id, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.PauseSandbox(ctx, r) })
}

// ResumeSandbox resumes a paused sandbox, on another edge if its own cannot
// fit it or is draining (spec §26.2).
func (s *Server) ResumeSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.resumeOrMove(ctx, r.Id, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.ResumeSandbox(ctx, r) })
}

func (s *Server) TouchSandbox(ctx context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return s.resumeOrMove(ctx, r.Id, func(ec pb.EdgeClient) (*pb.Sandbox, error) { return ec.TouchSandbox(ctx, r) })
}

// SetSandboxTimeout ends the sandbox timeout_s from now (spec §37), within
// the admission cap on its lifetime.
func (s *Server) SetSandboxTimeout(ctx context.Context, r *pb.SetTimeoutRequest) (*pb.Sandbox, error) {
	if r.TimeoutS <= 0 {
		return nil, rpcutil.Err(rpcutil.Invalid, "timeout_s must be > 0")
	}
	r.MaxLifetimeS = int64(s.adm.MaxTTLMax)
	return forward(s, ctx, r.SandboxId, r, func(c pb.EdgeClient, ctx context.Context, r *pb.SetTimeoutRequest) (*pb.Sandbox, error) {
		return c.SetSandboxTimeout(ctx, r)
	})
}

// ---- fan-out operations -------------------------------------------------------------

// healthyEdges returns clients for every healthy edge in the current snapshot.
func (s *Server) healthyEdges() map[string]pb.EdgeClient {
	out := map[string]pb.EdgeClient{}
	for _, e := range s.Engine.Snapshot().Edges {
		if !e.Healthy {
			continue
		}
		if ec, err := s.edgeClient(e.Id); err == nil {
			out[e.Id] = ec
		}
	}
	return out
}

func (s *Server) ListSandboxes(ctx context.Context, f *pb.SandboxFilter) (*pb.SandboxList, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if f.Project == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "project required")
	}
	if err := s.authorize(ctx, p, f.Project, iam.SandboxOperate); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := &pb.SandboxList{}
	for id, ec := range s.healthyEdges() {
		wg.Add(1)
		go func(id string, ec pb.EdgeClient) {
			defer wg.Done()
			l, err := ec.ListSandboxes(ctx, f)
			if err != nil {
				s.log.Warn("list: edge failed", "edge", id, "err", err)
				return
			}
			mu.Lock()
			out.Sandboxes = append(out.Sandboxes, l.Sandboxes...)
			mu.Unlock()
		}(id, ec)
	}
	wg.Wait()
	return out, nil
}

// ApplyTaskAction pauses/resumes/stops every sandbox of a task. It fans out to
// all healthy edges rather than only those the snapshot lists for the task:
// the snapshot can lag recent placements by other apiserver instances.
func (s *Server) ApplyTaskAction(ctx context.Context, r *pb.TaskActionRequest) (*pb.TaskActionResult, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if r.Project == "" || r.TaskId == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "project and task_id required")
	}
	if err := s.authorize(ctx, p, r.Project, iam.SandboxOperate); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	total := &pb.TaskActionResult{}
	for id, ec := range s.healthyEdges() {
		wg.Add(1)
		go func(id string, ec pb.EdgeClient) {
			defer wg.Done()
			res, err := ec.ApplyTaskAction(ctx, &pb.EdgeTaskActionRequest{Project: r.Project, TaskId: r.TaskId, Action: r.Action})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				total.Errors = append(total.Errors, id+": "+err.Error())
				return
			}
			total.Affected += res.Affected
			total.Failed += res.Failed
			total.Errors = append(total.Errors, res.Errors...)
		}(id, ec)
	}
	wg.Wait()
	return total, nil
}

func (s *Server) ClusterStatus(ctx context.Context, _ *pb.Empty) (*pb.Snapshot, error) {
	if _, err := s.principal(ctx); err != nil {
		return nil, err
	}
	snap := s.Engine.Snapshot()
	if n := ext.Notices(); len(n) > 0 { // a copy: the snapshot is shared
		snap = &pb.Snapshot{Version: snap.Version, TakenAt: snap.TakenAt, Edges: snap.Edges, Notices: n}
	}
	return snap, nil
}

// HostCPUs counts the CPU threads of the hosts the cluster's edges run on,
// each host once.
func (s *Server) HostCPUs() int {
	hosts := map[string]int32{}
	for _, e := range s.Engine.Snapshot().GetEdges() {
		h := e.HostId
		if h == "" {
			h = "edge/" + e.Id
		}
		hosts[h] = max(hosts[h], e.HostCpus)
	}
	n := 0
	for _, c := range hosts {
		n += int(c)
	}
	return n
}

// DrainEdge stops or resumes placement on an edge (maintenance). Cluster
// admins only: project.admin on root.
func (s *Server) DrainEdge(ctx context.Context, r *pb.DrainEdgeRequest) (*pb.Empty, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, p, "root", iam.ProjectAdmin); err != nil {
		return nil, err
	}
	ec, err := s.edgeClient(r.EdgeId)
	if err != nil {
		return nil, err
	}
	if _, err := ec.Drain(ctx, &pb.DrainRequest{Draining: r.Draining}); err != nil {
		return nil, err
	}
	s.Refresh(ctx) // placement sees it now, not at the next snapshot
	return &pb.Empty{}, nil
}

// ---- IAM management (actor = authenticated principal) ------------------------------------

func (s *Server) WhoAmI(ctx context.Context, _ *pb.Empty) (*pb.Principal, error) {
	tok := rpcutil.BearerToken(ctx)
	if len(ext.Authenticators()) > 0 {
		e, err := s.identify(ctx, tok)
		if err != nil {
			return nil, err
		}
		if e.byExt {
			return &pb.Principal{Id: e.principal}, nil
		}
	}
	p, err := s.iam.Authenticate(ctx, &pb.AuthenticateRequest{Token: tok})
	if err == nil {
		noteActor(ctx, p.Id)
	}
	return p, err
}

func (s *Server) CreateProject(ctx context.Context, r *pb.CreateProjectRequest) (*pb.Project, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.CreateProject(ctx, r)
}

func (s *Server) CreatePrincipal(ctx context.Context, r *pb.CreatePrincipalRequest) (*pb.CreatePrincipalResponse, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.CreatePrincipal(ctx, r)
}

func (s *Server) Grant(ctx context.Context, r *pb.GrantRequest) (*pb.Project, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.Grant(ctx, r)
}

func (s *Server) Revoke(ctx context.Context, r *pb.RevokeRequest) (*pb.Project, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	defer s.flushAuth() // takes effect on this instance at once, elsewhere via the epoch
	return s.iam.Revoke(ctx, r)
}

func (s *Server) CreateToken(ctx context.Context, r *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.CreateToken(ctx, r)
}

func (s *Server) ListTokens(ctx context.Context, r *pb.ListTokensRequest) (*pb.TokenList, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	if r.Principal == "" {
		r.Principal = p
	}
	return s.iam.ListTokens(ctx, r)
}

func (s *Server) RevokeToken(ctx context.Context, r *pb.RevokeTokenRequest) (*pb.Empty, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	defer s.flushAuth()
	return s.iam.RevokeToken(ctx, r)
}

func (s *Server) DeletePrincipal(ctx context.Context, r *pb.DeletePrincipalRequest) (*pb.Empty, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	defer s.flushAuth()
	return s.iam.DeletePrincipal(ctx, r)
}

func (s *Server) DeleteProject(ctx context.Context, r *pb.DeleteProjectRequest) (*pb.Empty, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	defer s.flushAuth()
	return s.iam.DeleteProject(ctx, r)
}

func (s *Server) SetQuota(ctx context.Context, r *pb.SetQuotaRequest) (*pb.Project, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.SetQuota(ctx, r)
}

func (s *Server) GetProject(ctx context.Context, r *pb.GetProjectRequest) (*pb.Project, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.GetProject(ctx, r)
}

func (s *Server) GetUsage(ctx context.Context, r *pb.UsageRequest) (*pb.UsageReport, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	r.Actor = p
	return s.iam.GetUsage(ctx, r)
}

// startSnapshot is the snapshot a sandbox of spec starts from: a fork
// copy's, or its snapshot image's.
func (s *Server) startSnapshot(spec *pb.SandboxSpec) string {
	if spec.Snapshot != "" || s.Images == nil || !images.IsStoreName(spec.Image) {
		return spec.Snapshot
	}
	if m, err := s.Images.GetManifest(spec.Image); err == nil {
		return m.Snapshot
	}
	return ""
}

// snapshotShape gives a sandbox started from a memory snapshot image the
// VM shape the snapshot holds where its spec leaves resources unset: the
// memory restores only into a VM of the same size (spec §37.10).
func (s *Server) snapshotShape(spec *pb.SandboxSpec) {
	res := spec.Resources
	if res.MemoryMb != 0 && res.CpuCores != 0 && res.DiskMb != 0 {
		return
	}
	id := s.startSnapshot(spec)
	if id == "" {
		return
	}
	snap, err := s.Images.GetSnapshot(id)
	if err != nil || !snap.Memory || snap.VM == nil {
		return
	}
	if res.MemoryMb == 0 {
		res.MemoryMb = snap.VM.MemMB
	}
	if res.CpuCores == 0 {
		res.CpuCores = float64(snap.VM.VCPUs)
	}
	if res.DiskMb == 0 {
		res.DiskMb = snap.VM.DiskMB
	}
}

// snapshotRuntime returns the runtime versions a memory snapshot needs
// (spec §28.12); nil for none, or when the store does not know.
func (s *Server) snapshotRuntime(id string) map[string]string {
	if id == "" || s.Images == nil {
		return nil
	}
	snap, err := s.Images.GetSnapshot(id)
	if err != nil || !snap.Memory {
		return nil
	}
	return snap.Runtime
}

// ---- IAM operations (spec §27.2): cluster admins only ---------------------------------------

func (s *Server) clusterAdmin(ctx context.Context) (string, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return "", err
	}
	return p, s.authorize(ctx, p, "root", iam.ProjectAdmin)
}

func (s *Server) BackupIAM(r *pb.IAMBackupRequest, stream pb.DSec_BackupIAMServer) error {
	p, err := s.clusterAdmin(stream.Context())
	if err != nil {
		return err
	}
	up, err := s.iam.Backup(stream.Context(), &pb.IAMBackupRequest{Actor: p})
	if err != nil {
		return err
	}
	return iam.Pipe(up, stream)
}

func (s *Server) RestoreIAM(stream pb.DSec_RestoreIAMServer) error {
	p, err := s.clusterAdmin(stream.Context())
	if err != nil {
		return err
	}
	_, data, err := iam.RecvChunks(stream.Recv)
	if err != nil {
		return err
	}
	up, err := s.iam.Restore(stream.Context())
	if err != nil {
		return err
	}
	first := true
	if err := iam.SendChunks(data, func(ch *pb.BackupChunk) error {
		if first {
			ch.Actor, first = p, false
		}
		return up.Send(ch)
	}); err != nil {
		return err
	}
	if _, err := up.CloseAndRecv(); err != nil {
		return err
	}
	s.flushAuth()
	return stream.SendAndClose(&pb.Empty{})
}

func (s *Server) IAMMembers(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	p, err := s.clusterAdmin(ctx)
	if err != nil {
		return nil, err
	}
	return s.iam.Members(ctx, &pb.IAMMemberRequest{Actor: p})
}

func (s *Server) AddIAMMember(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	p, err := s.clusterAdmin(ctx)
	if err != nil {
		return nil, err
	}
	return s.iam.AddMember(ctx, &pb.IAMMemberRequest{Actor: p, Id: r.Id, RaftAddr: r.RaftAddr, Addr: r.Addr})
}

func (s *Server) RemoveIAMMember(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	p, err := s.clusterAdmin(ctx)
	if err != nil {
		return nil, err
	}
	return s.iam.RemoveMember(ctx, &pb.IAMMemberRequest{Actor: p, Id: r.Id})
}
