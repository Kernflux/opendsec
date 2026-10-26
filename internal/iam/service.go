package iam

import (
	"context"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Service exposes IAM over gRPC (internal API). With replicas, a follower
// forwards every call unchanged to the current leader (spec §15.1), so
// clients may send to any replica.
type Service struct {
	pb.UnimplementedIAMServer
	IAM *IAM
	// Leader returns a client for the leader replica when this replica is not
	// the leader (nil when it is, or in standalone mode).
	Leader func() (pb.IAMClient, error)
}

func (s *Service) fwd() (pb.IAMClient, error) {
	if s.Leader == nil || s.IAM.IsLeader() {
		return nil, nil
	}
	return s.Leader()
}

// ResourceMap converts one sandbox's resources into quota usage, counting the
// sandbox itself under "sandboxes".
func ResourceMap(r *pb.Resources) map[string]float64 {
	m := map[string]float64{QSandboxes: 1}
	if r != nil {
		if r.CpuCores > 0 {
			m[QCPU] = r.CpuCores
		}
		if r.MemoryMb > 0 {
			m[QMemory] = float64(r.MemoryMb)
		}
		if r.Gpus > 0 {
			m[QGPUs] = float64(r.Gpus)
		}
	}
	return m
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

func (s *Service) Admit(ctx context.Context, r *pb.AdmitRequest) (*pb.AdmitResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Admit(ctx, r)
	}
	id := r.Principal // the apiserver authenticated it (only it may call IAM)
	if r.Token != "" || id == "" {
		p, err := s.IAM.Authenticate(r.Token)
		if err != nil {
			return nil, err
		}
		id = p.ID
	}
	perms := r.Perms
	if len(perms) == 0 {
		perms = []string{SandboxCreate}
	}
	for _, perm := range perms {
		if err := s.IAM.Authorize(id, r.Project, perm); err != nil {
			return nil, err
		}
	}
	if r.Lease != "" {
		reserve := s.IAM.ReserveOn
		if r.Fresh {
			reserve = s.IAM.ReserveFresh
		}
		if err := reserve(r.Lease, r.Project, ResourceMap(r.Resources), r.Edge); err != nil {
			return nil, err
		}
	}
	return &pb.AdmitResponse{Principal: id}, nil
}

func (s *Service) Authenticate(ctx context.Context, r *pb.AuthenticateRequest) (*pb.Principal, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Authenticate(ctx, r)
	}
	p, exp, err := s.IAM.AuthenticateToken(r.Token)
	if err != nil {
		return nil, err
	}
	return &pb.Principal{Id: p.ID, Kind: p.Kind, TokenExpiresAt: exp}, nil
}

func (s *Service) Authorize(ctx context.Context, r *pb.AuthorizeRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Authorize(ctx, r)
	}
	return &pb.Empty{}, s.IAM.Authorize(r.Principal, r.Project, r.Perm)
}

// releasingEdge is the edge a release comes from: an edge's own
// certificate decides, never what it says.
func releasingEdge(ctx context.Context, said string) string {
	if id, ok := rpcutil.PeerIdentity(ctx); ok && id.Role == pki.RoleEdge {
		return id.ID
	}
	return said
}

func (s *Service) Release(ctx context.Context, r *pb.ReleaseRequest) (*pb.ReleaseResponse, error) {
	r.Edge = releasingEdge(ctx, r.Edge) // before forwarding, which re-signs as this replica
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Release(ctx, r)
	}
	ok, err := s.IAM.ReleaseLease(r.Lease, r.Edge)
	if err != nil {
		return nil, err
	}
	return &pb.ReleaseResponse{Released: ok}, nil
}

func (s *Service) ReleaseLeases(ctx context.Context, r *pb.ReleaseLeasesRequest) (*pb.ReleaseLeasesResponse, error) {
	r.Edge = releasingEdge(ctx, r.Edge)
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.ReleaseLeases(ctx, r)
	}
	n, err := s.IAM.ReleaseLeases(r.Edge, r.Leases)
	if err != nil {
		return nil, err
	}
	return &pb.ReleaseLeasesResponse{Released: int32(n)}, nil
}

func (s *Service) LeaseEdge(ctx context.Context, r *pb.LeaseEdgeRequest) (*pb.LeaseEdgeResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil { // the leader's view: a retry may have just moved it
		if err != nil {
			return nil, err
		}
		return c.LeaseEdge(ctx, r)
	}
	held, edge := s.IAM.LeaseEdge(r.Lease)
	return &pb.LeaseEdgeResponse{Held: held, Edge: edge}, nil
}

func liveLeases(ls []*pb.LeaseInfo) []LiveLease {
	out := make([]LiveLease, 0, len(ls))
	for _, l := range ls {
		out = append(out, LiveLease{Lease: l.Lease, Project: l.Project, Res: ResourceMap(l.Resources)})
	}
	return out
}

func (s *Service) ReconcileEdge(ctx context.Context, r *pb.ReconcileEdgeRequest) (*pb.ReconcileEdgeResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.ReconcileEdge(ctx, r)
	}
	if r.Edge == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "edge required")
	}
	res, err := s.IAM.ReconcileEdge(r.Edge, liveLeases(r.Live), seconds(r.MinAgeS))
	if err != nil {
		return nil, err
	}
	return &pb.ReconcileEdgeResponse{Adopted: int32(res.Adopted), Bound: int32(res.Bound),
		Released: int32(res.Released), Conflicts: int32(res.Conflicts)}, nil
}

func (s *Service) SweepUnbound(ctx context.Context, r *pb.SweepUnboundRequest) (*pb.SweepUnboundResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.SweepUnbound(ctx, r)
	}
	n, err := s.IAM.SweepUnbound(seconds(r.MaxAgeS))
	if err != nil {
		return nil, err
	}
	return &pb.SweepUnboundResponse{Released: int32(n)}, nil
}

func (s *Service) CreateProject(ctx context.Context, r *pb.CreateProjectRequest) (*pb.Project, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.CreateProject(ctx, r)
	}
	p, err := s.IAM.CreateProject(r.Actor, r.Parent, r.Name, r.Quota)
	if err != nil {
		return nil, err
	}
	return s.view(p.Path)
}

func (s *Service) CreatePrincipal(ctx context.Context, r *pb.CreatePrincipalRequest) (*pb.CreatePrincipalResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.CreatePrincipal(ctx, r)
	}
	tok, t, err := s.IAM.CreatePrincipal(r.Actor, r.Project, r.Id, r.Kind, seconds(r.TtlS))
	if err != nil {
		return nil, err
	}
	return &pb.CreatePrincipalResponse{Id: r.Id, Token: tok, TokenInfo: tokenPB(*t)}, nil
}

func tokenPB(t Token) *pb.TokenInfo {
	return &pb.TokenInfo{Id: t.ID, Principal: t.Principal, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		Description: t.Description, CreatedBy: t.CreatedBy}
}

func (s *Service) CreateToken(ctx context.Context, r *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.CreateToken(ctx, r)
	}
	tok, t, err := s.IAM.CreateToken(r.Actor, r.Principal, seconds(r.TtlS), r.Description)
	if err != nil {
		return nil, err
	}
	return &pb.CreateTokenResponse{Token: tok, Info: tokenPB(*t)}, nil
}

func (s *Service) ListTokens(ctx context.Context, r *pb.ListTokensRequest) (*pb.TokenList, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.ListTokens(ctx, r)
	}
	ts, err := s.IAM.ListTokens(r.Actor, r.Principal)
	if err != nil {
		return nil, err
	}
	out := &pb.TokenList{}
	for _, t := range ts {
		out.Tokens = append(out.Tokens, tokenPB(t))
	}
	return out, nil
}

func (s *Service) RevokeToken(ctx context.Context, r *pb.RevokeTokenRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.RevokeToken(ctx, r)
	}
	return &pb.Empty{}, s.IAM.RevokeToken(r.Actor, r.Principal, r.TokenId)
}

func (s *Service) DeletePrincipal(ctx context.Context, r *pb.DeletePrincipalRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.DeletePrincipal(ctx, r)
	}
	return &pb.Empty{}, s.IAM.DeletePrincipal(r.Actor, r.Principal)
}

func (s *Service) DeleteProject(ctx context.Context, r *pb.DeleteProjectRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.DeleteProject(ctx, r)
	}
	return &pb.Empty{}, s.IAM.DeleteProject(r.Actor, r.Project)
}

func (s *Service) SecurityEpoch(ctx context.Context, r *pb.Empty) (*pb.EpochResponse, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.SecurityEpoch(ctx, r)
	}
	return &pb.EpochResponse{Epoch: s.IAM.SecurityEpoch()}, nil
}

func (s *Service) AcquireLock(ctx context.Context, r *pb.LockRequest) (*pb.LockState, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.AcquireLock(ctx, r)
	}
	res, err := s.IAM.AcquireLock(r.Name, r.Holder, seconds(r.TtlS))
	if err != nil {
		return nil, err
	}
	return &pb.LockState{Name: res.Lock.Name, Holder: res.Lock.Holder, ExpiresAt: res.Lock.Expires, Acquired: res.Acquired}, nil
}

func (s *Service) ReleaseLock(ctx context.Context, r *pb.LockRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.ReleaseLock(ctx, r)
	}
	return &pb.Empty{}, s.IAM.ReleaseLock(r.Name, r.Holder)
}

func (s *Service) Grant(ctx context.Context, r *pb.GrantRequest) (*pb.Project, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Grant(ctx, r)
	}
	if _, err := s.IAM.Grant(r.Actor, r.Project, r.Principal, r.Perms); err != nil {
		return nil, err
	}
	return s.view(r.Project)
}

func (s *Service) Revoke(ctx context.Context, r *pb.RevokeRequest) (*pb.Project, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Revoke(ctx, r)
	}
	if _, err := s.IAM.Revoke(r.Actor, r.Project, r.Principal, r.Perms); err != nil {
		return nil, err
	}
	return s.view(r.Project)
}

func (s *Service) SetQuota(ctx context.Context, r *pb.SetQuotaRequest) (*pb.Project, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.SetQuota(ctx, r)
	}
	if _, err := s.IAM.SetQuota(r.Actor, r.Project, r.Quota); err != nil {
		return nil, err
	}
	return s.view(r.Project)
}

func (s *Service) GetUsage(ctx context.Context, r *pb.UsageRequest) (*pb.UsageReport, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.GetUsage(ctx, r)
	}
	rows, err := s.IAM.Usage(r.Actor, r.Project, r.From, r.To)
	if err != nil {
		return nil, err
	}
	out := &pb.UsageReport{AsOf: unix(s.IAM.now())}
	for _, u := range rows {
		out.Rows = append(out.Rows, &pb.UsageRow{Project: u.Project, Day: u.Day, SandboxesStarted: u.Started,
			SandboxHours: u.SandboxS / 3600, CpuCoreHours: u.CPUS / 3600, MemoryGbHours: u.MemMBS / 1024 / 3600, GpuHours: u.GPUS / 3600})
	}
	return out, nil
}

func (s *Service) GetProject(ctx context.Context, r *pb.GetProjectRequest) (*pb.Project, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.GetProject(ctx, r)
	}
	v, err := s.IAM.GetProject(r.Actor, r.Project)
	if err != nil {
		return nil, err
	}
	return toPB(v), nil
}

func (s *Service) view(path string) (*pb.Project, error) {
	v, err := s.IAM.GetProject("", path)
	if err != nil {
		return nil, err
	}
	return toPB(v), nil
}

func toPB(v *ProjectView) *pb.Project {
	out := &pb.Project{Path: v.Path, Quota: v.Quota, Usage: v.Usage, Children: v.Children, Policies: map[string]*pb.Permissions{}}
	for k, perms := range v.Policies {
		out.Policies[k] = &pb.Permissions{Perms: perms}
	}
	return out
}
