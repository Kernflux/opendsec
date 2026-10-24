package apiserver

import (
	"context"
	"io"

	"google.golang.org/grpc/metadata"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// FleetProxy serves FleetAdmin on the public port (spec §28.8): it
// authenticates the bearer token, checks fleet.view or fleet.operate on the
// root project (project.admin there implies both), and forwards the call to
// the fleet service with the caller as the actor. The audit log records it
// like any other public call.
type FleetProxy struct {
	pb.UnimplementedFleetAdminServer
	S     *Server
	Fleet pb.FleetAdminClient // nil: no fleet service configured
}

const fleetActorKey = "x-opendsec-actor" // fleet.ActorKey (no import cycle with the fleet package)

func (f *FleetProxy) auth(ctx context.Context, perm string) (context.Context, error) {
	if f.Fleet == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "no fleet service in this cluster (fleet.replicas is empty)")
	}
	p, err := f.S.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := f.S.authorize(ctx, p, "root", perm); err != nil {
		if rpcutil.Reason(err) != rpcutil.Forbidden || f.S.authorize(ctx, p, "root", iam.ProjectAdmin) != nil {
			return nil, err
		}
	}
	return metadata.AppendToOutgoingContext(ctx, fleetActorKey, p), nil
}

func (f *FleetProxy) view(ctx context.Context) (context.Context, error) {
	return f.auth(ctx, iam.FleetView)
}

func (f *FleetProxy) operate(ctx context.Context) (context.Context, error) {
	return f.auth(ctx, iam.FleetOperate)
}

func (f *FleetProxy) ListNodes(ctx context.Context, r *pb.FleetListNodesRequest) (*pb.FleetNodeList, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.ListNodes(c, r)
}

func (f *FleetProxy) GetNode(ctx context.Context, r *pb.FleetNodeRef) (*pb.FleetNode, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.GetNode(c, r)
}

func (f *FleetProxy) UpdateNode(ctx context.Context, r *pb.FleetUpdateNodeRequest) (*pb.FleetNode, error) {
	c, err := f.operate(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.UpdateNode(c, r)
}

func (f *FleetProxy) ImportNodes(ctx context.Context, r *pb.FleetImportRequest) (*pb.FleetNodeList, error) {
	c, err := f.operate(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.ImportNodes(c, r)
}

func (f *FleetProxy) ListReleases(ctx context.Context, r *pb.Empty) (*pb.FleetReleaseList, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.ListReleases(c, r)
}

func (f *FleetProxy) PushRelease(stream pb.FleetAdmin_PushReleaseServer) error {
	c, err := f.operate(stream.Context())
	if err != nil {
		return err
	}
	up, err := f.Fleet.PushRelease(c)
	if err != nil {
		return err
	}
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := up.Send(chunk); err != nil {
			_, rerr := up.CloseAndRecv() // the fleet's reason, not just EOF
			if rerr != nil {
				return rerr
			}
			return err
		}
	}
	rel, err := up.CloseAndRecv()
	if err != nil {
		return err
	}
	return stream.SendAndClose(rel)
}

func (f *FleetProxy) PutConfig(ctx context.Context, r *pb.FleetPutConfigRequest) (*pb.FleetConfig, error) {
	c, err := f.operate(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.PutConfig(c, r)
}

func (f *FleetProxy) GetConfig(ctx context.Context, r *pb.FleetGetConfigRequest) (*pb.FleetConfig, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.GetConfig(c, r)
}

func (f *FleetProxy) CreateRollout(ctx context.Context, r *pb.FleetCreateRolloutRequest) (*pb.FleetRollout, error) {
	c, err := f.operate(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.CreateRollout(c, r)
}

func (f *FleetProxy) ControlRollout(ctx context.Context, r *pb.FleetControlRolloutRequest) (*pb.FleetRollout, error) {
	c, err := f.operate(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.ControlRollout(c, r)
}

func (f *FleetProxy) ListRollouts(ctx context.Context, r *pb.Empty) (*pb.FleetRolloutList, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.ListRollouts(c, r)
}

func (f *FleetProxy) GetRollout(ctx context.Context, r *pb.FleetRolloutRef) (*pb.FleetRollout, error) {
	c, err := f.view(ctx)
	if err != nil {
		return nil, err
	}
	return f.Fleet.GetRollout(c, r)
}
