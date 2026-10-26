package rpcutil

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/kernflux/opendsec/internal/pki"
)

// Security selects how internal components authenticate each other: mTLS
// with per-component certificates (production), or a shared service token
// (dev only, no per-caller authorization).
type Security struct {
	TLS   *pki.Material
	Token string
}

// ACL maps a full gRPC method ("/opendsec.v1.IAM/Release") or a service wildcard
// ("/opendsec.v1.IAM/*") to the roles allowed to call it.
type ACL map[string][]string

func (a ACL) allows(method, role string) bool {
	roles, ok := a[method]
	if !ok {
		roles = a[method[:strings.LastIndexByte(method, '/')+1]+"*"]
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

type identityKey struct{}

// PeerIdentity returns the authenticated identity of the internal caller
// (TLS mode only).
func PeerIdentity(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(pki.Identity)
	return id, ok
}

func identityFromPeer(ctx context.Context) (pki.Identity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return pki.Identity{}, Err(Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return pki.Identity{}, Err(Unauthenticated, "client certificate required")
	}
	id, err := pki.FromCert(ti.State.VerifiedChains[0][0])
	if err != nil {
		return pki.Identity{}, Err(Unauthenticated, "%v", err)
	}
	return id, nil
}

// InternalServerOptions secures an internal service: with TLS, callers must
// present a cluster certificate whose role the ACL allows for the method;
// otherwise the service token is required.
func InternalServerOptions(sec *Security, acl ACL) []grpc.ServerOption {
	var check func(ctx context.Context, method string) (context.Context, error)
	var opts []grpc.ServerOption
	if sec.TLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(sec.TLS.ServerConfig())))
		check = func(ctx context.Context, method string) (context.Context, error) {
			id, err := identityFromPeer(ctx)
			if err != nil {
				return nil, err
			}
			if !acl.allows(method, id.Role) {
				return nil, Err(Forbidden, "%s may not call %s", id, method)
			}
			return context.WithValue(ctx, identityKey{}, id), nil
		}
	} else {
		check = func(ctx context.Context, _ string) (context.Context, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			v := md.Get(ServiceTokenKey)
			if len(v) == 0 || subtle.ConstantTimeCompare([]byte(v[0]), []byte(sec.Token)) != 1 {
				return nil, Err(Unauthenticated, "internal API requires the service token")
			}
			return ctx, nil
		}
	}
	opts = append(opts,
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			ctx, err := check(ctx, info.FullMethod)
			if err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			ctx, err := check(ss.Context(), info.FullMethod)
			if err != nil {
				return err
			}
			return h(srv, &ctxStream{ServerStream: ss, ctx: ctx})
		}),
	)
	return ServerOptions(opts...)
}

// PublicServerOptions secures the public API transport (TLS when configured;
// callers authenticate per request with bearer tokens).
func PublicServerOptions(sec *Security, extra ...grpc.ServerOption) []grpc.ServerOption {
	if sec.TLS != nil {
		extra = append(extra, grpc.Creds(credentials.NewTLS(sec.TLS.PublicServerConfig())))
	}
	return ServerOptions(extra...)
}

type ctxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *ctxStream) Context() context.Context { return s.ctx }

// Access-control lists of the internal services (spec §14.1).
var (
	// Replicas forward to the IAM leader with their own iam/<id> identity,
	// so role "iam" may call everything.
	IAMACL = ACL{
		"/opendsec.v1.IAM/Release":       {pki.RoleEdge, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/ReleaseLeases": {pki.RoleEdge, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/LeaseEdge":     {pki.RoleEdge, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/ReconcileEdge": {pki.RoleWatcher, pki.RoleIAM},
		"/opendsec.v1.IAM/SweepUnbound":  {pki.RoleWatcher, pki.RoleIAM},
		"/opendsec.v1.IAM/AcquireLock":   {pki.RoleWatcher, pki.RoleFleet, pki.RoleIAM},
		"/opendsec.v1.IAM/ReleaseLock":   {pki.RoleWatcher, pki.RoleFleet, pki.RoleIAM},
		// The key-value area holds the fleet service's state (spec §28.3);
		// apiservers reach only its ext/ keys (IAM checks), their
		// extensions' state.
		"/opendsec.v1.IAM/KVGet":    {pki.RoleFleet, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/KVList":   {pki.RoleFleet, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/KVPut":    {pki.RoleFleet, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/KVDelete": {pki.RoleFleet, pki.RoleAPIServer, pki.RoleIAM},
		"/opendsec.v1.IAM/*":        {pki.RoleAPIServer, pki.RoleIAM},
	}
	WatcherACL = ACL{
		"/opendsec.v1.Watcher/GetSnapshot": {pki.RoleAPIServer, pki.RoleFleet, pki.RoleWatcher}, // watchers: seedFromPeers
		"/opendsec.v1.Watcher/Register":    {pki.RoleEdge},
	}
	// Fleet (spec §28.8): node agents report and download; replicas copy
	// releases and forward to the leader; apiservers proxy management calls
	// and operators may call them directly.
	FleetACL = ACL{
		"/opendsec.v1.Fleet/Heartbeat":    {pki.RoleNode, pki.RoleFleet},
		"/opendsec.v1.Fleet/FetchRelease": {pki.RoleNode, pki.RoleFleet},
		"/opendsec.v1.Fleet/PutRelease":   {pki.RoleFleet},
		"/opendsec.v1.FleetAdmin/*":       {pki.RoleAPIServer, pki.RoleOps, pki.RoleFleet},
	}
	EdgeACL = ACL{
		// The fleet service counts an edge's sandboxes before retiring it (spec §28.7).
		"/opendsec.v1.Edge/Status": {pki.RoleWatcher, pki.RoleAPIServer, pki.RoleFleet},
		// Edge to edge (spec §26): fetching held snapshots, completing moves.
		"/opendsec.v1.Edge/FetchSnapshot": {pki.RoleEdge},
		"/opendsec.v1.Edge/EndMove":       {pki.RoleEdge, pki.RoleAPIServer},
		// The fleet service drains an edge around its restart (spec §28.6).
		"/opendsec.v1.Edge/Drain": {pki.RoleAPIServer, pki.RoleFleet},
		"/opendsec.v1.Edge/*":     {pki.RoleAPIServer},
	}
)
