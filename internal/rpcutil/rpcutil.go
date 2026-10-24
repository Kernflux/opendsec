// Package rpcutil holds the gRPC plumbing shared by every OpenDsec component:
// stable error reasons, authentication metadata and interceptors, and a
// connection pool.
package rpcutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/pki"
)

// Stable error reasons (spec §3.1), carried in ErrorInfo.reason.
const (
	Unauthenticated = "unauthenticated"
	Forbidden       = "forbidden"
	NotFound        = "not_found"
	QuotaExceeded   = "quota_exceeded"
	RateLimited     = "rate_limited"
	NoCapacity      = "no_capacity"
	Invalid         = "invalid"
	Unavailable     = "unavailable"
	Timeout         = "timeout"
	Internal        = "internal"
	Conflict        = "conflict" // a conditional write lost to a concurrent one
)

var reasonCode = map[string]codes.Code{
	Unauthenticated: codes.Unauthenticated,
	Forbidden:       codes.PermissionDenied,
	NotFound:        codes.NotFound,
	QuotaExceeded:   codes.ResourceExhausted,
	RateLimited:     codes.ResourceExhausted,
	NoCapacity:      codes.Unavailable,
	Invalid:         codes.InvalidArgument,
	Unavailable:     codes.Unavailable,
	Timeout:         codes.DeadlineExceeded,
	Internal:        codes.Internal,
	Conflict:        codes.Aborted,
}

// Err builds a gRPC status error carrying an OpenDsec reason.
func Err(reason, format string, args ...any) error {
	code, ok := reasonCode[reason]
	if !ok {
		code = codes.Unknown
	}
	st := status.New(code, fmt.Sprintf(format, args...))
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "opendsec"}); err == nil {
		st = d
	}
	return st.Err()
}

// Moved reports that sandbox id moved to edge to (spec §26.2): an
// unavailable error naming the edge, so a caller unaware of moves retries
// while one that is aware (the apiserver) follows it at once.
func Moved(id, to string) error {
	st := status.New(codes.Unavailable, fmt.Sprintf("sandbox %s moved to edge %s", id, to))
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: Unavailable, Domain: "opendsec",
		Metadata: map[string]string{"moved_to": to}}); err == nil {
		st = d
	}
	return st.Err()
}

// MovedTo returns the edge a Moved error names, or "".
func MovedTo(err error) string {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return ""
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.Domain == "opendsec" {
			return ei.Metadata["moved_to"]
		}
	}
	return ""
}

// Reason extracts the OpenDsec reason from an error, falling back to the gRPC code.
func Reason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	st, ok := status.FromError(err)
	if !ok {
		return Internal
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.Domain == "opendsec" {
			return ei.Reason
		}
	}
	switch st.Code() {
	case codes.Unavailable, codes.Canceled:
		return Unavailable
	case codes.DeadlineExceeded:
		return Timeout
	case codes.NotFound:
		return NotFound
	case codes.InvalidArgument:
		return Invalid
	case codes.PermissionDenied:
		return Forbidden
	case codes.Unauthenticated:
		return Unauthenticated
	case codes.ResourceExhausted:
		return QuotaExceeded
	}
	return Internal
}

// Message returns the human-readable part of a status error.
// ReasonOf is Reason, "" for nil: for metrics labels.
func ReasonOf(err error) string {
	if err == nil {
		return ""
	}
	return Reason(err)
}

func Message(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Message()
	}
	return err.Error()
}

// ---- authentication metadata -------------------------------------------------

const (
	ServiceTokenKey  = "x-opendsec-service-token"
	authorizationKey = "authorization"
)

// BearerToken returns the caller's "authorization: Bearer <token>" value.
func BearerToken(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get(authorizationKey) {
		if t, ok := strings.CutPrefix(v, "Bearer "); ok {
			return t
		}
	}
	return ""
}

// ServerOptions are defaults for every OpenDsec gRPC server.
func ServerOptions(extra ...grpc.ServerOption) []grpc.ServerOption {
	return append([]grpc.ServerOption{
		// Outermost: every call is counted, including those auth rejects.
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			t0 := time.Now()
			resp, err := h(ctx, req)
			observeRPC(info.FullMethod, err, t0)
			return resp, err
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			t0 := time.Now()
			err := h(srv, ss)
			observeRPC(info.FullMethod, err, t0)
			return err
		}),
		grpc.MaxConcurrentStreams(1 << 16),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
		// Ping idle connections: a load balancer in front of the apiservers
		// cuts connections idle longer than its timeout (HAProxy's default
		// is 50 s), and a quiet stream (a batch create, exec, output) is idle
		// on the wire. Clients that send no pings themselves (the Python
		// SDK) are covered too.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: ServerPingInterval, Timeout: 20 * time.Second}),
	}, extra...)
}

// ServerPingInterval: servers ping a connection after this long without
// activity, below the idle timeout of common load balancers.
const ServerPingInterval = 20 * time.Second

// observeRPC records a served call; method is "/opendsec.v1.<Service>/<Method>".
func observeRPC(method string, err error, t0 time.Time) {
	svc, m, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	metrics.RPC(strings.TrimPrefix(svc, "opendsec.v1."), m, ReasonOf(err), time.Since(t0))
}

// Dial opens a client connection to an internal peer, authenticated per sec
// (mTLS, or the service token in dev mode). If expect is set, the server's
// certificate must carry that identity (TLS mode only).
func Dial(addr string, sec *Security, expect *pki.Identity) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		// A peer that went away silently (network partition, host down)
		// fails the connection, and the calls on it, within ~15 s instead of
		// at their deadlines or TCP's timeout. Servers allow pings every 5 s.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}),
		// gRPC's default reconnect backoff grows to 120s: a peer that was
		// down for a while (edge restart) would stay unreachable long after
		// it is back. Internal peers are few and local, so retry quickly.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 2 * time.Second},
			MinConnectTimeout: 2 * time.Second,
		}),
	}
	switch {
	case sec != nil && sec.TLS != nil:
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(sec.TLS.ClientConfig(expect))))
	default:
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if sec != nil && sec.Token != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(staticCreds{ServiceTokenKey: sec.Token}))
		}
	}
	target := addr
	switch {
	case strings.HasPrefix(addr, "unix:"):
		target = "unix://" + strings.TrimPrefix(addr, "unix:")
	case strings.Contains(addr, ","):
		// Replicated service: balance over every replica and transparently
		// retry UNAVAILABLE (a replica down, or no leader during an election).
		r := manual.NewBuilderWithScheme("opendsec-replicas")
		var st resolver.State
		for _, a := range strings.Split(addr, ",") {
			st.Addresses = append(st.Addresses, resolver.Address{Addr: strings.TrimSpace(a)})
		}
		r.InitialState(st)
		opts = append(opts, grpc.WithResolvers(r), grpc.WithDefaultServiceConfig(replicaServiceConfig))
		target = r.Scheme() + ":///replicas"
	default:
		target = "passthrough:///" + addr
	}
	return grpc.NewClient(target, opts...)
}

// replicaServiceConfig: round-robin over replicas; retry UNAVAILABLE with
// backoff. Retried calls are idempotent or fail harmlessly (spec §15.1).
const replicaServiceConfig = `{
  "loadBalancingConfig": [{"round_robin": {}}],
  "methodConfig": [{
    "name": [{}],
    "retryPolicy": {
      "maxAttempts": 5, "initialBackoff": "0.2s", "maxBackoff": "1.5s", "backoffMultiplier": 2,
      "retryableStatusCodes": ["UNAVAILABLE"]
    }
  }]
}`

type staticCreds map[string]string

func (c staticCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return c, nil
}
func (staticCreds) RequireTransportSecurity() bool { return false }

// ---- connection pool -----------------------------------------------------------

// Pool caches one client connection per address. gRPC connections reconnect
// on their own, so entries are kept until Close.
type Pool struct {
	sec   *Security
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn // key: addr, or addr|role/id when the peer identity is pinned
}

func NewPool(sec *Security) *Pool {
	return &Pool{sec: sec, conns: map[string]*grpc.ClientConn{}}
}

// Get returns a connection to the internal service at addr.
func (p *Pool) Get(addr string) (*grpc.ClientConn, error) { return p.get(addr, nil) }

// GetEdge returns a connection to edge id at addr; with TLS, the server must
// prove it is that edge.
func (p *Pool) GetEdge(addr, id string) (*grpc.ClientConn, error) {
	return p.get(addr, &pki.Identity{Role: pki.RoleEdge, ID: id})
}

func (p *Pool) get(addr string, expect *pki.Identity) (*grpc.ClientConn, error) {
	key := addr
	if expect != nil {
		key += "|" + expect.String()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.conns[key]; ok {
		return c, nil
	}
	c, err := Dial(addr, p.sec, expect)
	if err != nil {
		return nil, err
	}
	p.conns[key] = c
	return c, nil
}

// ResetBackoff makes connections to addr retry immediately, e.g. when the
// watcher reports a restarted edge healthy again.
func (p *Pool) ResetBackoff(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.conns {
		if k == addr || strings.HasPrefix(k, addr+"|") {
			c.ResetConnectBackoff()
		}
	}
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = map[string]*grpc.ClientConn{}
}

// Now returns the wall clock as float seconds, the time unit used on the wire.
func Now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// PipeEvents relays a server stream of ExecEvents to another server stream
// (aether -> edge -> apiserver -> client).
func PipeEvents(up interface{ Recv() (*pb.ExecEvent, error) }, down interface{ Send(*pb.ExecEvent) error }) error {
	return Pipe(up, down)
}

// Pipe relays a server stream's messages until it ends.
func Pipe[T any](up interface{ Recv() (T, error) }, down interface{ Send(T) error }) error {
	for {
		ev, err := up.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := down.Send(ev); err != nil {
			return err
		}
	}
}

// portStream is a ConnectPort stream, either side's.
type portStream interface {
	Recv() (*pb.PortData, error)
	Send(*pb.PortData) error
}

// PipePort relays between a ConnectPort stream and the connection it was
// opened for (spec §37.8): what the stream receives is written to conn,
// what conn reads is sent. The stream's peer done sending closes conn's
// write side; conn's peer done (EOF) ends the relay, as does any error.
func PipePort(st portStream, conn net.Conn) error {
	recvd := make(chan error, 1) // stream -> conn ended
	go func() {
		for {
			m, err := st.Recv()
			if err == io.EOF {
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
				recvd <- nil
				return
			}
			if err == nil && len(m.Data) > 0 {
				_, err = conn.Write(m.Data)
			}
			if err != nil {
				recvd <- err
				return
			}
		}
	}()
	sent := make(chan error, 1) // conn -> stream ended
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if serr := st.Send(&pb.PortData{Data: buf[:n]}); serr != nil {
					sent <- serr
					return
				}
			}
			if err == io.EOF {
				sent <- nil
				return
			}
			if err != nil {
				sent <- err
				return
			}
		}
	}()
	defer conn.Close()
	select {
	case err := <-sent:
		return err
	case err := <-recvd:
		if err != nil {
			return err
		}
		return <-sent // half-closed: the rest of conn's answer
	}
}

// portClient is the client side of a ConnectPort stream.
type portClient interface {
	portStream
	CloseSend() error
}

// PipePortStreams relays a ConnectPort stream (down: served here) to the
// next hop (up: opened by us), both ways, keeping half-closes.
func PipePortStreams(down portStream, up portClient) error {
	go func() {
		for {
			m, err := down.Recv()
			if err != nil { // EOF: the caller is done sending; or gone (up ends with the context)
				up.CloseSend()
				return
			}
			if up.Send(m) != nil {
				return
			}
		}
	}()
	return Pipe[*pb.PortData](up, down)
}
