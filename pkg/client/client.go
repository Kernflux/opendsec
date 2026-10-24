// Package client is the Go client for the public OpenDsec API, used by opendsecctl
// and the end-to-end tests. RL code should use the Python SDK (opendsec).
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

type Client struct {
	pb.DSecClient
	conn    *grpc.ClientConn
	Project string
}

type options struct {
	pool       *x509.CertPool
	serverName string
	err        error
}

// Option configures Dial.
type Option func(*options)

// WithCAFile enables TLS, trusting the CA certificate in path.
func WithCAFile(path string) Option {
	return func(o *options) {
		b, err := os.ReadFile(path)
		if err != nil {
			o.err = err
			return
		}
		o.pool = x509.NewCertPool()
		if !o.pool.AppendCertsFromPEM(b) {
			o.err = fmt.Errorf("%s: no certificates", path)
		}
	}
}

// WithCAPool enables TLS with the given trust roots.
func WithCAPool(p *x509.CertPool) Option { return func(o *options) { o.pool = p } }

// WithServerName overrides the TLS server name (default: the address host).
func WithServerName(n string) Option { return func(o *options) { o.serverName = n } }

// APIServerName is the name every apiserver certificate carries, for
// clients that reach several apiservers (or a load balancer), as the Python
// SDK does. It is internal/pki's APIServerName (a pki test checks they
// match); not imported, since this package is Apache-2.0 (NOTICE).
const APIServerName = "api.opendsec.internal"

// Dial connects to an apiserver, or to several ("host:port,host:port",
// balanced round-robin, verified as APIServerName under TLS); project is
// the default project for creations. With token "", calls carry the token
// their context was given by WithToken (a gateway serving many callers).
func Dial(addr, token, project string, opts ...Option) (*Client, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	if o.err != nil {
		return nil, o.err
	}
	target := "passthrough:///" + addr
	// A silently lost apiserver (partition, host down) fails within ~15 s.
	dopts := []grpc.DialOption{grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true})}
	if token != "" {
		dopts = append(dopts, grpc.WithPerRPCCredentials(bearer(token)))
	}
	if strings.Contains(addr, ",") {
		r := manual.NewBuilderWithScheme("opendsec-api")
		var st resolver.State
		for _, a := range strings.Split(addr, ",") {
			st.Addresses = append(st.Addresses, resolver.Address{Addr: strings.TrimSpace(a)})
		}
		r.InitialState(st)
		target = r.Scheme() + ":///apiservers"
		dopts = append(dopts, grpc.WithResolvers(r), grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin": {}}]}`))
		if o.serverName == "" {
			o.serverName = APIServerName
		}
	}
	creds := insecure.NewCredentials()
	if o.pool != nil {
		creds = credentials.NewTLS(&tls.Config{RootCAs: o.pool, ServerName: o.serverName, MinVersion: tls.VersionTLS12})
	}
	conn, err := grpc.NewClient(target, append(dopts, grpc.WithTransportCredentials(creds))...)
	if err != nil {
		return nil, err
	}
	return &Client{DSecClient: pb.NewDSecClient(conn), conn: conn, Project: project}, nil
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}

// RequireTransportSecurity is false so dev clusters without TLS still work;
// with TLS configured the token only ever travels encrypted.
func (b bearer) RequireTransportSecurity() bool { return false }

// WithToken makes the calls made with ctx carry token (on a client dialed
// without one).
func WithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func (c *Client) Close() error { return c.conn.Close() }

// Ready reports whether the connection to the apiservers is usable (not
// failing), and starts connecting when it is idle: a readiness check.
func (c *Client) Ready() error {
	switch s := c.conn.GetState(); s {
	case connectivity.TransientFailure, connectivity.Shutdown:
		return fmt.Errorf("apiservers: %s", s)
	case connectivity.Idle:
		c.conn.Connect()
	}
	return nil
}

// Fleet returns the cluster management API (spec §28.8) on the same connection.
func (c *Client) Fleet() pb.FleetAdminClient { return pb.NewFleetAdminClient(c.conn) }

func (c *Client) Create(ctx context.Context, spec *pb.SandboxSpec) (*pb.Sandbox, error) {
	return c.CreateSandbox(ctx, &pb.CreateSandboxRequest{Project: c.Project, Spec: spec})
}

func (c *Client) Stop(ctx context.Context, id string) (*pb.Sandbox, error) {
	return c.StopSandbox(ctx, &pb.SandboxRef{Id: id})
}

// CreateBatch creates count sandboxes and collects every result.
func (c *Client) CreateBatch(ctx context.Context, spec *pb.SandboxSpec, count int32) ([]*pb.CreateSandboxResult, error) {
	st, err := c.CreateSandboxes(ctx, &pb.CreateSandboxesRequest{Project: c.Project, Spec: spec, Count: count})
	if err != nil {
		return nil, err
	}
	return collect(st)
}

// Fork copies a running sandbox and collects one result per copy (spec §19).
func (c *Client) Fork(ctx context.Context, r *pb.ForkSandboxRequest) ([]*pb.CreateSandboxResult, error) {
	st, err := c.ForkSandbox(ctx, r)
	if err != nil {
		return nil, err
	}
	return collect(st)
}

func collect(st interface {
	Recv() (*pb.CreateSandboxResult, error)
}) ([]*pb.CreateSandboxResult, error) {
	var out []*pb.CreateSandboxResult
	for {
		r, err := st.Recv()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
}
