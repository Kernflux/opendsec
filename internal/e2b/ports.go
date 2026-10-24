package e2b

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/pkg/client"
)

// Ports of a sandbox other than envd's (spec §37.8): HTTP, streamed
// responses and upgrades (WebSocket) to a server in the sandbox, as E2B's
// sandbox hosts "<port>-<id>.<domain>" serve them. Each request is a
// connection of its own through ConnectPort (apiserver -> edge -> aether ->
// the sandbox's loopback), made with the caller's token: connections are
// never shared between callers.

// routingHeaders are the gateway's own: never passed to the sandbox, so no
// token reaches what runs there.
var routingHeaders = []string{"E2b-Sandbox-Id", "E2b-Sandbox-Port", "X-Access-Token", "E2b-Traffic-Access-Token", "X-Api-Key"}

func (g *Gateway) portProxy(id string, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := apiKey(r)
		if key == "" {
			writeErr(w, http.StatusUnauthorized, "missing access token (E2B-Traffic-Access-Token or X-Access-Token): an OpenDsec token")
			return
		}
		tr := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 0,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return g.dialPort(client.WithToken(context.Background(), key), id, port)
			}}
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = "http", fmt.Sprintf("localhost:%d", port)
				for _, h := range routingHeaders {
					pr.Out.Header.Del(h)
				}
				if a := pr.Out.Header.Get("Authorization"); a == "Bearer "+key {
					pr.Out.Header.Del("Authorization")
				}
			},
			Transport:     tr,
			FlushInterval: -1, // streamed responses (code interpreter's NDJSON) as they come
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				code, msg := http.StatusBadGateway, err.Error()
				var de *dialErr
				if errors.As(err, &de) {
					err = de.err
				}
				if st, ok := status.FromError(err); ok {
					code, msg = httpStatus(err), st.Message()
				}
				if code == http.StatusServiceUnavailable {
					code = http.StatusBadGateway // nothing listens on the port: as E2B's proxy answers
				}
				writeErr(w, code, fmt.Sprintf("sandbox port %d: %s", port, msg))
			},
		}
		rp.ServeHTTP(w, r)
	})
}

// dialPort opens a connection to port of sandbox id; it waits for aether's
// acknowledgement, so a closed port fails here.
func (g *Gateway) dialPort(ctx context.Context, id string, port int) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	st, err := g.api.ConnectPort(ctx)
	if err == nil {
		err = st.Send(&pb.PortData{SandboxId: id, Port: uint32(port)})
	}
	if err == nil {
		_, err = st.Recv() // the acknowledgement
	}
	if err != nil {
		cancel()
		return nil, &dialErr{err}
	}
	return &portConn{st: st, cancel: cancel}, nil
}

// dialErr keeps the apiserver's status for the error handler (net/http
// wraps dial errors).
type dialErr struct{ err error }

func (e *dialErr) Error() string { return e.err.Error() }
func (e *dialErr) Unwrap() error { return e.err }

// portConn is a ConnectPort stream as a net.Conn.
type portConn struct {
	st     pb.DSec_ConnectPortClient
	cancel context.CancelFunc

	rmu  sync.Mutex
	rbuf []byte
	wmu  sync.Mutex
}

func (c *portConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		m, err := c.st.Recv()
		if err == io.EOF {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		c.rbuf = m.Data
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// maxPortMsg bounds one message: well under gRPC's 4 MB.
const maxPortMsg = 1 << 20

func (c *portConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n := 0
	for len(p) > 0 {
		k := min(len(p), maxPortMsg)
		if err := c.st.Send(&pb.PortData{Data: p[:k]}); err != nil {
			return n, err
		}
		n, p = n+k, p[k:]
	}
	return n, nil
}

// CloseWrite tells the sandbox's side that nothing more comes.
func (c *portConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.st.CloseSend()
}

func (c *portConn) Close() error { c.cancel(); return nil }

type portAddr struct{}

func (portAddr) Network() string { return "opendsec-port" }
func (portAddr) String() string  { return "sandbox" }

func (c *portConn) LocalAddr() net.Addr              { return portAddr{} }
func (c *portConn) RemoteAddr() net.Addr             { return portAddr{} }
func (c *portConn) SetDeadline(time.Time) error      { return nil }
func (c *portConn) SetReadDeadline(time.Time) error  { return nil }
func (c *portConn) SetWriteDeadline(time.Time) error { return nil }
