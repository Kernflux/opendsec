package fullvm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kernflux/opendsec/internal/agent/aether"
)

// qmpCall runs one QMP command on the socket at path and returns its
// result.
func qmpCall(ctx context.Context, path, cmd string) (json.RawMessage, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes('\n'); err != nil { // greeting
		return nil, err
	}
	send := func(cmd string) (json.RawMessage, error) {
		if _, err := fmt.Fprintf(c, `{"execute":%q}`+"\n", cmd); err != nil {
			return nil, err
		}
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return nil, err
			}
			var m struct {
				Return json.RawMessage `json:"return"`
				Error  *struct {
					Desc string `json:"desc"`
				} `json:"error"`
			}
			if err := json.Unmarshal(line, &m); err != nil {
				return nil, err
			}
			if m.Error != nil {
				return nil, fmt.Errorf("qmp %s: %s", cmd, m.Error.Desc)
			}
			if m.Return != nil {
				return m.Return, nil
			}
			// an asynchronous event: keep reading
		}
	}
	if _, err := send("qmp_capabilities"); err != nil {
		return nil, err
	}
	return send(cmd)
}

func qmp(ctx context.Context, path, cmd string) error {
	_, err := qmpCall(ctx, path, cmd)
	return err
}

// qmpStatus is the VM's run state ("running", "paused", ...).
func qmpStatus(ctx context.Context, path string) (string, error) {
	out, err := qmpCall(ctx, path, "query-status")
	if err != nil {
		return "", err
	}
	var st struct {
		Status string `json:"status"`
	}
	err = json.Unmarshal(out, &st)
	return st.Status, err
}

// dialVsock connects to port of the VM with context id cid (vhost-vsock).
func dialVsock(cid uint32, port uint32) (net.Conn, error) {
	return aether.DialVsock(cid, port, 2*time.Second)
}

func grpcVsock(cid uint32) (*grpc.ClientConn, error) {
	return grpc.NewClient(fmt.Sprintf("passthrough:///vsock-%d", cid), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dialVsock(cid, 1024) }),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 20 * time.Millisecond,
			Multiplier: 1.6, Jitter: 0.2, MaxDelay: time.Second}, MinConnectTimeout: 5 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(80<<20), grpc.MaxCallSendMsgSize(80<<20)))
}
