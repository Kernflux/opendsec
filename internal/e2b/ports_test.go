package e2b

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/pkg/client"
)

// hangingAPI is an apiserver whose port connections never acknowledge.
type hangingAPI struct {
	pb.UnimplementedDSecServer
	ended chan struct{} // a ConnectPort stream was given up by the gateway
}

func (h *hangingAPI) ConnectPort(st grpc.BidiStreamingServer[pb.PortData, pb.PortData]) error {
	<-st.Context().Done()
	h.ended <- struct{}{}
	return nil
}

func (h *hangingAPI) CreateSandbox(context.Context, *pb.CreateSandboxRequest) (*pb.Sandbox, error) {
	return &pb.Sandbox{Id: ids.Sandbox("e000", ids.NewLease()), State: pb.SandboxState_RUNNING}, nil
}

func (h *hangingAPI) StopSandbox(context.Context, *pb.SandboxRef) (*pb.Sandbox, error) {
	return &pb.Sandbox{}, nil
}

func hangingGateway(t *testing.T, cfg config.E2B) (*hangingAPI, *httptest.Server) {
	h := &hangingAPI{ended: make(chan struct{}, 16)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterDSecServer(gs, h)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)
	api, err := client.Dial(ln.Addr().String(), "", "root")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close() })
	srv := httptest.NewServer(New(cfg, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return h, srv
}

// TestPortDialCancelled: a caller giving up on a sandbox port also gives
// up the gateway's dial (it ran on Background, piling up).
func TestPortDialCancelled(t *testing.T) {
	h, srv := hangingGateway(t, config.E2B{Project: "root"})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/", nil)
	r.Header.Set("E2b-Sandbox-Id", toE2B(ids.Sandbox("e000", ids.NewLease())))
	r.Header.Set("E2b-Sandbox-Port", "8080")
	r.Header.Set("X-Access-Token", "dsk.a.b")
	if resp, err := http.DefaultClient.Do(r); err == nil {
		resp.Body.Close()
	}
	select {
	case <-h.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the dial outlived its request")
	}
}

// TestReadyProbeBounded: a ready probe that hangs is cut at ReadyTimeout.
func TestReadyProbeBounded(t *testing.T) {
	_, srv := hangingGateway(t, config.E2B{Project: "root", Templates: map[string]config.E2BTemplate{
		"base": {Image: "img", Backend: "sim", ReadyPort: 8080, ReadyTimeout: 1}}})
	c := &http.Client{Timeout: 5 * time.Second}
	r, _ := http.NewRequest("POST", srv.URL+"/sandboxes", strings.NewReader(`{"templateID":"base"}`))
	r.Header.Set("X-API-Key", "dsk.a.b")
	r.Header.Set("Content-Type", "application/json")
	t0 := time.Now()
	resp, err := c.Do(r)
	if err != nil {
		t.Fatalf("create with a hanging ready port: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || time.Since(t0) > 3*time.Second {
		t.Fatalf("create: %d after %v", resp.StatusCode, time.Since(t0))
	}
}
