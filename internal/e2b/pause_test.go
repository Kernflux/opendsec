package e2b

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/pkg/client"
)

// pauseAPI is an apiserver with one sandbox, recording the timeouts set.
type pauseAPI struct {
	pb.UnimplementedDSecServer
	mu       sync.Mutex
	sb       *pb.Sandbox
	timeouts []int64
}

func (a *pauseAPI) get() *pb.Sandbox { return proto.Clone(a.sb).(*pb.Sandbox) }

func (a *pauseAPI) GetSandbox(context.Context, *pb.SandboxRef) (*pb.Sandbox, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.get(), nil
}

func (a *pauseAPI) PauseSandbox(context.Context, *pb.SandboxRef) (*pb.Sandbox, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sb.State = pb.SandboxState_PAUSED
	return a.get(), nil
}

func (a *pauseAPI) ResumeSandbox(context.Context, *pb.SandboxRef) (*pb.Sandbox, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sb.State = pb.SandboxState_RUNNING
	return a.get(), nil
}

func (a *pauseAPI) SetSandboxTimeout(_ context.Context, r *pb.SetTimeoutRequest) (*pb.Sandbox, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.timeouts = append(a.timeouts, r.TimeoutS)
	a.sb.Spec.TtlMaxS = int64(time.Since(time.Unix(0, int64(a.sb.CreatedAt*1e9)))/time.Second) + r.TimeoutS
	a.sb.PauseDeadline = false
	return a.get(), nil
}

func (a *pauseAPI) set() []int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.timeouts
	a.timeouts = nil
	return out
}

func pauseGateway(t *testing.T, sb *pb.Sandbox) (*pauseAPI, func(path, body string) int) {
	a := &pauseAPI{sb: sb}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterDSecServer(gs, a)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)
	api, err := client.Dial(ln.Addr().String(), "", "root")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close() })
	srv := httptest.NewServer(New(config.E2B{Project: "root"}, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return a, func(path, body string) int {
		t.Helper()
		r, _ := http.NewRequest("POST", srv.URL+"/sandboxes/"+toE2B(sb.Id)+path, strings.NewReader(body))
		r.Header.Set("X-API-KEY", "dsk.a.b")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
}

func eq(a []int64, b ...int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPauseConnect: a paused sandbox is kept pausedTimeout; resumed by
// connect, it runs for connect's timeout, not for what its pause had left.
func TestPauseConnect(t *testing.T) {
	now := float64(time.Now().UnixNano()) / 1e9
	a, post := pauseGateway(t, &pb.Sandbox{Id: ids.Sandbox("e000", ids.NewLease()), State: pb.SandboxState_RUNNING,
		CreatedAt: now, LastActiveAt: now, Spec: &pb.SandboxSpec{TtlMaxS: 300, TtlRunningStopS: 300}})
	if code := post("/pause", ""); code != http.StatusNoContent {
		t.Fatalf("pause: %d", code)
	}
	if got := a.set(); !eq(got, pausedTimeout) {
		t.Fatalf("pause set %v", got)
	}
	if code := post("/connect", `{"timeout": 60}`); code != http.StatusCreated {
		t.Fatalf("connect: %d", code)
	}
	if got := a.set(); !eq(got, 60) {
		t.Fatalf("connect of a paused sandbox set %v", got)
	}
	// Running: connect only extends.
	post("/connect", `{"timeout": 30}`)
	post("/connect", `{"timeout": 600}`)
	if got := a.set(); !eq(got, 600) {
		t.Fatalf("connects of a running sandbox set %v", got)
	}
}

// TestIdleRun: a sandbox resumed from an automatic pause ends by its idle
// timeout, and the edge keeps it when it is paused again.
func TestIdleRun(t *testing.T) {
	now := float64(time.Now().UnixNano()) / 1e9
	sb := &pb.Sandbox{Id: ids.Sandbox("e000", ids.NewLease()), State: pb.SandboxState_RUNNING, PauseDeadline: true,
		CreatedAt: now - 1000, LastActiveAt: now - 10,
		Spec: &pb.SandboxSpec{TtlMaxS: 500, TtlRunningStopS: 300, TtlPausedS: pausedTimeout}} // the old pause's deadline has passed
	if end, ok := endOf(sb); !ok || time.Until(end) < 280*time.Second || time.Until(end) > 300*time.Second {
		t.Fatalf("ends %v", end)
	}
	a, post := pauseGateway(t, sb)
	post("/connect", `{"timeout": 60}`) // less than what is left
	post("/connect", `{"timeout": 600}`)
	if got := a.set(); !eq(got, 600) {
		t.Fatalf("connects set %v", got)
	}
	a.mu.Lock()
	a.sb.PauseDeadline = true
	a.mu.Unlock()
	if code := post("/pause", ""); code != http.StatusNoContent {
		t.Fatalf("pause: %d", code)
	}
	if got := a.set(); len(got) != 0 {
		t.Fatalf("pause set %v over the edge's own deadline", got)
	}
}
