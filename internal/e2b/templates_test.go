package e2b

import (
	"context"
	"encoding/json"
	"errors"
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

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/pkg/client"
)

// buildAPI is an apiserver just big enough for a template build's bookkeeping.
type buildAPI struct {
	pb.UnimplementedDSecServer
	mkdirErr error
	beatFor  time.Duration // how long a heartbeat's status write takes
	getFor   time.Duration // how long the build's first call takes

	mu      sync.Mutex
	stops   int
	claimed bool
	gets    int
	status  string // the last status written
}

func (a *buildAPI) CreateSandbox(context.Context, *pb.CreateSandboxRequest) (*pb.Sandbox, error) {
	return &pb.Sandbox{Id: ids.Sandbox("e000", ids.NewLease()), State: pb.SandboxState_RUNNING}, nil
}

func (a *buildAPI) GetSandbox(_ context.Context, r *pb.SandboxRef) (*pb.Sandbox, error) {
	return &pb.Sandbox{Id: r.Id, Spec: &pb.SandboxSpec{Labels: map[string]string{labelBuild: "x"}}}, nil
}

func (a *buildAPI) StopSandbox(context.Context, *pb.SandboxRef) (*pb.Sandbox, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stops++
	return &pb.Sandbox{}, nil
}

func (a *buildAPI) MakeDir(context.Context, *pb.FileRequest) (*pb.FileInfo, error) {
	return &pb.FileInfo{}, a.mkdirErr
}

func (a *buildAPI) WriteFile(ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
	if r.Path == buildStatus {
		var st buildState
		json.Unmarshal(r.Data, &st)
		if st.Heartbeat != 0 && a.beatFor > 0 {
			time.Sleep(a.beatFor)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.status = st.Status
	}
	return &pb.FileInfo{}, nil
}

func (a *buildAPI) Exec(context.Context, *pb.ExecRequest) (*pb.ExecResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.claimed {
		return &pb.ExecResult{ExitCode: claimTaken}, nil
	}
	a.claimed = true
	return &pb.ExecResult{}, nil
}

func (a *buildAPI) GetImage(context.Context, *pb.ImageRef) (*pb.ImageInfo, error) {
	time.Sleep(a.getFor)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gets++
	return nil, errors.New("no such image")
}

func (a *buildAPI) state() (string, int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status, a.stops, a.gets
}

func buildGateway(t *testing.T, a *buildAPI) (*Gateway, *httptest.Server) {
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
	g := New(config.E2B{Project: "root", Templates: map[string]config.E2BTemplate{"base": {Image: "img"}}}, api,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return g, srv
}

func post(t *testing.T, url, body string) int {
	t.Helper()
	r, _ := http.NewRequest("POST", url, strings.NewReader(body))
	r.Header.Set("X-API-Key", "dsk.a.b")
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// A staging sandbox that cannot be set up is an error, and is stopped.
func TestRequestBuildSetupFails(t *testing.T) {
	a := &buildAPI{mkdirErr: errors.New("disk full")}
	_, srv := buildGateway(t, a)
	if code := post(t, srv.URL+"/v3/templates", `{"name":"x"}`); code == http.StatusAccepted {
		t.Fatal("accepted a build whose staging sandbox failed")
	}
	if _, stops, _ := a.state(); stops != 1 {
		t.Fatalf("staging sandbox stopped %d times", stops)
	}
}

// Starting a build twice runs it once; both requests are answered.
func TestStartBuildOnce(t *testing.T) {
	a := &buildAPI{}
	_, srv := buildGateway(t, a)
	url := srv.URL + "/v2/templates/x/builds/" + toE2B(ids.Sandbox("e000", ids.NewLease()))
	for i := range 2 {
		if code := post(t, url, `{"fromTemplate":"y"}`); code != http.StatusAccepted {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if status, _, _ := a.state(); status == "error" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the build never ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if _, _, gets := a.state(); gets != 1 {
		t.Fatalf("the build ran %d times", gets)
	}
}

// A heartbeat being written when the build ends does not replace its outcome.
func TestHeartbeatDoesNotOverwriteOutcome(t *testing.T) {
	old := heartbeatEvery
	heartbeatEvery = 40 * time.Millisecond
	t.Cleanup(func() { heartbeatEvery = old })
	// A heartbeat starts at 40 ms and lands at 70; the build ends at 55.
	a := &buildAPI{beatFor: 30 * time.Millisecond, getFor: 55 * time.Millisecond}
	g, _ := buildGateway(t, a)
	b := &builder{g: g, ctx: context.Background(), stage: "s", name: "x", project: "root", spec: buildSpec{FromTemplate: "y"}}
	b.run()
	time.Sleep(100 * time.Millisecond)
	if status, _, _ := a.state(); status != "error" {
		t.Fatalf("final status: %q", status)
	}
}

// The outcome is recorded even when the build's own context has run out.
func TestOutcomeAfterTimeout(t *testing.T) {
	a := &buildAPI{}
	g, _ := buildGateway(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &builder{g: g, ctx: ctx, stage: "s", name: "x", project: "root", spec: buildSpec{FromTemplate: "y"}}
	b.run()
	if status, _, _ := a.state(); status != "error" {
		t.Fatalf("final status: %q", status)
	}
}
