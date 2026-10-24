package apiserver

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

type snapWatcher struct {
	pb.WatcherClient
	snap *pb.Snapshot
}

func (w *snapWatcher) GetSnapshot(context.Context, *pb.Empty, ...grpc.CallOption) (*pb.Snapshot, error) {
	return w.snap, nil
}

// TestRefreshKeepsMissingEdges: an edge missing from a snapshot (a watcher
// that just restarted has not heard from it yet) stays routable for
// edgeAddrGrace; an edge never seen is not_found.
func TestRefreshKeepsMissingEdges(t *testing.T) {
	w := &snapWatcher{snap: &pb.Snapshot{Edges: []*pb.EdgeState{
		{Id: "e1", Addr: "10.0.0.1:7201", Healthy: true}, {Id: "e2", Addr: "10.0.0.2:7201", Healthy: true}}}}
	s := New(config.APIServer{}, config.Placement{}, nil, w, rpcutil.NewPool(nil), slog.New(slog.DiscardHandler))
	ctx := context.Background()
	s.Refresh(ctx)
	w.snap = &pb.Snapshot{Edges: []*pb.EdgeState{{Id: "e1", Addr: "10.0.0.1:7201", Healthy: true}}}
	s.Refresh(ctx)
	if got := (*s.addrs.Load())["e2"]; got != "10.0.0.2:7201" {
		t.Fatalf("e2 dropped at once: %q", got)
	}
	if _, err := s.edgeClient("nope"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("an edge never seen: %v", err)
	}
	s.goneMu.Lock()
	g := s.gone["e2"]
	g.since = time.Now().Add(-edgeAddrGrace)
	s.gone["e2"] = g
	s.goneMu.Unlock()
	s.Refresh(ctx)
	if _, ok := (*s.addrs.Load())["e2"]; ok {
		t.Fatal("e2 kept past the grace")
	}
	// Back in a snapshot: routed again, and a later absence starts afresh.
	w.snap.Edges = append(w.snap.Edges, &pb.EdgeState{Id: "e2", Addr: "10.0.0.2:7201", Healthy: true})
	s.Refresh(ctx)
	w.snap.Edges = w.snap.Edges[:1]
	s.Refresh(ctx)
	if _, ok := (*s.addrs.Load())["e2"]; !ok {
		t.Fatal("e2 dropped at once after coming back")
	}
}
