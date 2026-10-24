package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// fakeIAM records released leases; fail makes the next calls fail.
type fakeIAM struct {
	pb.IAMClient
	mu          sync.Mutex
	batches     []int
	released    map[string]int
	fail        int  // calls left to fail
	unsupported bool // no ReleaseLeases (an older IAM)
	singles     int
}

func (f *fakeIAM) ReleaseLeases(_ context.Context, r *pb.ReleaseLeasesRequest, _ ...grpc.CallOption) (*pb.ReleaseLeasesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unsupported {
		return nil, status.Error(codes.Unimplemented, "unknown method ReleaseLeases")
	}
	if f.fail > 0 {
		f.fail--
		return nil, errors.New("iam unavailable")
	}
	f.batches = append(f.batches, len(r.Leases))
	for _, l := range r.Leases {
		f.released[l]++
	}
	return &pb.ReleaseLeasesResponse{Released: int32(len(r.Leases))}, nil
}

func (f *fakeIAM) Release(_ context.Context, r *pb.ReleaseRequest, _ ...grpc.CallOption) (*pb.ReleaseResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.singles++
	f.released[r.Lease]++
	return &pb.ReleaseResponse{Released: true}, nil
}

func (f *fakeIAM) waitReleased(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.released)
		f.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("released %d of %d leases", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestIAMReleaserBatches: a burst of ended sandboxes goes to IAM as a few
// calls of at most releaseBatch leases, each lease once.
func TestIAMReleaserBatches(t *testing.T) {
	f := &fakeIAM{released: map[string]int{}}
	release := IAMReleaser(f, "e1", quiet())
	const n = 2500
	for i := 0; i < n; i++ {
		release(fmt.Sprintf("l%d", i))
	}
	f.waitReleased(t, n)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.batches) > 5 {
		t.Fatalf("%d calls for %d leases (%v), want a few batches", len(f.batches), n, f.batches)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(f.batches)))
	if f.batches[0] > releaseBatch {
		t.Fatalf("a batch of %d leases, more than %d", f.batches[0], releaseBatch)
	}
	for l, c := range f.released {
		if c != 1 {
			t.Fatalf("lease %s released %d times", l, c)
		}
	}
}

// TestIAMReleaserRetries: a failed batch is sent again; nothing is lost.
func TestIAMReleaserRetries(t *testing.T) {
	f := &fakeIAM{released: map[string]int{}, fail: 2}
	release := IAMReleaser(f, "e1", quiet())
	for i := 0; i < 10; i++ {
		release(fmt.Sprintf("l%d", i))
	}
	f.waitReleased(t, 10)
}

// TestIAMReleaserOlderIAM: without ReleaseLeases, leases go one by one.
func TestIAMReleaserOlderIAM(t *testing.T) {
	f := &fakeIAM{released: map[string]int{}, unsupported: true}
	release := IAMReleaser(f, "e1", quiet())
	for i := 0; i < 20; i++ {
		release(fmt.Sprintf("l%d", i))
	}
	f.waitReleased(t, 20)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.singles != 20 {
		t.Fatalf("%d single releases, want 20", f.singles)
	}
}

// TestIAMReleaserIAMUpgraded: once IAM gains ReleaseLeases (its leader was
// upgraded after this edge), the edge goes back to batches.
func TestIAMReleaserIAMUpgraded(t *testing.T) {
	defer func(d time.Duration) { releaseRetryBatch = d }(releaseRetryBatch)
	releaseRetryBatch = 100 * time.Millisecond
	f := &fakeIAM{released: map[string]int{}, unsupported: true}
	release := IAMReleaser(f, "e1", quiet())
	release("old")
	f.waitReleased(t, 1)
	f.mu.Lock()
	f.unsupported = false
	f.mu.Unlock()
	time.Sleep(2 * releaseRetryBatch)
	for i := 0; i < 20; i++ {
		release(fmt.Sprintf("l%d", i))
	}
	f.waitReleased(t, 21)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.singles != 1 || len(f.batches) == 0 {
		t.Fatalf("%d single releases and %d batches after the upgrade, want 1 and some", f.singles, len(f.batches))
	}
}
