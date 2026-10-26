package e2e

import (
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

func byIndex(t *testing.T, res []*pb.CreateSandboxResult, n int) []string {
	t.Helper()
	out := make([]string, n)
	for _, r := range res {
		if r.ErrorReason != "" {
			t.Fatalf("item %d: %s %s", r.Index, r.ErrorReason, r.ErrorMessage)
		}
		out[r.Index] = r.Sandbox.Id
	}
	for i, id := range out {
		if id == "" {
			t.Fatalf("no result for item %d", i)
		}
	}
	return out
}

func batch(t *testing.T, c *client.Client, r *pb.CreateSandboxesRequest) []*pb.CreateSandboxResult {
	t.Helper()
	st, err := c.CreateSandboxes(ctx(t), r)
	if err != nil {
		t.Fatal(err)
	}
	var out []*pb.CreateSandboxResult
	for {
		x, err := st.Recv()
		if err != nil {
			if len(out) == 0 && rpcutil.Reason(err) != "" {
				t.Fatal(err)
			}
			return out
		}
		out = append(out, x)
	}
}

// TestBatchRetry: a bulk creation or fork retried with the same request_id
// returns what the first attempt made instead of making more (a client that
// lost the stream to an apiserver or edge crash retries safely).
func TestBatchRetry(t *testing.T) {
	_, admin := start(t, 2, 1000)
	cx := ctx(t)
	live := func() int {
		l, err := admin.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"})
		if err != nil {
			t.Fatal(err)
		}
		return len(l.Sandboxes)
	}

	// Bulk creation: the retry returns the same sandboxes; a larger count
	// makes only the missing ones.
	key := ids.NewLease()
	first := byIndex(t, batch(t, admin, &pb.CreateSandboxesRequest{Project: "root", Spec: spec, Count: 4, RequestId: key}), 4)
	again := byIndex(t, batch(t, admin, &pb.CreateSandboxesRequest{Project: "root", Spec: spec, Count: 6, RequestId: key, Retry: true}), 6)
	for i := range first {
		if again[i] != first[i] {
			t.Fatalf("retry item %d: %s, first attempt made %s", i, again[i], first[i])
		}
	}
	if n := live(); n != 6 {
		t.Fatalf("%d sandboxes after the retry, want 6", n)
	}
	// A stopped item is replaced by a new sandbox.
	if _, err := admin.Stop(cx, first[1]); err != nil {
		t.Fatal(err)
	}
	third := byIndex(t, batch(t, admin, &pb.CreateSandboxesRequest{Project: "root", Spec: spec, Count: 6, RequestId: key, Retry: true}), 6)
	if third[1] == first[1] || third[0] != first[0] || third[5] != again[5] {
		t.Fatalf("after stopping item 1: %v (before %v)", third, again)
	}

	// Fork: the same, and the retry does not snapshot the source again.
	src, err := admin.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	fkey := ids.NewLease()
	r1, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 3, RequestId: fkey})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 3, RequestId: fkey, Retry: true})
	if err != nil {
		t.Fatal(err)
	}
	a, b := byIndex(t, r1, 3), byIndex(t, r2, 3)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("fork retry copy %d: %s, first attempt made %s", i, b[i], a[i])
		}
	}
	if r1[0].Sandbox.Spec.Snapshot != r2[0].Sandbox.Spec.Snapshot {
		t.Fatal("fork retry took a new snapshot although every copy existed")
	}
	if n := live(); n != 6+1+3 {
		t.Fatalf("%d sandboxes after the fork retry, want 10", n)
	}

	// Without retry, the key only names the leases; a bad key is refused.
	if _, err := admin.Fork(cx, &pb.ForkSandboxRequest{SandboxId: src.Id, Count: 1, RequestId: "BAD"}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("bad request_id: %v", err)
	}
}

// TestLeaseReuse: a create naming a lease that is held is refused unless it
// is a retry, which returns the sandbox the lease made; nothing is created
// or charged twice.
func TestLeaseReuse(t *testing.T) {
	_, admin := start(t, 2, 1000)
	cx := ctx(t)
	lease := ids.NewLease()
	sb, err := admin.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: "root", Spec: spec, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: "root", Spec: spec, Lease: lease})
	if rpcutil.Reason(err) != rpcutil.Conflict {
		t.Fatalf("reusing a held lease: %v, want conflict", err)
	}
	again, err := admin.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: "root", Spec: spec, Lease: lease, Retry: true})
	if err != nil || again.Id != sb.Id {
		t.Fatalf("retry = %v, %v; want %s", again.GetId(), err, sb.Id)
	}
	l, err := admin.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"})
	if err != nil || len(l.Sandboxes) != 1 {
		t.Fatalf("%d sandboxes, %v; want 1", len(l.GetSandboxes()), err)
	}
}
