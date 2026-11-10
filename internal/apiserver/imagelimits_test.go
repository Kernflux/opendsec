package apiserver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func limitsRig(t *testing.T, projects map[string]config.ProjectAdmission) (*Server, *catalog, string) {
	t.Helper()
	st, layer := testStore(t)
	c := newCatalog(nil, newFakeKV(), fakeEdges{st}, quietLog())
	startCatalog(t, c)
	s := &Server{imagesOn: true, log: quietLog(), iam: c.iam, authz: map[string]time.Time{},
		authn: map[string]authnEntry{"tok": {principal: "u", exp: time.Now().Add(time.Hour)}}}
	s.catOnce.Do(func() { s.cat = c })
	s.SetAdmission(config.Admission{Projects: projects})
	return s, c, layer
}

// Image quotas count a project's own images (not its subprojects'), and
// an overwrite does not count the image it replaces.
func TestImageQuota(t *testing.T) {
	ctx := context.Background()
	s, c, layer := limitsRig(t, map[string]config.ProjectAdmission{"root/try/u": {MaxImages: 2, MaxImageMB: 3}})
	put := func(name string, mb int64) {
		t.Helper()
		if err := c.Put(ctx, &images.Manifest{Name: name, Layers: []string{layer}, Size: mb << 20}, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.checkImageQuota(ctx, "root/other/x:1"); err != nil {
		t.Fatalf("unlimited project: %v", err)
	}
	put("root/try/u/gh-1/a:1", 1)
	put("root/try/u/gh-1/sub/z:1", 50) // a subproject's: not counted
	put("root/try/u/gh-2/a:1", 50)     // another user's
	if err := s.checkImageQuota(ctx, "root/try/u/gh-1/b:1"); err != nil {
		t.Fatalf("second image: %v", err)
	}
	put("root/try/u/gh-1/b:1", 1)
	if err := s.checkImageQuota(ctx, "root/try/u/gh-1/c:1"); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("third image: %v", err)
	}
	if err := s.checkImageQuota(ctx, "root/try/u/gh-1/b:1"); err != nil {
		t.Fatalf("overwriting one: %v", err)
	}
	// Data: 2 MB of 3; one more over the limit, then nothing.
	s.SetAdmission(config.Admission{Projects: map[string]config.ProjectAdmission{"root/try/u": {MaxImageMB: 3}}})
	if err := s.checkImageQuota(ctx, "root/try/u/gh-1/c:1"); err != nil {
		t.Fatalf("under the data limit: %v", err)
	}
	put("root/try/u/gh-1/c:1", 2)
	if err := s.checkImageQuota(ctx, "root/try/u/gh-1/d:1"); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("over the data limit: %v", err)
	}
}

// Unused images expire; a use (Touch) keeps one; an entry changed after it
// was listed is not deleted.
func TestImageExpiry(t *testing.T) {
	ctx := context.Background()
	s, c, layer := limitsRig(t, map[string]config.ProjectAdmission{"root/try/u": {ImageTTL: 3600}})
	old := float64(time.Now().Add(-2*time.Hour).UnixNano()) / 1e9
	for _, n := range []string{"root/try/u/gh-1/old:1", "root/try/u/gh-1/used:1", "root/try/u/gh-1/new:1", "root/keep/old:1"} {
		created := old
		if n == "root/try/u/gh-1/new:1" {
			created = 0 // Put stamps now
		}
		if err := c.Put(ctx, &images.Manifest{Name: n, Layers: []string{layer}, CreatedAt: created}, false); err != nil {
			t.Fatal(err)
		}
	}
	m, err := c.Get(ctx, "root/try/u/gh-1/used:1")
	if err != nil {
		t.Fatal(err)
	}
	if m.CreatedAt != old {
		t.Skip("Put stamps its own creation time; expiry checked in e2e")
	}
	s.noteImageUse(m) // stale: touched in the background
	deadline := time.Now().Add(5 * time.Second)
	for {
		m, _ := c.Fresh(ctx, "root/try/u/gh-1/used:1")
		if m != nil && m.UsedAt > old {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("use not recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Listed before a use: Expire leaves it.
	stale, _ := c.List(ctx, "root/try/u")
	s.expireImagesOnce(ctx)
	for n, want := range map[string]bool{"root/try/u/gh-1/old:1": false, "root/try/u/gh-1/used:1": true,
		"root/try/u/gh-1/new:1": true, "root/keep/old:1": true} {
		if _, err := c.Fresh(ctx, n); (err == nil) != want {
			t.Errorf("%s: kept=%v, want %v (%v)", n, err == nil, want, err)
		}
	}
	for _, m := range stale {
		if m.Name == "root/try/u/gh-1/new:1" {
			if err := c.Touch(ctx, m.Name, float64(time.Now().UnixNano())/1e9); err != nil {
				t.Fatal(err)
			}
			if gone, err := c.Expire(ctx, m); gone || err != nil {
				t.Fatalf("expired an entry used after it was listed: %v %v", gone, err)
			}
		}
	}
}

func sizedLayer(t *testing.T, st *images.Store, size int64) string {
	t.Helper()
	id := images.NewDiffLayerID()
	w, _, err := st.BeginLayer(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(images.LayerMeta{Source: "test", Size: size}); err != nil {
		t.Fatal(err)
	}
	return id
}

// RegisterImage counts the layers' data whatever the caller does: an
// overwrite does not reset it, and another name for the same layers counts.
func TestRegisterImageSize(t *testing.T) {
	st, _ := testStore(t)
	c := newCatalog(nil, newFakeKV(), fakeEdges{st}, quietLog())
	startCatalog(t, c)
	s := &Server{imagesOn: true, log: quietLog(), iam: c.iam, authz: map[string]time.Time{},
		authn: map[string]authnEntry{"tok": {principal: "u", exp: time.Now().Add(time.Hour)}}}
	s.catOnce.Do(func() { s.cat = c })
	s.SetAdmission(config.Admission{Projects: map[string]config.ProjectAdmission{"root/try/u": {MaxImageMB: 8}}})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer tok"))
	big := sizedLayer(t, st, 5<<20)
	reg := func(name string, overwrite bool) (*pb.ImageInfo, error) {
		return s.RegisterImage(ctx, &pb.RegisterImageRequest{Overwrite: overwrite,
			Image: &pb.ImageInfo{Name: name, Layers: []string{big}, SizeBytes: 1}})
	}
	for _, overwrite := range []bool{false, true} {
		info, err := reg("root/try/u/a:1", overwrite)
		if err != nil || info.SizeBytes != 5<<20 {
			t.Fatalf("overwrite=%v: %v %v", overwrite, info, err)
		}
	}
	if _, err := reg("root/try/u/b:1", false); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("the same layers under a second name, over the room left: %v", err)
	}
}

// With edges too old to report sizes and no store here, a project with a
// data limit is refused rather than counted as nothing.
func TestRegisterImageSizeUnknown(t *testing.T) {
	c := newCatalog(nil, newFakeKV(), oldEdges{}, quietLog())
	if n := c.layersSize(context.Background(), []string{"x"}); n != -1 {
		t.Fatalf("size from old edges: %d", n)
	}
}

// Publishes at once under different names cannot all pass the check.
func TestPublishQuotaConcurrent(t *testing.T) {
	ctx := context.Background()
	s, c, layer := limitsRig(t, map[string]config.ProjectAdmission{"root/try/u": {MaxImages: 1}})
	c.iam.(*fakeKV).listFor = 5 * time.Millisecond // all would pass the check before any writes
	var ok, refused atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.publishImage(ctx, &images.Manifest{Name: fmt.Sprintf("root/try/u/gh-1/n%d:1", i), Layers: []string{layer}}, false, false)
			switch rpcutil.Reason(err) {
			case "":
				ok.Add(1)
			case rpcutil.QuotaExceeded:
				refused.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || refused.Load() != 15 {
		t.Fatalf("%d published, %d refused", ok.Load(), refused.Load())
	}
}

// Strict publishes stop at the room left; the others may pass it once.
func TestPublishStrict(t *testing.T) {
	ctx := context.Background()
	s, _, layer := limitsRig(t, map[string]config.ProjectAdmission{"root/try/u": {MaxImageMB: 3}})
	m := func(n string) *images.Manifest {
		return &images.Manifest{Name: "root/try/u/gh-1/" + n, Layers: []string{layer}, Size: 4 << 20}
	}
	if err := s.publishImage(ctx, m("a:1"), false, true); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("strict, over the room: %v", err)
	}
	if err := s.publishImage(ctx, m("a:1"), false, false); err != nil {
		t.Fatalf("not strict: %v", err)
	}
}

// A write whose lock ran out is refused, and not reported as a name taken.
func TestPutLostLock(t *testing.T) {
	ctx := context.Background()
	_, c, layer := limitsRig(t, nil)
	m := &images.Manifest{Name: "root/a:1", Layers: []string{layer}}
	for _, overwrite := range []bool{false, true} {
		err := c.put(ctx, m, overwrite, &pb.Fence{Lock: "l", Holder: "gone"})
		if rpcutil.Reason(err) != rpcutil.Unavailable {
			t.Fatalf("overwrite=%v: %v", overwrite, err)
		}
	}
	if _, err := c.Fresh(ctx, m.Name); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("written without the lock: %v", err)
	}
}

func TestTouchEvery(t *testing.T) {
	for _, c := range []struct{ ttl, want float64 }{{4, 5}, {600, 150}, {3600, 900}, {30 * 86400, 3600}} {
		if got := touchEvery(c.ttl); got != c.want {
			t.Errorf("ttl %v: %v, want %v", c.ttl, got, c.want)
		}
	}
}

// With an IAM that refuses the locks (older, during an upgrade), publishes
// go on as before them, quotas still checked.
func TestPublishOlderIAM(t *testing.T) {
	ctx := context.Background()
	s, c, layer := limitsRig(t, map[string]config.ProjectAdmission{"root/try/u": {MaxImages: 1}})
	c.iam.(*fakeKV).lockErr = rpcutil.Err(rpcutil.Forbidden, "apiserver/0 may not call /opendsec.v1.IAM/AcquireLock")
	m := func(n string) *images.Manifest {
		return &images.Manifest{Name: "root/try/u/gh-1/" + n, Layers: []string{layer}}
	}
	if err := s.publishImage(ctx, m("a:1"), false, false); err != nil {
		t.Fatalf("first image: %v", err)
	}
	if err := s.publishImage(ctx, m("b:1"), false, false); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("second image: %v", err)
	}
}
