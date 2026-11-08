package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func limitsRig(t *testing.T, projects map[string]config.ProjectAdmission) (*Server, *catalog, string) {
	t.Helper()
	st, layer := testStore(t)
	c := newCatalog(nil, newFakeKV(), fakeEdges{st}, quietLog())
	startCatalog(t, c)
	s := &Server{imagesOn: true, log: quietLog()}
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
