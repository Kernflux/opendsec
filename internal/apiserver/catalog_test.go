package apiserver

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeKV is IAM's key-value area in memory, with its revision checks.
// refuse makes it answer like an IAM that does not accept img/ keys.
type fakeKV struct {
	pb.IAMClient
	mu     sync.Mutex
	rev    uint64
	kv     map[string]*pb.KVEntry
	refuse bool
	puts   int
}

func newFakeKV() *fakeKV { return &fakeKV{kv: map[string]*pb.KVEntry{}} }

func (f *fakeKV) check(key string, check bool, expect uint64) error {
	if f.refuse && strings.HasPrefix(key, "img/") {
		return rpcutil.Err(rpcutil.Invalid, "key %q: allowed prefixes are [fleet/ ext/]", key)
	}
	var cur uint64
	if e := f.kv[key]; e != nil {
		cur = e.Rev
	}
	if check && cur != expect {
		return rpcutil.Err(rpcutil.Conflict, "%s is at revision %d, not %d", key, cur, expect)
	}
	return nil
}

func (f *fakeKV) KVGet(_ context.Context, r *pb.KVGetRequest, _ ...grpc.CallOption) (*pb.KVEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.kv[r.Key]; e != nil {
		return &pb.KVEntry{Key: e.Key, Value: e.Value, Rev: e.Rev}, nil
	}
	return &pb.KVEntry{Key: r.Key}, nil
}

func (f *fakeKV) KVList(_ context.Context, r *pb.KVListRequest, _ ...grpc.CallOption) (*pb.KVEntries, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &pb.KVEntries{}
	for k, e := range f.kv {
		if strings.HasPrefix(k, r.Prefix) {
			out.Entries = append(out.Entries, &pb.KVEntry{Key: e.Key, Value: e.Value, Rev: e.Rev})
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Key < out.Entries[j].Key })
	return out, nil
}

func (f *fakeKV) KVPut(_ context.Context, r *pb.KVPutRequest, _ ...grpc.CallOption) (*pb.KVEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(r.Key, r.Check, r.ExpectRev); err != nil {
		return nil, err
	}
	f.rev++
	f.puts++
	f.kv[r.Key] = &pb.KVEntry{Key: r.Key, Value: append([]byte(nil), r.Value...), Rev: f.rev}
	return &pb.KVEntry{Key: r.Key, Value: r.Value, Rev: f.rev}, nil
}

func (f *fakeKV) KVDelete(_ context.Context, r *pb.KVDeleteRequest, _ ...grpc.CallOption) (*pb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(r.Key, r.Check, r.ExpectRev); err != nil {
		return nil, err
	}
	if f.kv[r.Key] != nil {
		f.rev++
		delete(f.kv, r.Key)
	}
	return &pb.Empty{}, nil
}

func (f *fakeKV) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kv[catalogPrefix+name] != nil
}

func testStore(t *testing.T) (*images.Store, string) {
	t.Helper()
	st, err := images.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := images.NewDiffLayerID()
	w, _, err := st.BeginLayer(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	return st, id
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// startCatalog runs c's switch-over once, as Run does at start.
func startCatalog(t *testing.T, c *catalog) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for !c.kv.Load() {
		if time.Now().After(deadline) {
			t.Fatal("catalog did not switch to IAM")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCatalogImportsAndMirrors(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	// Published before the catalog: only a file.
	if err := st.PutManifest(&images.Manifest{Name: "root/a/old:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	kv := newFakeKV()
	c := newCatalog(st, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)
	if !kv.has("root/a/old:v1") {
		t.Fatal("the existing image was not imported")
	}

	// A new image: in the catalog, and in its file for the edges.
	if err := c.Put(ctx, &images.Manifest{Name: "root/a/new:v1", Layers: []string{layer}, Workdir: "/srv"}, false); err != nil {
		t.Fatal(err)
	}
	if !kv.has("root/a/new:v1") {
		t.Fatal("not in the catalog")
	}
	if m, err := st.GetManifest("root/a/new:v1"); err != nil || m.Workdir != "/srv" {
		t.Fatalf("file: %v %v", m, err)
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/a/new:v1", Layers: []string{layer}}, false); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("taking a taken name: %v", err)
	}
	// Overwrite: the catalog and the file both change, at once for this apiserver.
	if err := c.Put(ctx, &images.Manifest{Name: "root/a/new:v1", Layers: []string{layer}, Workdir: "/w2"}, true); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Get(ctx, "root/a/new:v1"); err != nil || m.Workdir != "/w2" {
		t.Fatalf("catalog after overwrite: %v %v", m, err)
	}
	if m, _ := st.GetManifest("root/a/new:v1"); m.Workdir != "/w2" {
		t.Fatalf("file after overwrite: %v", m.Workdir)
	}

	ms, err := c.List(ctx, "root/a")
	if err != nil || len(ms) != 2 || ms[0].Name != "root/a/new:v1" || ms[1].Name != "root/a/old:v1" {
		t.Fatalf("list: %v %v", ms, err)
	}
	if ms, _ := c.List(ctx, "root/ab"); len(ms) != 0 {
		t.Fatalf("root/ab lists root/a's images: %v", ms)
	}

	if err := c.Delete(ctx, "root/a/new:v1"); err != nil {
		t.Fatal(err)
	}
	if kv.has("root/a/new:v1") {
		t.Fatal("still in the catalog")
	}
	if _, err := st.GetManifest("root/a/new:v1"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("file left: %v", err)
	}
	if _, err := c.Get(ctx, "root/a/new:v1"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("get after delete: %v", err)
	}
}

// An image written only as a file (by an older apiserver during an
// upgrade) is found, and imported on the way.
func TestCatalogFindsFileOnlyImages(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	c := newCatalog(st, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)
	if err := st.PutManifest(&images.Manifest{Name: "root/late:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "root/late:v1"); err != nil {
		t.Fatal(err)
	}
	if !kv.has("root/late:v1") {
		t.Fatal("not imported")
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/late2:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	// A file-only name is taken for a new image too.
	if err := st.PutManifest(&images.Manifest{Name: "root/late3:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/late3:v1", Layers: []string{layer}}, false); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("file-only name: %v", err)
	}
}

// With an IAM that refuses img/ keys, the catalog is the files.
func TestCatalogWithOlderIAM(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	kv.refuse = true
	c := newCatalog(st, kv, fakeEdges{st}, quietLog())
	ctx2, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { c.run(ctx2); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(50 * time.Millisecond)
	if c.kv.Load() {
		t.Fatal("switched to an IAM that refuses the keys")
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/x:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest("root/x:v1"); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Get(ctx, "root/x:v1"); err != nil || m.Name != "root/x:v1" {
		t.Fatalf("%v %v", m, err)
	}
	if ms, err := c.List(ctx, "root"); err != nil || len(ms) != 1 {
		t.Fatalf("%v %v", ms, err)
	}
	if err := c.Delete(ctx, "root/x:v1"); err != nil {
		t.Fatal(err)
	}
}

// A file that cannot be written takes the catalog entry back: edges would
// not find the image.
func TestCatalogTakesBackUnwrittenEntry(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	c := newCatalog(st, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)
	if err := c.Put(ctx, &images.Manifest{Name: "root/p/img:v1", Layers: []string{layer}, Workdir: "/one"}, false); err != nil {
		t.Fatal(err)
	}
	// A file where the directory for root/p/img2 would go: its file cannot be written.
	if err := writeFile(st.Root+"/images/root/p/img2", "x"); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/p/img2:v1", Layers: []string{layer}}, true); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("put: %v", err)
	}
	if kv.has("root/p/img2:v1") {
		t.Fatal("an entry without its file stayed")
	}
}

func TestWithTimeoutGivesUp(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	start := time.Now()
	_, err := withTimeout(context.Background(), 50*time.Millisecond, func() (int, error) { <-block; return 1, nil })
	if rpcutil.Reason(err) != rpcutil.Unavailable || time.Since(start) > time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// fakeEdges is one edge with the store mounted (st; nil: no edge).
type fakeEdges struct{ st *images.Store }

func (f fakeEdges) storeEdgeIDs(string) []string {
	if f.st == nil {
		return nil
	}
	return []string{"e1"}
}

func (f fakeEdges) edgeClient(string) (pb.EdgeClient, error) { return fakeEdge{st: f.st}, nil }

type fakeEdge struct {
	pb.EdgeClient
	st *images.Store
}

func (f fakeEdge) CheckLayers(_ context.Context, r *pb.CheckLayersRequest, _ ...grpc.CallOption) (*pb.CheckLayersResponse, error) {
	out := &pb.CheckLayersResponse{}
	for _, l := range r.LayerIds {
		if !f.st.HasLayer(l) {
			out.Missing = append(out.Missing, l)
		}
	}
	return out, nil
}

func (f fakeEdge) DeleteSnapshot(_ context.Context, r *pb.DeleteSnapshotRequest, _ ...grpc.CallOption) (*pb.Empty, error) {
	return &pb.Empty{}, f.st.DeleteSnapshot(r.SnapshotId)
}

// Without manifest files, the apiserver never touches the store: the
// catalog is IAM's, and layers are checked and snapshot files removed
// through an edge.
func TestCatalogWithoutFiles(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	c := newCatalog(nil, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)

	if err := c.Put(ctx, &images.Manifest{Name: "root/a/img:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest("root/a/img:v1"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("a manifest file was written: %v", err)
	}
	if m, err := c.Get(ctx, "root/a/img:v1"); err != nil || m.Layers[0] != layer {
		t.Fatalf("%v %v", m, err)
	}
	missing := images.NewDiffLayerID()
	if err := c.Put(ctx, &images.Manifest{Name: "root/a/bad:v1", Layers: []string{layer, missing}}, false); rpcutil.Reason(err) != rpcutil.NotFound ||
		!strings.Contains(rpcutil.Message(err), missing) {
		t.Fatalf("a missing layer: %v", err)
	}

	// A snapshot an edge took: its record in the catalog, its files in the store.
	id := images.NewSnapshotID()
	if err := st.PutSnapshot(&images.Snapshot{ID: id, Layers: []string{layer}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutSnapshot(ctx, &images.Snapshot{ID: id, Layers: []string{layer}, Env: map[string]string{"A": "1"}}); err != nil {
		t.Fatal(err)
	}
	if snap, err := c.GetSnapshot(ctx, id); err != nil || snap.Env["A"] != "1" {
		t.Fatalf("%v %v", snap, err)
	}
	refs, err := c.Refs(ctx)
	if err != nil || len(refs.Images) != 1 || len(refs.Snapshots) != 1 {
		t.Fatalf("refs: %+v %v", refs, err)
	}
	c.DeleteSnapshot(ctx, id, "e1")
	if _, err := c.GetSnapshot(ctx, id); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("record left: %v", err)
	}
	if _, err := st.GetSnapshot(id); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("files left: %v", err)
	}

	if err := c.Delete(ctx, "root/a/img:v1"); err != nil {
		t.Fatal(err)
	}
	if ms, err := c.List(ctx, "root"); err != nil || len(ms) != 0 {
		t.Fatalf("%v %v", ms, err)
	}

	// No edge to check layers with: publishing waits for one.
	c2 := newCatalog(nil, kv, fakeEdges{}, quietLog())
	c2.kv.Store(true)
	if err := c2.Put(ctx, &images.Manifest{Name: "root/a/img:v2", Layers: []string{layer}}, false); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("without edges: %v", err)
	}
}

// GC keeps what the catalog names and drops, through ForgetSnapshots, the
// records of the snapshots it removes.
func TestGCWithCatalogRefs(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	c := newCatalog(nil, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)
	old := images.NewSnapshotID()
	if err := st.PutSnapshot(&images.Snapshot{ID: old, Layers: []string{layer}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutSnapshot(ctx, &images.Snapshot{ID: old, Layers: []string{layer}, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	os.Chtimes(filepath.Join(st.Root, "snapshots", old, "snapshot.json"), past, past)
	os.Chtimes(filepath.Join(st.Root, "layers", layer, "meta.json"), past, past)
	if err := c.Put(ctx, &images.Manifest{Name: "root/keep:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	refs, err := c.Refs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.GCRefs(refs, 24*time.Hour, false, func(ids []string) error { return c.ForgetSnapshots(ctx, ids) })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Snapshots) != 1 || len(res.Layers) != 0 {
		t.Fatalf("removed %+v", res)
	}
	if _, err := c.GetSnapshot(ctx, old); err == nil {
		t.Fatal("the record of the removed snapshot stayed")
	}
	if !st.HasLayer(layer) {
		t.Fatal("a layer an image names went")
	}
}

// With manifest files but nothing mounted, publishing fails cleanly (no
// entry without its file, nothing written to the empty mount point) while
// reads go on from the catalog.
func TestCatalogStoreNotMounted(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	kv := newFakeKV()
	c := newCatalog(st, kv, fakeEdges{st}, quietLog())
	startCatalog(t, c)
	if err := c.Put(ctx, &images.Manifest{Name: "root/a:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	c2 := newCatalog(images.OpenStore(empty), kv, fakeEdges{st}, quietLog())
	startCatalog(t, c2)
	if _, err := c2.Get(ctx, "root/a:v1"); err != nil {
		t.Fatalf("read with the store away: %v", err)
	}
	if err := c2.Put(ctx, &images.Manifest{Name: "root/b:v1", Layers: []string{layer}}, false); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("publish with the store away: %v", err)
	}
	if kv.has("root/b:v1") {
		t.Fatal("an entry without its file stayed")
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Fatalf("written into the empty mount point: %v", ents)
	}
}

// oldEdges are edges older than the catalog: they do not know CheckLayers
// or DeleteSnapshot.
type oldEdges struct{}

func (oldEdges) storeEdgeIDs(string) []string             { return []string{"e1", "e2"} }
func (oldEdges) edgeClient(string) (pb.EdgeClient, error) { return oldEdge{}, nil }

type oldEdge struct{ pb.EdgeClient }

func (oldEdge) CheckLayers(context.Context, *pb.CheckLayersRequest, ...grpc.CallOption) (*pb.CheckLayersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method CheckLayers")
}

func (oldEdge) DeleteSnapshot(context.Context, *pb.DeleteSnapshotRequest, ...grpc.CallOption) (*pb.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method DeleteSnapshot")
}

// With older edges, an apiserver with the store mounted does their part.
func TestCatalogWithOlderEdges(t *testing.T) {
	ctx := context.Background()
	st, layer := testStore(t)
	c := newCatalog(st, newFakeKV(), oldEdges{}, quietLog())
	startCatalog(t, c)
	if err := c.Put(ctx, &images.Manifest{Name: "root/a:v1", Layers: []string{layer}}, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, &images.Manifest{Name: "root/b:v1", Layers: []string{images.NewDiffLayerID()}}, false); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("missing layer: %v", err)
	}
	id := images.NewSnapshotID()
	st.PutSnapshot(&images.Snapshot{ID: id, Layers: []string{layer}})
	c.DeleteSnapshot(ctx, id, "e1")
	if _, err := st.GetSnapshot(id); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("files left: %v", err)
	}
	// Without the store mounted, publishing waits for a newer edge.
	c2 := newCatalog(nil, newFakeKV(), oldEdges{}, quietLog())
	c2.kv.Store(true)
	if err := c2.Put(ctx, &images.Manifest{Name: "root/a:v1", Layers: []string{layer}}, false); rpcutil.Reason(err) != rpcutil.Unavailable {
		t.Fatalf("%v", err)
	}
}
