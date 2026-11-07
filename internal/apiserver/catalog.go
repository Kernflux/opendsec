package apiserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// The image catalog (spec §42): image names with the manifests they point
// to, and the records of snapshots, live in IAM's key-value area (img/m/<name>,
// img/s/<id>), replicated through Raft. A name is taken atomically there,
// and all apiservers see the same manifest for it. The data (layers,
// snapshot files) stays on the shared store, which only edges access: the
// apiserver asks an edge whether layers exist, and has one remove a
// snapshot's files. Edges get manifests and snapshot records with each
// creation.
//
// st, when set (image_store.manifest_files), is the store as this apiserver
// mounts it, for edges and apiservers older than the catalog: every manifest
// is also written to its file, images and snapshots that only have files are
// imported, and until IAM accepts img/ keys (an older IAM during an
// upgrade) the catalog is the files, as before.

const (
	catalogPrefix  = "img/m/"
	snapshotPrefix = "img/s/"
	catalogProbe   = "img/version"
	// catalogTTL is how long an apiserver reuses an entry it read: a tag
	// another apiserver overwrote is seen within it.
	catalogTTL = 2 * time.Second
	// kvTimeout and storeTimeout bound each call to IAM or an edge, and
	// each access to the store's files: a hung shared filesystem (hard NFS
	// mounts block, they do not fail) must not hold requests forever.
	kvTimeout    = 5 * time.Second
	storeTimeout = 10 * time.Second
	// catalogImportEvery is how often files without a catalog entry are
	// looked for, and IAM is probed again while it refuses img/ keys.
	catalogImportEvery = time.Minute
)

// storeEdges reaches the edges, which access the store's data.
type storeEdges interface {
	// storeEdgeIDs lists healthy edges, the preferred one first if healthy.
	storeEdgeIDs(prefer string) []string
	edgeClient(id string) (pb.EdgeClient, error)
}

type catalog struct {
	st    *images.Store // nil: this apiserver does not access the store
	iam   pb.IAMClient
	edges storeEdges
	log   *slog.Logger

	kv atomic.Bool // IAM keeps the catalog (else: the files)

	mu    sync.Mutex
	cache map[string]catalogEntry // key -> entry
}

type catalogEntry struct {
	m    *images.Manifest
	snap *images.Snapshot
	at   time.Time
}

func newCatalog(st *images.Store, iamc pb.IAMClient, edges storeEdges, log *slog.Logger) *catalog {
	return &catalog{st: st, iam: iamc, edges: edges, log: log, cache: map[string]catalogEntry{}}
}

var errNoCatalog = rpcutil.Err(rpcutil.Unavailable, "the image catalog is not available: IAM does not keep it yet and this apiserver does not access the image store")

// run switches the catalog to IAM once IAM accepts img/ keys, importing the
// store's files first, then keeps importing ones written only as files.
func (c *catalog) run(ctx context.Context) {
	t := time.NewTicker(catalogImportEvery)
	defer t.Stop()
	for {
		if !c.kv.Load() {
			if c.probe(ctx) {
				// Switched even if the import fails (the store unreachable):
				// what is not imported yet is found in the files on use, and
				// imported on the next round.
				if err := c.importFiles(ctx); err != nil {
					c.log.Warn("image catalog: import from the store failed; retrying every minute", "err", err)
				}
				c.kv.Store(true)
				c.log.Info("image catalog: kept in IAM", "files", c.st != nil)
			}
		} else if err := c.importFiles(ctx); err != nil {
			c.log.Warn("image catalog: import from the store failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// probe reports whether IAM accepts the catalog's keys (an older IAM
// refuses the img/ prefix).
func (c *catalog) probe(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	_, err := c.iam.KVPut(ctx, &pb.KVPutRequest{Key: catalogProbe, Value: []byte("1"), Check: true})
	switch rpcutil.ReasonOf(err) {
	case "", rpcutil.Conflict: // written, or already there
		return true
	}
	c.log.Debug("image catalog: IAM does not keep it yet", "err", err)
	return false
}

// importFiles adds the store's manifests and snapshot records that have no
// catalog entry (without a store: nothing to import).
func (c *catalog) importFiles(ctx context.Context) error {
	if c.st == nil {
		return nil
	}
	ms, err := onFiles(ctx, c.st, c.st.ListAll)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if err := c.importOne(ctx, catalogPrefix+m.Name, m, func() bool {
			_, err := c.st.GetManifest(m.Name)
			return rpcutil.Reason(err) == rpcutil.NotFound
		}); err != nil {
			return err
		}
	}
	snaps, err := onFiles(ctx, c.st, func() ([]*images.Snapshot, error) { return c.st.ListSnapshots(false) })
	if err != nil {
		return err
	}
	for _, snap := range snaps {
		if err := c.importOne(ctx, snapshotPrefix+snap.ID, snap, func() bool {
			_, err := c.st.GetSnapshot(snap.ID)
			return rpcutil.Reason(err) == rpcutil.NotFound
		}); err != nil {
			return err
		}
	}
	return nil
}

// importOne adds v under key unless the key is taken. gone reports whether
// the file it came from was deleted meanwhile: then the entry is taken back.
func (c *catalog) importOne(ctx context.Context, key string, v any, gone func() bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	kctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	e, err := c.iam.KVPut(kctx, &pb.KVPutRequest{Key: key, Value: b, Check: true})
	if rpcutil.ReasonOf(err) == rpcutil.Conflict {
		return nil
	}
	if err != nil {
		return err
	}
	c.log.Info("image catalog: imported from the store", "key", key)
	if g, _ := onFiles(ctx, c.st, func() (bool, error) { return gone(), nil }); g {
		c.iam.KVDelete(kctx, &pb.KVDeleteRequest{Key: e.Key, Check: true, ExpectRev: e.Rev})
	}
	return nil
}

// ---- manifests -------------------------------------------------------------------

// Get returns the manifest of image name (canonical).
func (c *catalog) Get(ctx context.Context, name string) (*images.Manifest, error) {
	return c.getManifest(ctx, name, false)
}

// Fresh is Get without the reuse window: for answers about the name itself.
func (c *catalog) Fresh(ctx context.Context, name string) (*images.Manifest, error) {
	return c.getManifest(ctx, name, true)
}

func (c *catalog) getManifest(ctx context.Context, name string, fresh bool) (*images.Manifest, error) {
	if !c.kv.Load() {
		if c.st == nil {
			return nil, errNoCatalog
		}
		return onFiles(ctx, c.st, func() (*images.Manifest, error) {
			if fresh {
				c.st.Refresh(name)
			}
			return c.st.GetManifest(name)
		})
	}
	key := catalogPrefix + name
	if e, ok := c.cached(key, fresh); ok {
		return e.m, nil
	}
	var m images.Manifest
	found, _, err := c.kvGet(ctx, key, &m)
	if err != nil {
		return nil, err
	}
	if !found {
		if c.st == nil {
			return nil, rpcutil.Err(rpcutil.NotFound, "image %s", name)
		}
		// Published by an older apiserver, not imported yet.
		fm, err := onFiles(ctx, c.st, func() (*images.Manifest, error) {
			c.st.Refresh(name)
			return c.st.GetManifest(name)
		})
		if err != nil {
			return nil, err
		}
		if err := c.importOne(ctx, key, fm, func() bool { return false }); err != nil {
			c.log.Warn("image catalog: import failed", "image", name, "err", err)
		}
		return fm, nil
	}
	c.remember(key, catalogEntry{m: &m})
	return &m, nil
}

// kvGet reads key into v; found is false if there is no entry.
func (c *catalog) kvGet(ctx context.Context, key string, v any) (found bool, rev uint64, err error) {
	ctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	e, err := c.iam.KVGet(ctx, &pb.KVGetRequest{Key: key})
	if err != nil {
		return false, 0, err
	}
	if e.GetRev() == 0 {
		return false, 0, nil
	}
	if err := json.Unmarshal(e.Value, v); err != nil {
		return false, 0, rpcutil.Err(rpcutil.Internal, "catalog entry %s: %v", key, err)
	}
	return true, e.Rev, nil
}

// Put publishes m. Without overwrite, an existing name is an error.
func (c *catalog) Put(ctx context.Context, m *images.Manifest, overwrite bool) error {
	if err := images.ValidateManifest(m); err != nil {
		return err
	}
	if err := c.checkLayers(ctx, m.Layers, m.Snapshot, m.Name); err != nil {
		return err
	}
	if !c.kv.Load() {
		if c.st == nil {
			return errNoCatalog
		}
		_, err := onFiles(ctx, c.st, func() (struct{}, error) { return struct{}{}, c.st.WriteManifest(m, overwrite) })
		return err
	}
	if !overwrite {
		// A name with only a file (not imported yet) is taken too.
		switch _, err := c.Fresh(ctx, m.Name); rpcutil.Reason(err) {
		case "":
			return rpcutil.Err(rpcutil.Invalid, "image %s already exists", m.Name)
		case rpcutil.NotFound:
		default:
			return err
		}
	}
	key := catalogPrefix + m.Name
	var prev images.Manifest // to take the entry back if the file cannot be written
	hadPrev, _, err := c.kvGet(ctx, key, &prev)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	kctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	// The entry decides: of two writers without overwrite, one fails; with
	// overwrite, the later one wins, and the files converge on it below.
	e, err := c.iam.KVPut(kctx, &pb.KVPutRequest{Key: key, Value: b, Check: !overwrite})
	if rpcutil.ReasonOf(err) == rpcutil.Conflict {
		return rpcutil.Err(rpcutil.Invalid, "image %s already exists", m.Name)
	}
	if err != nil {
		return err
	}
	c.forget(key)
	if c.st == nil {
		return nil
	}
	if err := c.mirror(ctx, m, e.Rev); err != nil {
		// Older edges read the file: without it they cannot start the
		// image. Take the entry back to what it was.
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), kvTimeout)
		defer rcancel()
		var rerr error
		if !hadPrev {
			_, rerr = c.iam.KVDelete(rctx, &pb.KVDeleteRequest{Key: e.Key, Check: true, ExpectRev: e.Rev})
		} else if old, merr := json.Marshal(&prev); merr == nil {
			_, rerr = c.iam.KVPut(rctx, &pb.KVPutRequest{Key: e.Key, Value: old, Check: true, ExpectRev: e.Rev})
		}
		if rerr != nil {
			c.log.Warn("image catalog: could not take back an entry whose file was not written", "image", m.Name, "err", rerr)
		}
		return rpcutil.Err(rpcutil.Unavailable, "image %s: writing it to the image store failed: %v", m.Name, err)
	}
	return nil
}

// mirror writes m (catalog revision rev) to its file, then makes sure the
// file holds the newest entry: of two overwrites at once, the files could
// land in the other order than the entries.
func (c *catalog) mirror(ctx context.Context, m *images.Manifest, rev uint64) error {
	for i := 0; i < 3; i++ {
		w := m
		if _, err := onFiles(ctx, c.st, func() (struct{}, error) { return struct{}{}, c.st.WriteManifest(w, true) }); err != nil {
			return err
		}
		var cur images.Manifest
		found, curRev, err := c.kvGet(ctx, catalogPrefix+m.Name, &cur)
		if err != nil || !found || curRev == rev {
			return nil // deleted meanwhile: the delete removes the file
		}
		m, rev = &cur, curRev
	}
	return nil
}

// Delete removes image name. The file goes first: an entry without a file
// would be taken for one not imported yet, the other way round.
func (c *catalog) Delete(ctx context.Context, name string) error {
	if _, err := c.Fresh(ctx, name); err != nil {
		return err
	}
	if c.st != nil {
		if _, err := onFiles(ctx, c.st, func() (struct{}, error) {
			err := c.st.DeleteManifest(name)
			if rpcutil.Reason(err) == rpcutil.NotFound {
				err = nil
			}
			return struct{}{}, err
		}); err != nil {
			return err
		}
	}
	key := catalogPrefix + name
	c.forget(key)
	if !c.kv.Load() {
		return nil
	}
	kctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	_, err := c.iam.KVDelete(kctx, &pb.KVDeleteRequest{Key: key})
	return err
}

// List returns the images of project and its subprojects, by name.
func (c *catalog) List(ctx context.Context, project string) ([]*images.Manifest, error) {
	if !c.kv.Load() {
		if c.st == nil {
			return nil, errNoCatalog
		}
		return onFiles(ctx, c.st, func() ([]*images.Manifest, error) { return c.st.List(project) })
	}
	if err := images.ValidProject(project); err != nil {
		return nil, err
	}
	var out []*images.Manifest
	err := c.kvList(ctx, catalogPrefix+project+"/", func(key string, b []byte) {
		var m images.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			c.log.Warn("image catalog: unreadable entry", "key", key, "err", err)
			return
		}
		out = append(out, &m)
	})
	return out, err // KVList is sorted by key, which is the name
}

func (c *catalog) kvList(ctx context.Context, prefix string, f func(key string, value []byte)) error {
	ctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	r, err := c.iam.KVList(ctx, &pb.KVListRequest{Prefix: prefix})
	if err != nil {
		return err
	}
	for _, e := range r.GetEntries() {
		f(e.Key, e.Value)
	}
	return nil
}

// ---- snapshot records ------------------------------------------------------------

// PutSnapshot records a snapshot an edge took (its record as the edge
// returned it). Records never change: a snapshot is immutable.
func (c *catalog) PutSnapshot(ctx context.Context, snap *images.Snapshot) error {
	if !images.ValidSnapshotID(snap.ID) {
		return rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", snap.ID)
	}
	if !c.kv.Load() {
		if c.st == nil {
			return errNoCatalog
		}
		return nil // the edge wrote it to the store, which is the catalog
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	kctx, cancel := context.WithTimeout(ctx, kvTimeout)
	defer cancel()
	if _, err := c.iam.KVPut(kctx, &pb.KVPutRequest{Key: snapshotPrefix + snap.ID, Value: b}); err != nil {
		return err
	}
	c.remember(snapshotPrefix+snap.ID, catalogEntry{snap: snap})
	return nil
}

// GetSnapshot returns the record of snapshot id.
func (c *catalog) GetSnapshot(ctx context.Context, id string) (*images.Snapshot, error) {
	if !images.ValidSnapshotID(id) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", id)
	}
	fromFile := func() (*images.Snapshot, error) {
		return onFiles(ctx, c.st, func() (*images.Snapshot, error) { return c.st.GetSnapshot(id) })
	}
	if !c.kv.Load() {
		if c.st == nil {
			return nil, errNoCatalog
		}
		return fromFile()
	}
	key := snapshotPrefix + id
	if e, ok := c.cached(key, false); ok {
		return e.snap, nil
	}
	var snap images.Snapshot
	found, _, err := c.kvGet(ctx, key, &snap)
	if err != nil {
		return nil, err
	}
	if !found {
		if c.st == nil {
			return nil, rpcutil.Err(rpcutil.NotFound, "snapshot %s", id)
		}
		// Taken through an older apiserver, not imported yet.
		fs, err := fromFile()
		if err != nil {
			return nil, err
		}
		if err := c.importOne(ctx, key, fs, func() bool { return false }); err != nil {
			c.log.Warn("image catalog: import failed", "snapshot", id, "err", err)
		}
		return fs, nil
	}
	c.remember(key, catalogEntry{snap: &snap})
	return &snap, nil
}

// DeleteSnapshot drops snapshot id's record, then has an edge (edge, the
// one that took it, if it can) remove its files from the store. Files
// left behind are removed by garbage collection, as files without a record.
func (c *catalog) DeleteSnapshot(ctx context.Context, id, edge string) {
	key := snapshotPrefix + id
	c.forget(key)
	if c.kv.Load() {
		kctx, cancel := context.WithTimeout(ctx, kvTimeout)
		_, err := c.iam.KVDelete(kctx, &pb.KVDeleteRequest{Key: key})
		cancel()
		if err != nil {
			c.log.Warn("image catalog: dropping a snapshot record failed", "snapshot", id, "err", err)
		}
	}
	err := c.onEdge(ctx, edge, func(ctx context.Context, ec pb.EdgeClient) error {
		_, err := ec.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{SnapshotId: id})
		return err
	})
	if err != nil && c.st != nil {
		_, err = onFiles(ctx, c.st, func() (struct{}, error) { return struct{}{}, c.st.DeleteSnapshot(id) })
	}
	if err != nil {
		c.log.Warn("image catalog: removing a snapshot's files failed; garbage collection will", "snapshot", id, "err", err)
	}
}

// ---- for garbage collection ------------------------------------------------------

// Refs returns every manifest and snapshot record: what garbage collection
// keeps. With the store mounted, its files count too, until imported.
func (c *catalog) Refs(ctx context.Context) (*images.Refs, error) {
	if !c.kv.Load() {
		if c.st == nil {
			return nil, errNoCatalog
		}
		return onFiles(ctx, c.st, c.st.FileRefs)
	}
	refs := &images.Refs{}
	seenM, seenS := map[string]bool{}, map[string]bool{}
	var bad error
	if err := c.kvList(ctx, catalogPrefix, func(key string, b []byte) {
		var m images.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			bad = rpcutil.Err(rpcutil.Internal, "catalog entry %s: %v", key, err)
			return
		}
		seenM[m.Name] = true
		refs.Images = append(refs.Images, &m)
	}); err != nil {
		return nil, err
	}
	if err := c.kvList(ctx, snapshotPrefix, func(key string, b []byte) {
		var snap images.Snapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			bad = rpcutil.Err(rpcutil.Internal, "catalog entry %s: %v", key, err)
			return
		}
		seenS[snap.ID] = true
		refs.Snapshots = append(refs.Snapshots, &snap)
	}); err != nil {
		return nil, err
	}
	if bad != nil {
		return nil, bad // a reference GC cannot read stops it
	}
	if c.st != nil {
		files, err := onFiles(ctx, c.st, c.st.FileRefs)
		if err != nil {
			return nil, err
		}
		for _, m := range files.Images {
			if !seenM[m.Name] {
				refs.Images = append(refs.Images, m)
			}
		}
		for _, snap := range files.Snapshots {
			if !seenS[snap.ID] {
				refs.Snapshots = append(refs.Snapshots, snap)
			}
		}
	}
	return refs, nil
}

// ForgetSnapshots drops the records of snapshots garbage collection removes.
func (c *catalog) ForgetSnapshots(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if !images.ValidSnapshotID(id) {
			return rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", id)
		}
	}
	if !c.kv.Load() {
		return nil // the records are the files GC removes
	}
	for _, id := range ids {
		c.forget(snapshotPrefix + id)
		kctx, cancel := context.WithTimeout(ctx, kvTimeout)
		_, err := c.iam.KVDelete(kctx, &pb.KVDeleteRequest{Key: snapshotPrefix + id})
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- the store's data, through edges ---------------------------------------------

// checkLayers fails unless the store has all layers (and marks them, and
// snapshot, used: a garbage collection running meanwhile keeps them).
func (c *catalog) checkLayers(ctx context.Context, layers []string, snapshot, image string) error {
	var missing []string
	err := c.onEdge(ctx, "", func(ctx context.Context, ec pb.EdgeClient) error {
		r, err := ec.CheckLayers(ctx, &pb.CheckLayersRequest{LayerIds: layers, SnapshotId: snapshot})
		missing = r.GetMissing()
		return err
	})
	if err != nil && c.st != nil {
		_, err = onFiles(ctx, c.st, func() (struct{}, error) {
			missing = nil
			c.st.Touch(layers, snapshot)
			for _, l := range layers {
				if !c.st.HasLayer(l) {
					missing = append(missing, l)
				}
			}
			return struct{}{}, nil
		})
	}
	if err != nil {
		return rpcutil.Err(rpcutil.Unavailable, "image %s: cannot check its layers in the image store: %v", image, err)
	}
	if len(missing) > 0 {
		return images.MissingLayer(missing[0], image)
	}
	return nil
}

// onEdge runs f against an edge: prefer if it is healthy, else another, up
// to three. Edges too old to know the call are skipped.
func (c *catalog) onEdge(ctx context.Context, prefer string, f func(context.Context, pb.EdgeClient) error) error {
	ids := c.edges.storeEdgeIDs(prefer)
	if len(ids) == 0 {
		return rpcutil.Err(rpcutil.Unavailable, "no healthy edge")
	}
	var last error
	for i, id := range ids {
		if i == 3 {
			break
		}
		ec, err := c.edges.edgeClient(id)
		if err == nil {
			ectx, cancel := context.WithTimeout(ctx, kvTimeout)
			err = f(ectx, ec)
			cancel()
		}
		if err == nil {
			return nil
		}
		if status.Code(err) == codes.Unimplemented {
			err = rpcutil.Err(rpcutil.Unavailable, "edge %s is too old", id)
		} else if r := rpcutil.Reason(err); r != rpcutil.Unavailable && r != rpcutil.Timeout {
			return err // an answer, not an edge that could not give one
		}
		last = err
	}
	return last
}

// ---- cache -----------------------------------------------------------------------

func (c *catalog) cached(key string, fresh bool) (catalogEntry, bool) {
	if fresh {
		return catalogEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || time.Since(e.at) >= catalogTTL {
		return catalogEntry{}, false
	}
	return e, true
}

func (c *catalog) remember(key string, e catalogEntry) {
	e.at = time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) > 10000 { // expired entries are only dropped here
		for k, old := range c.cache {
			if time.Since(old.at) >= catalogTTL {
				delete(c.cache, k)
			}
		}
	}
	c.cache[key] = e
}

func (c *catalog) forget(key string) {
	c.mu.Lock()
	delete(c.cache, key)
	c.mu.Unlock()
}

// withTimeout runs f, giving up after d (or when ctx ends). f keeps running
// when given up on: a call into a hung filesystem cannot be interrupted.
func withTimeout[T any](ctx context.Context, d time.Duration, f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-t.C:
	case <-ctx.Done():
	}
	var zero T
	return zero, rpcutil.Err(rpcutil.Unavailable, "the image store did not answer within %s", d)
}

// onFiles runs f on the store's files, if the store is there, within
// storeTimeout.
func onFiles[T any](ctx context.Context, st *images.Store, f func() (T, error)) (T, error) {
	return withTimeout(ctx, storeTimeout, func() (T, error) {
		if err := st.Check(); err != nil {
			var zero T
			return zero, err
		}
		return f()
	})
}

// shuffled returns ids in random order with prefer first, if present.
func shuffled(ids []string, prefer string) []string {
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	for i, id := range ids {
		if id == prefer {
			ids[0], ids[i] = ids[i], ids[0]
		}
	}
	return ids
}
