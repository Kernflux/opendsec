package microvm

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// snapCache makes store snapshots restorable on this node (spec §19.12).
// Restoring hard-links a snapshot's files into the jail; when the store is
// on another filesystem (shared storage, another node's), the snapshot is
// first pulled into a node-local copy, once, which every copy on the node
// then links (sharing its page cache). Copies whose snapshot left the store
// are dropped by gc; running VMs keep their links.
type snapCache struct {
	dir   string
	disks string // where read-only disks fetched from peers are kept, by content id
	store *images.Store
	log   *slog.Logger

	mu      sync.Mutex
	pulling map[string]*build
}

var vmSnapshotFiles = []string{images.VMStateFile, images.VMMemFile, images.VMDiskFile, images.VMImageFile, images.VMAgentsFile}

// dirFor returns a directory on the node's filesystem holding the files of
// snapshot id, whose store directory is storeDir: the store's own, the
// node's copy (taken here, or pulled before), a fresh pull once the edge
// that took the snapshot has published it, or, for a snapshot held by
// another edge, a fetch from peer (spec §26).
func (c *snapCache) dirFor(ctx context.Context, id, storeDir string, peer backend.SnapshotPeer) (string, error) {
	p := filepath.Join(c.dir, id)
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	t0 := time.Now()
	defer func() { c.log.Debug("snapshot ready", "snapshot", id, "took", time.Since(t0)) }()
	var snap *images.Snapshot
	for {
		var err error
		if snap, err = c.store.GetSnapshot(id); err != nil {
			return "", err
		}
		if snap.Publishing == "" || snap.Holder != "" {
			break
		}
		select {
		case <-ctx.Done():
			return "", rpcutil.Err(rpcutil.Unavailable, "snapshot %s: still being published by edge %s", id, snap.Publishing)
		case <-time.After(100 * time.Millisecond):
		}
	}
	get := func() error { return c.pull(storeDir, p) }
	switch {
	case snap.Holder != "":
		if peer == nil {
			return "", rpcutil.Err(rpcutil.Unavailable, "snapshot %s is held by edge %s, which this request does not name", id, snap.Holder)
		}
		get = func() error { return c.fetch(id, p, peer) }
	case sameFS(storeDir, c.dir):
		return storeDir, nil
	}
	c.mu.Lock()
	if b := c.pulling[id]; b != nil {
		c.mu.Unlock()
		<-b.done
		return p, b.err
	}
	b := &build{done: make(chan struct{})}
	c.pulling[id] = b
	c.mu.Unlock()
	tGet := time.Now()
	b.err = get()
	kind := "pull"
	if snap.Holder != "" {
		kind = "fetch"
	}
	metrics.Transfer(kind, time.Since(tGet))
	c.mu.Lock()
	delete(c.pulling, id)
	c.mu.Unlock()
	close(b.done)
	return p, b.err
}

func (c *snapCache) pull(storeDir, p string) error {
	tmp := p + ".tmp-" + images.NewDiffLayerID()[5:13]
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	for _, f := range vmSnapshotFiles {
		if err := copySparse(filepath.Join(storeDir, f), filepath.Join(tmp, f)); err != nil {
			return rpcutil.Err(rpcutil.Unavailable, "pull snapshot: %v", err)
		}
	}
	return os.Rename(tmp, p)
}

// fetchTimeout bounds fetching one snapshot from a peer: the fetch is shared
// by every copy waiting for it, so it does not follow any one's context.
const fetchTimeout = 5 * time.Minute

// fetch copies the files of snapshot id from the edge holding it into p, in
// parallel. Read-only disks are kept by content id: later snapshots of
// sandboxes on the same disks (every fork of a sandbox) reuse them.
func (c *snapCache) fetch(id, p string, peer backend.SnapshotPeer) error {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	tmp := p + ".tmp-" + images.NewDiffLayerID()[5:13]
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	reuse := func(cid string) string {
		if q := c.diskPath(cid); fileExists(q) {
			return q
		}
		return ""
	}
	errs := make(chan error, len(vmSnapshotFiles))
	for _, f := range vmSnapshotFiles {
		go func() {
			dst := filepath.Join(tmp, f)
			cid, err := peer.FetchFile(ctx, id, f, dst, reuse)
			if err == nil && cid != "" {
				os.Link(dst, c.diskPath(cid)) // kept already if reused
			}
			errs <- err
		}()
	}
	var first error
	for range vmSnapshotFiles {
		if err := <-errs; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	if first != nil {
		return rpcutil.Err(rpcutil.Unavailable, "fetch snapshot %s from its edge: %v", id, first)
	}
	return os.Rename(tmp, p)
}

func (c *snapCache) diskPath(contentID string) string {
	return filepath.Join(c.disks, "peer-"+contentID+".ext4")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// publish copies a snapshot taken on this node into the store and clears
// its Publishing mark; it gives up if the snapshot is deleted meanwhile.
func (c *snapCache) publish(snap *images.Snapshot, log *slog.Logger) {
	t0 := time.Now()
	src := filepath.Join(c.dir, snap.ID)
	dst := filepath.Join(c.store.Root, "snapshots", snap.ID)
	// deleted reports whether the snapshot was deleted (a fork's, once its
	// copies run), removing what the copy left: a deletion racing a copy
	// into its directory leaves that directory behind.
	deleted := func() bool {
		if _, err := c.store.GetSnapshot(snap.ID); rpcutil.Reason(err) != rpcutil.NotFound {
			return false
		}
		os.RemoveAll(dst)
		return true
	}
	for _, f := range vmSnapshotFiles {
		if deleted() {
			return
		}
		tmp := filepath.Join(dst, f+".tmp-publish")
		err := copySparse(filepath.Join(src, f), tmp)
		if err == nil {
			err = os.Rename(tmp, filepath.Join(dst, f))
		}
		if err != nil {
			os.Remove(tmp)
			if !deleted() {
				log.Warn("publish snapshot", "snapshot", snap.ID, "file", f, "err", err)
			}
			return
		}
	}
	if deleted() {
		return
	}
	done := *snap
	done.Publishing = ""
	if err := c.store.PutSnapshot(&done); err != nil {
		log.Warn("publish snapshot", "snapshot", snap.ID, "err", err)
		return
	}
	log.Debug("snapshot published", "snapshot", snap.ID, "took", time.Since(t0))
	metrics.Transfer("publish", time.Since(t0))
}

// resumePublishing publishes what an earlier process of this edge left
// unpublished.
func (c *snapCache) resumePublishing(edge string, log *slog.Logger) {
	for _, id := range c.cached() {
		if snap, err := c.store.GetSnapshot(id); err == nil && snap.Publishing == edge {
			go c.publish(snap, log)
		}
	}
}

// cached lists the snapshots held on the node.
func (c *snapCache) cached() []string {
	ents, _ := os.ReadDir(c.dir)
	var out []string
	for _, e := range ents {
		if e.IsDir() && images.ValidSnapshotID(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// gc removes copies of snapshots no longer in the store, and leftovers of
// interrupted pulls.
func (c *snapCache) gc() {
	ents, _ := os.ReadDir(c.dir)
	for _, e := range ents {
		name := e.Name()
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if !images.ValidSnapshotID(name) {
			if time.Since(fi.ModTime()) > time.Hour {
				os.RemoveAll(filepath.Join(c.dir, name))
			}
			continue
		}
		// A snapshot taken here enters the cache before its record enters
		// the store (Snapshot renames it in, then PutSnapshot): a young one
		// missing from the store may be on its way, and removing it fails
		// the forks starting from it (spec §33.2).
		if time.Since(fi.ModTime()) < snapGCGrace {
			continue
		}
		if _, err := c.store.GetSnapshot(name); rpcutil.Reason(err) == rpcutil.NotFound {
			os.RemoveAll(filepath.Join(c.dir, name))
		}
	}
}

// snapGCGrace: cached snapshots younger than this are kept even when the
// store does not (yet) know them.
const snapGCGrace = 10 * time.Minute

func sameFS(a, b string) bool {
	var sa, sb syscall.Stat_t
	return syscall.Stat(a, &sa) == nil && syscall.Stat(b, &sb) == nil && sa.Dev == sb.Dev
}

func (b *Backend) CachedSnapshots() []string {
	if b.snaps == nil {
		return nil
	}
	return b.snaps.cached()
}
