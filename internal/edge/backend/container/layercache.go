package container

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/images"
)

// layerCache keeps node-local copies of store layers, which containers
// mount as their lowerdirs instead of the store's (spec §33.1): running
// containers then read nothing from the image store, so an outage of the
// store (a NAS) does not stall them, and cold reads hit local disk. Layers
// are immutable, so a copy is keyed by the layer id alone; every container
// backend of an edge (container, fncall) shares the edge's cache.
type layerCache struct {
	dir   string // <state_dir>/<edge>/layers
	store *images.Store

	mu       sync.Mutex
	building map[string]*layerCopy
}

type layerCopy struct {
	done chan struct{}
	err  error
}

// layerCopyTimeout: a temporary copy older than this was cut short (an
// edge crash) and is removed.
const layerCopyTimeout = 30 * time.Minute

// layerCacheTTL: a cached layer no sandbox uses is removed after this long
// without use.
const layerCacheTTL = 6 * time.Hour

func newLayerCache(dir string, store *images.Store) (*layerCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &layerCache{dir: dir, store: store, building: map[string]*layerCopy{}}, nil
}

func (c *layerCache) path(id string) string { return filepath.Join(c.dir, id) }

// lowerdirs is the local copies of layers (bottom first) as overlay
// lowerdirs, topmost first; it copies the missing ones, in parallel.
func (c *layerCache) lowerdirs(layers []string) ([]string, error) {
	out := make([]string, len(layers))
	errs := make([]error, len(layers))
	var wg sync.WaitGroup
	for i, id := range layers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[len(layers)-1-i], errs[i] = c.get(id)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("cache layer %s: %w", layers[i], err)
		}
	}
	return out, nil
}

// get returns the local copy of layer id, copying it on first use.
// Concurrent requests for one layer share the copy.
func (c *layerCache) get(id string) (string, error) {
	p := c.path(id)
	if _, err := os.Stat(p); err == nil {
		now := time.Now() // last use, for GC
		os.Chtimes(p, now, now)
		return p, nil
	}
	c.mu.Lock()
	if b := c.building[id]; b != nil {
		c.mu.Unlock()
		<-b.done
		return p, b.err
	}
	b := &layerCopy{done: make(chan struct{})}
	c.building[id] = b
	c.mu.Unlock()
	b.err = c.copy(id, p)
	c.mu.Lock()
	delete(c.building, id)
	c.mu.Unlock()
	close(b.done)
	return p, b.err
}

// copy copies the store's layer id to p (via a temporary directory, so a
// copy cut short is never used).
func (c *layerCache) copy(id, p string) error {
	src := c.store.LayerRootfs(id)
	if _, err := os.Stat(src); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(c.dir, id+".tmp-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(src, tmp); err != nil {
		return err
	}
	// The root got the layer root's times; now is this copy's last use,
	// for GC.
	now := time.Now()
	os.Chtimes(tmp, now, now)
	if err := os.Rename(tmp, p); err != nil {
		if _, serr := os.Stat(p); serr == nil {
			return nil // another edge process got there first (layers are immutable)
		}
		return err
	}
	return nil
}

// copyTree copies the directory tree src into the existing directory dst:
// contents, owners, modes (with setuid and sticky bits), times, hard links,
// symlinks, whiteouts and other device nodes. Not ACLs or xattrs: the
// store is NFS, whose NFSv4 ACLs a local file system refuses (cp -a fails
// there), and store layers carry no xattrs that overlay needs (opaque
// directories are expanded, spec §29.5).
func copyTree(src, dst string) error {
	links := map[[2]uint64]string{} // (dev, inode) -> first copy, for hard links
	var dirs []string               // copied directories, parents first
	err := filepath.WalkDir(src, func(sp string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, sp)
		dp := filepath.Join(dst, rel)
		var st unix.Stat_t
		if err := unix.Lstat(sp, &st); err != nil {
			return err
		}
		mode := st.Mode & unix.S_IFMT
		if mode != unix.S_IFDIR && st.Nlink > 1 {
			key := [2]uint64{uint64(st.Dev), st.Ino}
			if first, ok := links[key]; ok {
				return os.Link(first, dp)
			}
			links[key] = dp
		}
		switch mode {
		case unix.S_IFDIR:
			if rel != "." {
				if err := os.Mkdir(dp, 0o700); err != nil {
					return err
				}
			}
			dirs = append(dirs, rel)
			return nil // owner, mode and times once its contents are in
		case unix.S_IFREG:
			if err := copyFile(sp, dp); err != nil {
				return err
			}
		case unix.S_IFLNK:
			target, err := os.Readlink(sp)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dp); err != nil {
				return err
			}
		case unix.S_IFCHR, unix.S_IFBLK, unix.S_IFIFO, unix.S_IFSOCK:
			if err := unix.Mknod(dp, st.Mode, int(st.Rdev)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unsupported file type %o", sp, mode)
		}
		return setMeta(dp, &st)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- { // children first: setting times on a parent last
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(src, dirs[i]), &st); err != nil {
			return err
		}
		if err := setMeta(filepath.Join(dst, dirs[i]), &st); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil { // copy_file_range where it can
		out.Close()
		return err
	}
	return out.Close()
}

// setMeta gives p the owner, mode and times of st (chown first: it clears
// setuid and setgid bits).
func setMeta(p string, st *unix.Stat_t) error {
	if err := unix.Lchown(p, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		if err := unix.Chmod(p, st.Mode&0o7777); err != nil {
			return err
		}
	}
	ts := []unix.Timespec{st.Atim, st.Mtim}
	return unix.UtimesNanoAt(unix.AT_FDCWD, p, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// gc removes cached layers no sandbox of the edge runs on and unused for
// ttl; it returns their ids. edgeDir is <state_dir>/<edge>: the sandboxes
// of every container backend of the edge are found through their
// image.json, so one backend never removes another's layers.
func (c *layerCache) gc(edgeDir string, ttl time.Duration) []string {
	used := map[string]bool{}
	states, _ := filepath.Glob(filepath.Join(edgeDir, "sb", "*", "image.json"))
	more, _ := filepath.Glob(filepath.Join(edgeDir, "*", "sb", "*", "image.json"))
	for _, f := range append(states, more...) {
		var img imageState
		if linuxrt.ReadJSON(f, &img) == nil {
			for _, l := range img.Layers {
				used[l] = true
			}
		}
	}
	ents, _ := os.ReadDir(c.dir)
	var out []string
	for _, e := range ents {
		name := e.Name()
		if strings.Contains(name, ".tmp-") {
			// A copy cut short by a crash: old enough not to be in progress.
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > layerCopyTimeout {
				os.RemoveAll(filepath.Join(c.dir, name))
			}
			continue
		}
		if used[name] {
			continue
		}
		fi, err := e.Info()
		if err != nil || time.Since(fi.ModTime()) < ttl {
			continue
		}
		if os.RemoveAll(filepath.Join(c.dir, name)) == nil {
			out = append(out, name)
		}
	}
	return out
}
