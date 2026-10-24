package images

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// MergeLayers publishes layer id holding layers (bottom first) squashed
// into one. It stays in overlay format: stacked over any layers beneath, it
// gives the same view as the layers it replaces (whiteouts and opaque
// directories are kept, for what lies beneath).
func (s *Store) MergeLayers(id string, layers []string, meta LayerMeta) (*LayerMeta, error) {
	for _, l := range layers {
		if !s.HasLayer(l) {
			return nil, fmt.Errorf("merge: layer %s is missing from the store", l)
		}
	}
	w, exists, err := s.BeginLayer(id)
	if err != nil {
		return nil, err
	}
	if exists {
		return s.LayerMeta(id)
	}
	for _, l := range layers {
		if err := applyLayer(w.Rootfs, s.LayerRootfs(l)); err != nil {
			w.Abort()
			return nil, fmt.Errorf("merge layer %s: %w", l, err)
		}
	}
	return w.Commit(meta)
}

// applyLayer puts layer src over the squashed layers in dst: what src hides
// or replaces is removed first, then src is copied in.
func applyLayer(dst, src string) error {
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		cur, err := os.Lstat(target)
		if err != nil {
			return nil // nothing beneath to hide
		}
		switch {
		case !d.IsDir():
			// Files, links and whiteouts replace whatever is there.
			return os.RemoveAll(target)
		case isOpaque(p):
			// Its old content is hidden: only src's (copied below) remains.
			if err := os.RemoveAll(target); err != nil {
				return err
			}
			return fs.SkipDir
		case !cur.IsDir():
			return os.RemoveAll(target)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if out, err := exec.Command("cp", "-a", "--", src+"/.", dst+"/").CombinedOutput(); err != nil {
		return fmt.Errorf("copy: %v: %s", err, out)
	}
	return nil
}

func isOpaque(dir string) bool {
	var b [1]byte
	n, err := unix.Lgetxattr(dir, "trusted.overlay.opaque", b[:])
	return err == nil && n == 1 && b[0] == 'y'
}
