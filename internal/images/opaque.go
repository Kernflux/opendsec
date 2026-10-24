package images

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Opaque directories without xattrs (spec §29.5). Overlayfs marks a
// directory that hides the same directory of the layers beneath with the
// xattr trusted.overlay.opaque, which NFS (the image store, a managed NAS)
// does not carry: a layer kept there would let the hidden files show
// through. Layers are therefore stored with their opaque directories
// expanded: each gets a whiteout (a 0:0 character device, which NFS keeps)
// for every name the layers beneath show there and it does not hold itself,
// and so does every directory inside it. Such a layer holds the right view
// only over the layers it was expanded against.

const opaqueXattr = "trusted.overlay.opaque"

// isWhiteout reports whether fi is an overlay whiteout.
func isWhiteout(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0
}

// hiddenIn reports whether some parent of rel is not a directory in layer
// (a file or a whiteout there hides everything beneath).
func hiddenIn(layer, rel string) bool {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		fi, err := os.Lstat(filepath.Join(layer, filepath.Join(parts[:i]...)))
		if err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// visibleNames lists the names the layers lower (overlay lowerdirs,
// topmost first) show in directory rel.
func visibleNames(lower []string, rel string) map[string]bool {
	names := map[string]bool{}
	for i := len(lower) - 1; i >= 0; i-- { // bottom first
		if hiddenIn(lower[i], rel) {
			clear(names)
			continue
		}
		dir := filepath.Join(lower[i], rel)
		fi, err := os.Lstat(dir)
		if err != nil {
			continue // not in this layer
		}
		if !fi.IsDir() || isOpaque(dir) { // replaced, whited out, or opaque (a layer kept elsewhere)
			clear(names)
			if !fi.IsDir() {
				continue
			}
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if info, err := e.Info(); err == nil && isWhiteout(info) {
				delete(names, e.Name())
			} else {
				names[e.Name()] = true
			}
		}
	}
	return names
}

// expandOpaque expands the opaque directories dirs (relative to layer
// root), and every directory inside them, against the layers lower
// (lowerdirs, topmost first), and drops their xattrs.
func expandOpaque(root string, dirs []string, lower []string) error {
	var all []string
	for _, d := range dirs {
		filepath.WalkDir(filepath.Join(root, d), func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.IsDir() {
				rel, _ := filepath.Rel(root, p)
				all = append(all, rel)
			}
			return nil
		})
	}
	for _, d := range all {
		dir := filepath.Join(root, d)
		unix.Lremovexattr(dir, opaqueXattr)
		for name := range visibleNames(lower, d) {
			p := filepath.Join(dir, name)
			if _, err := os.Lstat(p); err == nil {
				continue // the layer's own entry hides it already
			}
			if err := unix.Mknod(p, unix.S_IFCHR, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// opaqueDirs lists the directories under root (relative) with the opaque
// xattr: a writable layer's upper dir, made by the kernel.
func opaqueDirs(root string) []string {
	var out []string
	filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.IsDir() && isOpaque(p) {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}
