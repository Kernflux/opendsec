package images

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMergeLayers: layers squashed by MergeLayers, over the same base, give
// the same overlay view as the layers themselves.
func TestMergeLayers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (whiteouts, trusted xattrs, overlay mounts)")
	}
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	layer := func(name string, build func(root string)) string {
		id := "diff-" + strings.Repeat(name, 16)[:16]
		w, _, err := st.BeginLayer(id)
		if err != nil {
			t.Fatal(err)
		}
		build(w.Rootfs)
		if _, err := w.Commit(LayerMeta{Source: "test"}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	write := func(root, p, data string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	whiteout := func(root, p string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		if err := unix.Mknod(filepath.Join(root, p), unix.S_IFCHR, 0); err != nil {
			t.Fatal(err)
		}
	}
	opaque := func(root, p string) {
		os.MkdirAll(filepath.Join(root, p), 0o755)
		if err := unix.Lsetxattr(filepath.Join(root, p), "trusted.overlay.opaque", []byte("y"), 0); err != nil {
			t.Fatal(err)
		}
	}
	base := layer("a", func(r string) {
		write(r, "etc/keep", "base")
		write(r, "etc/gone", "base")
		write(r, "opq/old", "base")
		write(r, "dir2file/x", "base")
		write(r, "file2dir", "base")
		write(r, "later/gone", "base")
	})
	l1 := layer("b", func(r string) {
		write(r, "etc/keep", "l1")
		whiteout(r, "etc/gone")
		opaque(r, "opq")
		write(r, "opq/new", "l1")
		write(r, "tmp/made", "l1")
		whiteout(r, "dir2file")
	})
	l2 := layer("c", func(r string) {
		write(r, "dir2file", "l2")
		write(r, "file2dir/y", "l2")
		whiteout(r, "tmp/made") // made above, deleted again
		write(r, "opq/l2", "l2")
	})
	l3 := layer("d", func(r string) {
		opaque(r, "tmp")
		write(r, "tmp/fresh", "l3")
		whiteout(r, "later/gone")
		write(r, "etc/gone", "back")
	})
	merged, err := st.MergeLayers("diff-eeeeeeeeeeeeeeee", []string{l1, l2, l3}, LayerMeta{Source: "merge"})
	if err != nil {
		t.Fatal(err)
	}
	view := func(layers ...string) []string {
		lower, err := st.Lowerdirs(&Manifest{Name: "t", Layers: layers})
		if err != nil {
			t.Fatal(err)
		}
		mnt := t.TempDir()
		if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+strings.Join(lower, ":")); err != nil {
			t.Skipf("overlay: %v", err)
		}
		defer unix.Unmount(mnt, unix.MNT_DETACH)
		var out []string
		filepath.WalkDir(mnt, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(mnt, p)
			if d.IsDir() {
				out = append(out, rel+"/")
			} else {
				b, _ := os.ReadFile(p)
				out = append(out, rel+"="+string(b))
			}
			return nil
		})
		slices.Sort(out)
		return out
	}
	want, got := view(base, l1, l2, l3), view(base, merged.ID)
	if !slices.Equal(want, got) {
		t.Fatalf("merged view:\n%v\nwant:\n%v", got, want)
	}
	if !slices.Contains(want, "opq/new=l1") || slices.Contains(want, "opq/old=base") || !slices.Contains(want, "etc/gone=back") {
		t.Fatalf("unexpected stacked view: %v", want)
	}
}
