package images

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPublishExpandsOpaque (root; spec §29.5): an upper dir's opaque
// directory, as the kernel marks it when a sandbox deletes and recreates a
// directory, becomes whiteouts over the layers beneath, nested directories
// included; the merged view is the same without any xattr.
func TestPublishExpandsOpaque(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("whiteouts, trusted xattrs and overlay mounts need root")
	}
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lower := t.TempDir()
	for _, p := range []string{"app/a", "app/b", "app/sub/x", "keep/y"} {
		os.MkdirAll(filepath.Join(lower, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(lower, p), []byte(p), 0o644)
	}
	upper := t.TempDir()
	os.MkdirAll(filepath.Join(upper, "app/sub"), 0o755)
	os.WriteFile(filepath.Join(upper, "app/c"), []byte("c"), 0o644)
	if err := unix.Lsetxattr(filepath.Join(upper, "app"), opaqueXattr, []byte("y"), 0); err != nil {
		t.Skipf("no trusted xattrs here: %v", err)
	}
	id := NewDiffLayerID()
	if _, err := st.PublishLayerDir(id, upper, []string{lower}, nil, LayerMeta{}); err != nil {
		t.Fatal(err)
	}
	root := st.LayerRootfs(id)
	if isOpaque(filepath.Join(root, "app")) {
		t.Fatal("the opaque xattr is still set")
	}
	mnt := t.TempDir()
	if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+root+":"+lower); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(mnt, unix.MNT_DETACH)
	names := func(rel string) (out []string) {
		ents, _ := os.ReadDir(filepath.Join(mnt, rel))
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return out
	}
	if got := names("app"); !slices.Equal(got, []string{"c", "sub"}) {
		t.Fatalf("app: %v", got)
	}
	if got := names("app/sub"); len(got) != 0 {
		t.Fatalf("app/sub shows the layer beneath: %v", got)
	}
	if got := names("keep"); !slices.Equal(got, []string{"y"}) {
		t.Fatalf("keep: %v", got)
	}
}

// TestCheckStore: a local filesystem passes every required check, and the
// scratch directory goes.
func TestCheckStore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown, whiteouts, overlay)")
	}
	dir := t.TempDir()
	for _, c := range CheckStore(dir) {
		if c.Required && c.Err != nil {
			t.Errorf("%s: %v", c.Name, c.Err)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("left behind: %v", ents)
	}
}
