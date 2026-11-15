package container

import (
	"os"
	"path/filepath"
	"testing"
)

// The edge reads a sandbox's writable layer only as a real directory of
// the sandbox's disk: a link in its place, or on the way to it, is refused
// rather than followed.
func TestOpenLayer(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "disk/upper/etc"), 0o755)
	os.WriteFile(filepath.Join(root, "disk/upper/etc/f"), []byte("data"), 0o644)
	p, done, err := openLayer(root, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(p, "etc/f")); err != nil || string(b) != "data" {
		t.Fatalf("read through %s: %q %v", p, b, err)
	}
	done()

	elsewhere := t.TempDir()
	os.Rename(filepath.Join(root, "disk/upper"), filepath.Join(root, "disk/kept"))
	os.Symlink(elsewhere, filepath.Join(root, "disk/upper"))
	if _, _, err := openLayer(root, "disk"); err == nil {
		t.Fatal("a link in place of the layer was followed")
	}
	os.Remove(filepath.Join(root, "disk/upper"))
	os.Rename(filepath.Join(root, "disk/kept"), filepath.Join(root, "disk/upper"))
	os.Rename(filepath.Join(root, "disk"), filepath.Join(root, "real"))
	os.Symlink("real", filepath.Join(root, "disk"))
	if _, _, err := openLayer(root, "disk"); err == nil {
		t.Fatal("a link on the way to the layer was followed")
	}
	if _, _, err := openLayer(root, "real"); err != nil {
		t.Fatal(err)
	}
}
