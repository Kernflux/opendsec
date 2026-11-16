package microvm

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Files of a jail are the VM process's to replace: the edge never follows
// a link at one of their names, reading or writing.
func TestJailFiles(t *testing.T) {
	jail, host := t.TempDir(), t.TempDir()
	victim := filepath.Join(host, "victim")
	os.WriteFile(victim, []byte("host data"), 0o600)
	unchanged := func(what string) {
		t.Helper()
		if b, _ := os.ReadFile(victim); string(b) != "host data" {
			t.Fatalf("%s: the host's file is now %q", what, b)
		}
	}
	real := filepath.Join(jail, "real")
	os.WriteFile(real, []byte("vm data"), 0o644)
	link := filepath.Join(jail, "link")
	os.Symlink(victim, link)
	fifo := filepath.Join(jail, "fifo")
	syscall.Mkfifo(fifo, 0o600)

	for _, p := range []string{link, fifo, jail} {
		if f, err := openRegular(p, os.O_RDONLY); err == nil {
			f.Close()
			t.Errorf("opened %s", p)
		}
	}
	if f, err := openRegular(real, os.O_RDONLY); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}

	// Reading: a link is not copied, linked or moved into a snapshot.
	out := filepath.Join(host, "out")
	if err := copySparse(link, out); err == nil {
		t.Error("copied through a link")
	}
	if err := linkRegular(link, out); err == nil {
		t.Error("linked a link")
	}
	if err := moveFile(link, out); err == nil {
		t.Error("moved a link")
	}
	if _, err := os.Lstat(out); err == nil {
		t.Error("something was made of a link")
	}
	if _, err := mergeDiff(real, link); err == nil {
		t.Error("merged from a link")
	}

	// Writing: a link at the destination is replaced, not written through.
	dst := filepath.Join(jail, "dst")
	os.Symlink(victim, dst)
	if err := copySparseOwned(real, dst, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	unchanged("copy onto a link")
	if b, _ := os.ReadFile(dst); string(b) != "vm data" {
		t.Fatalf("copy: %q", b)
	}
	if fi, _ := os.Lstat(dst); !fi.Mode().IsRegular() {
		t.Fatal("the copy is not a regular file")
	}
	if _, err := mergeDiff(link, real); err == nil {
		t.Error("merged into a link")
	}
	unchanged("merge into a link")
	dropCache(link)
	digHolesNow(link)
	unchanged("cache drop and hole punching")

	// And the ordinary cases still work.
	if err := linkRegular(real, filepath.Join(jail, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := moveFile(filepath.Join(jail, "hard"), out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "vm data" {
		t.Fatalf("moved: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(jail, "hard")); err == nil {
		t.Error("the moved file is still there")
	}
}
