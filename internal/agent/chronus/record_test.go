package chronus

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
)

// Output that cannot be written to its record (the sandbox's disk is
// full) is reported as dropped, not lost silently.
func TestRecorderDiskFull(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	pipe := filepath.Join(t.TempDir(), "p")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	var total atomic.Int64
	r := startRecorder(pipe, "/dev/full", 1<<20, &total, nil)
	w, err := os.OpenFile(pipe, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(make([]byte, 1000))
	w.Close()
	<-r.done
	if r.dropped.Load() != 1000 || total.Load() != 0 {
		t.Fatalf("dropped %d, recorded %d", r.dropped.Load(), total.Load())
	}
}

// A numeric user's home under /tmp is never a link someone planted, nor
// another user's directory.
func TestNumericHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown)")
	}
	tmp := t.TempDir()
	if h := numericHome(tmp, 4242, 4242); h != filepath.Join(tmp, "home-4242") {
		t.Fatalf("new home: %s", h)
	}
	if h := numericHome(tmp, 4242, 4242); h != filepath.Join(tmp, "home-4242") {
		t.Fatalf("its own home again: %s", h)
	}
	target := t.TempDir()
	os.Symlink(target, filepath.Join(tmp, "home-4243"))
	if h := numericHome(tmp, 4243, 4243); h != "/" {
		t.Fatalf("a link at the name: %s", h)
	}
	if fi, _ := os.Stat(target); fi.Sys().(*syscall.Stat_t).Uid == 4243 {
		t.Fatal("the link's target was chowned")
	}
	os.Mkdir(filepath.Join(tmp, "home-4244"), 0o777) // root's here: someone else's
	if h := numericHome(tmp, 4244, 4244); h != "/" {
		t.Fatalf("another user's directory: %s", h)
	}
}
