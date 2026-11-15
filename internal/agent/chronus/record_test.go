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
