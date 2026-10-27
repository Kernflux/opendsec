package sandboxfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// inMountNS runs f on a thread of its own in a new, private mount
// namespace (the thread is not reused after).
func inMountNS(t *testing.T, f func() error) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			errc <- err
			return
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			errc <- err
			return
		}
		errc <- f()
	}()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestReadonlySubmounts: a read-only path covers the mounts below it too,
// as /dev/shm under /dev.
func TestReadonlySubmounts(t *testing.T) {
	dir := t.TempDir()
	top, sub := filepath.Join(dir, "dev"), filepath.Join(dir, "dev", "shm")
	inMountNS(t, func() error {
		os.Mkdir(top, 0o755)
		if err := unix.Mount("tmpfs", top, "tmpfs", 0, "size=1m"); err != nil {
			return err
		}
		os.Mkdir(sub, 0o755)
		if err := unix.Mount("tmpfs", sub, "tmpfs", 0, "size=1m"); err != nil {
			return err
		}
		if err := Apply([]string{top}, nil); err != nil {
			return err
		}
		for _, p := range []string{top, sub} {
			if err := os.WriteFile(filepath.Join(p, "f"), []byte("x"), 0o644); !errors.Is(err, syscall.EROFS) {
				return errors.New(p + " is still writable")
			}
		}
		return nil
	})
}
