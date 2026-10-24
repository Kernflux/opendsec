package microvm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// mergePause folds the dirty pages of a diff pause snapshot (pauseDiff)
// into the sandbox's Base, giving pauseMem: in place when the sandbox owns
// Base, else into a copy of it (sharing its blocks where the filesystem
// reflinks). It returns the bytes merged.
func (s *sandbox) mergePause() (int64, error) {
	diff := filepath.Join(s.root, pauseDiff)
	dst := filepath.Join(s.root, pauseMem)
	if s.st.Base == zeroBase {
		// The diff of a cold-booted VM is all of its memory (sparse).
		n := allocatedFile(diff)
		if err := os.Rename(diff, dst); err != nil {
			return 0, err
		}
		s.st.Base, s.st.BaseOwned = pauseMem, true
		return n, nil
	}
	if !s.st.BaseOwned || s.st.Base != pauseMem {
		tmp := dst + ".tmp"
		os.Remove(tmp)
		if err := copySparse(filepath.Join(s.root, s.st.Base), tmp); err != nil {
			return 0, err
		}
		if err := os.Chown(tmp, s.uid, s.uid); err != nil {
			os.Remove(tmp)
			return 0, err
		}
		// Replaces a pauseMem this sandbox shares (with a snapshot of it)
		// by its own: the VM and the snapshot keep the shared one.
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return 0, err
		}
		if s.st.Base != pauseMem {
			os.Remove(filepath.Join(s.root, s.st.Base))
		}
		s.st.Base, s.st.BaseOwned = pauseMem, true
	}
	n, err := mergeDiff(dst, diff)
	if err != nil {
		return 0, err
	}
	os.Remove(diff)
	return n, nil
}

// mergeDiff writes the data ranges of the sparse file diff (a Firecracker
// diff memory file: the dirty pages at their offsets) over dst.
func mergeDiff(dst, diff string) (int64, error) {
	in, err := os.Open(diff)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	fi, err := in.Stat()
	if err != nil {
		return 0, err
	}
	if ofi, err := out.Stat(); err != nil || ofi.Size() != fi.Size() {
		return 0, fmt.Errorf("diff of %d bytes for a base of %d", fi.Size(), ofi.Size())
	}
	var n int64
	for off := int64(0); off < fi.Size(); {
		data, err := unix.Seek(int(in.Fd()), off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // only a hole left
		}
		if err != nil {
			return n, err
		}
		hole, err := unix.Seek(int(in.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			return n, err
		}
		for roff, woff := data, data; roff < hole; {
			c, err := unix.CopyFileRange(int(in.Fd()), &roff, int(out.Fd()), &woff, int(hole-roff), 0)
			if err != nil {
				return n, err
			}
			if c == 0 {
				return n, fmt.Errorf("short copy at %d", roff)
			}
			n += int64(c)
		}
		off = hole
	}
	return n, out.Sync()
}

// allocatedFile is the disk space a file uses.
func allocatedFile(p string) int64 {
	var st unix.Stat_t
	if unix.Stat(p, &st) != nil {
		return 0
	}
	return st.Blocks * 512
}
