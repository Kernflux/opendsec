package microvm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// A VM's jail root is writable by the VM's process (Firecracker writes its
// snapshots there), and the edge, as root, reads and writes files in it:
// memory and disk files it merges, copies into snapshots, hands to other
// VMs. A VMM that was broken into must not turn that into root on the
// node: with a link at one of those names, the edge would write through it
// or copy a file of the host into a snapshot. So a file of a jail is
// opened without following a link at its name and must be a regular file,
// and everything after goes by the open file, not by the name again.
// (The jail's own path is the edge's: only the last component can be the
// VM's.)

// openRegular opens the regular file at path; a link, a pipe or a
// directory at the name is refused.
func openRegular(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New("not a regular file")}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// createNew makes a new file at path, replacing what is at the name
// (never written through).
func createNew(path string, mode os.FileMode) (*os.File, error) {
	os.Remove(path)
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

// fdPath names f's open file for another process or call (through /proc).
func fdPath(f *os.File) string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd()) }

// linkOpen makes dst a hard link to the open file f.
func linkOpen(f *os.File, dst string) error {
	return unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.AT_FDCWD, dst, unix.AT_SYMLINK_FOLLOW)
}

// linkRegular makes dst a hard link to the regular file at src (a file of
// a jail), or a copy of it across filesystems.
func linkRegular(src, dst string) error {
	in, err := openRegular(src, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer in.Close()
	err = linkOpen(in, dst)
	if errors.Is(err, syscall.EXDEV) {
		return copyOpen(in, dst, 0o644)
	}
	if err != nil {
		return &os.LinkError{Op: "link", Old: src, New: dst, Err: err}
	}
	return nil
}

// copyOpen copies the open file in to a new file dst.
func copyOpen(in *os.File, dst string, mode os.FileMode) error {
	out, err := createNew(dst, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copySparseOwned copies the regular file src to a new file dst, sparse
// and sharing blocks where the filesystem reflinks, owned by uid (if >=
// 0). Neither name is followed if a link, and the owner is set on the file
// made, not by its name.
func copySparseOwned(src, dst string, uid int) error {
	in, err := openRegular(src, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := createNew(dst, fi.Mode().Perm())
	if err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	defer out.Close()
	if b, err := exec.Command("cp", "--sparse=always", "--reflink=auto", "--", fdPath(in), fdPath(out)).CombinedOutput(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("copy %s: %v: %s", src, err, b)
	}
	if uid >= 0 {
		if err := out.Chown(uid, uid); err != nil {
			os.Remove(dst)
			return err
		}
	}
	return nil
}
