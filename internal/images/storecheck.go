package images

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// StoreCheck is one capability of a filesystem the image store runs on
// (spec §29.5).
type StoreCheck struct {
	Name     string
	Required bool  // the store does not work without it
	Err      error // nil: works
}

// CheckStore tries, in a scratch directory under root that it removes, what
// the store needs from its filesystem: a shared filesystem (a managed NAS)
// should pass every required check before the store moves onto it. Needs
// root, as the edges that write the store run.
func CheckStore(root string) []StoreCheck {
	var out []StoreCheck
	add := func(name string, required bool, err error) { out = append(out, StoreCheck{name, required, err}) }
	dir, err := os.MkdirTemp(root, ".store-check-")
	if err != nil {
		add("create a directory", true, err)
		return out
	}
	defer os.RemoveAll(dir)
	p := func(name string) string { return filepath.Join(dir, name) }

	add("write, sync and read back a file", true, func() error {
		f, err := os.Create(p("f"))
		if err != nil {
			return err
		}
		if _, err := f.WriteString("data"); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		f.Close()
		if b, err := os.ReadFile(p("f")); err != nil || string(b) != "data" {
			return fmt.Errorf("read back %q: %v", b, err)
		}
		return nil
	}())
	add("files a root process creates are root's (no root squash)", true, func() error {
		var st unix.Stat_t
		if err := unix.Stat(p("f"), &st); err != nil {
			return err
		}
		if st.Uid != 0 {
			return fmt.Errorf("owned by uid %d: the export squashes root", st.Uid)
		}
		return nil
	}())
	add("chown to another user (image files keep their owners)", true, func() error {
		if err := os.Chown(p("f"), 1000, 1000); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Stat(p("f"), &st); err != nil || st.Uid != 1000 {
			return fmt.Errorf("uid after chown %d: %v", st.Uid, err)
		}
		return nil
	}())
	add("exclusive create (one edge builds a VM disk at a time)", true, func() error {
		f, err := os.OpenFile(p("lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.Close()
		if _, err := os.OpenFile(p("lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("a second exclusive create did not fail with EEXIST: %v", err)
		}
		return nil
	}())
	add("rename a file over another (manifests, records)", true, func() error {
		os.WriteFile(p("new"), []byte("new"), 0o644)
		if err := os.Rename(p("new"), p("f")); err != nil {
			return err
		}
		if b, _ := os.ReadFile(p("f")); string(b) != "new" {
			return fmt.Errorf("content after rename %q", b)
		}
		return nil
	}())
	add("rename a directory (layers are published so)", true, func() error {
		os.MkdirAll(p("d.tmp/rootfs"), 0o755)
		return os.Rename(p("d.tmp"), p("d"))
	}())
	add("hard links (snapshots link their disks)", true, func() error {
		if err := os.Link(p("f"), p("f.link")); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Stat(p("f"), &st); err != nil || st.Nlink != 2 {
			return fmt.Errorf("link count %d: %v", st.Nlink, err)
		}
		return nil
	}())
	add("symbolic links", true, os.Symlink("/bin/sh", p("sym")))
	add("0:0 character devices (layer whiteouts)", true, func() error {
		if err := unix.Mknod(p("wh"), unix.S_IFCHR, 0); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(p("wh"), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != 0 {
			return fmt.Errorf("mode %o rdev %d: %v", st.Mode, st.Rdev, err)
		}
		return nil
	}())
	add("overlay over layers kept here, whiteouts honored", true, func() error {
		lower := p("layer")
		os.MkdirAll(filepath.Join(lower, "dir"), 0o755)
		os.WriteFile(filepath.Join(lower, "dir/kept"), nil, 0o644)
		top := p("top")
		os.MkdirAll(filepath.Join(top, "dir"), 0o755)
		if err := unix.Mknod(filepath.Join(top, "dir/kept"), unix.S_IFCHR, 0); err != nil {
			return err
		}
		os.WriteFile(filepath.Join(top, "dir/new"), nil, 0o644)
		mnt, err := os.MkdirTemp("", "store-check-mnt-")
		if err != nil {
			return err
		}
		defer os.Remove(mnt)
		if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+top+":"+lower); err != nil {
			return err
		}
		defer unix.Unmount(mnt, unix.MNT_DETACH)
		ents, err := os.ReadDir(filepath.Join(mnt, "dir"))
		if err != nil || len(ents) != 1 || ents[0].Name() != "new" {
			return fmt.Errorf("merged view %v: %v", ents, err)
		}
		return nil
	}())
	xattr := func(name string) error {
		if err := unix.Lsetxattr(p("d"), name, []byte("y"), 0); err != nil {
			if errors.Is(err, syscall.ENOTSUP) {
				return fmt.Errorf("not supported (fine: opaque directories are stored as whiteouts, spec §29.5)")
			}
			return err
		}
		return nil
	}
	add("trusted.* xattrs", false, xattr("trusted.overlay.opaque"))
	add("user.* xattrs", false, xattr("user.overlay.opaque"))
	return out
}
