package container

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/images"
)

// TestLayerCacheCopy: a cached layer is a faithful copy (owners, modes,
// hard links, symlinks, whiteouts), made once, and GC keeps what sandboxes
// use.
func TestLayerCacheCopy(t *testing.T) {
	st, err := images.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := images.NewDiffLayerID()
	w, _, err := st.BeginLayer(id)
	if err != nil {
		t.Fatal(err)
	}
	r := w.Rootfs
	os.MkdirAll(filepath.Join(r, "etc/app"), 0o750)
	os.WriteFile(filepath.Join(r, "etc/app/conf"), []byte("x=1\n"), 0o640)
	os.Chown(filepath.Join(r, "etc/app/conf"), 1234, 5678)
	os.Link(filepath.Join(r, "etc/app/conf"), filepath.Join(r, "etc/app/conf.link"))
	os.Symlink("app/conf", filepath.Join(r, "etc/conf"))
	os.WriteFile(filepath.Join(r, "etc/suid"), []byte("#!/bin/sh\n"), 0o755)
	os.Chown(filepath.Join(r, "etc/suid"), 0, 42)
	os.Chmod(filepath.Join(r, "etc/suid"), 0o755|os.ModeSetuid)
	if err := unix.Mknod(filepath.Join(r, "etc/gone"), unix.S_IFCHR, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(images.LayerMeta{}); err != nil {
		t.Fatal(err)
	}

	edgeDir := t.TempDir()
	c, err := newLayerCache(filepath.Join(edgeDir, "layers"), st)
	if err != nil {
		t.Fatal(err)
	}
	lower, err := c.lowerdirs([]string{id})
	if err != nil {
		t.Fatal(err)
	}
	p := lower[0]
	if p != c.path(id) || strings.HasPrefix(p, st.LayerRootfs(id)) {
		t.Fatalf("lowerdir %s is not the local copy", p)
	}
	var a, b unix.Stat_t
	if err := unix.Lstat(filepath.Join(p, "etc/app/conf"), &a); err != nil {
		t.Fatal(err)
	}
	unix.Lstat(filepath.Join(p, "etc/app/conf.link"), &b)
	if a.Uid != 1234 || a.Gid != 5678 || a.Mode&0o777 != 0o640 || a.Ino != b.Ino {
		t.Fatalf("conf: uid %d gid %d mode %o, link inode %d vs %d", a.Uid, a.Gid, a.Mode&0o777, b.Ino, a.Ino)
	}
	if l, _ := os.Readlink(filepath.Join(p, "etc/conf")); l != "app/conf" {
		t.Fatalf("symlink -> %q", l)
	}
	var su unix.Stat_t
	unix.Lstat(filepath.Join(p, "etc/suid"), &su)
	if su.Mode&0o7777 != 0o4755 || su.Gid != 42 {
		t.Fatalf("setuid file: mode %o gid %d", su.Mode&0o7777, su.Gid)
	}
	var wh unix.Stat_t
	unix.Lstat(filepath.Join(p, "etc/gone"), &wh)
	if wh.Mode&syscall.S_IFMT != syscall.S_IFCHR || wh.Rdev != 0 {
		t.Fatalf("whiteout lost: mode %o rdev %d", wh.Mode, wh.Rdev)
	}
	if fi, _ := os.Stat(filepath.Join(p, "etc/app")); fi.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode %v", fi.Mode())
	}
	// Second use: no copy (a marker written into the copy survives).
	os.WriteFile(filepath.Join(p, "marker"), nil, 0o644)
	if _, err := c.get(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p, "marker")); err != nil {
		t.Fatal("layer copied again")
	}

	// GC: kept while a sandbox's image.json names it, then removed.
	sbDir := filepath.Join(edgeDir, "fncall", "sb", "lease1")
	os.MkdirAll(sbDir, 0o700)
	linuxrt.WriteJSON(filepath.Join(sbDir, "image.json"), imageState{Layers: []string{id}})
	if got := c.gc(edgeDir, 0); len(got) != 0 {
		t.Fatalf("gc removed %v while in use", got)
	}
	if got := c.gc(edgeDir, time.Hour); len(got) != 0 {
		t.Fatalf("gc removed recently used %v", got)
	}
	os.RemoveAll(sbDir)
	if got := c.gc(edgeDir, 0); len(got) != 1 || got[0] != id {
		t.Fatalf("gc removed %v, want %s", got, id)
	}
}

// TestLayerCacheSandbox: a sandbox started from a store snapshot mounts
// local copies of the store layers, not the store's.
func TestLayerCacheSandbox(t *testing.T) {
	st, err := images.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newBackendWith(t, func(o *Options) { o.Store, o.LayerCache = st, true })
	src := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	if r := sh(t, f, src, `echo cached > /root/layer-file`); r.ExitCode != 0 {
		t.Fatalf("%q", r.Stderr)
	}
	snap, err := f.b.Snapshot(context.Background(), src, images.NewSnapshotID(), false)
	if err != nil {
		t.Fatal(err)
	}
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}, Snapshot: snap.ID})
	if got := out(sh(t, f, sb, `cat /root/layer-file`)); got != "cached" {
		t.Fatalf("file from the snapshot layer: %q", got)
	}
	s, _ := f.b.get(sb.ID)
	mi, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(s.pid), "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range snap.Layers {
		if !strings.Contains(string(mi), f.b.layers.path(l)) {
			t.Fatalf("layer %s is not mounted from the cache:\n%s", l, mi)
		}
		if strings.Contains(string(mi), st.LayerRootfs(l)) {
			t.Fatalf("layer %s is mounted from the store", l)
		}
	}
}

// TestCopyTreeReal copies the directory OPENDSEC_TEST_LAYER_SRC (e.g. a
// layer of the NFS image store; only read) and compares every entry:
// type, owner, mode, size, mtime, link target, device and content.
func TestCopyTreeReal(t *testing.T) {
	src := os.Getenv("OPENDSEC_TEST_LAYER_SRC")
	if src == "" {
		t.Skip("set OPENDSEC_TEST_LAYER_SRC to a directory to copy")
	}
	dst := t.TempDir()
	start := time.Now()
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		var a, b unix.Stat_t
		if err := unix.Lstat(p, &a); err != nil {
			return err
		}
		if err := unix.Lstat(filepath.Join(dst, rel), &b); err != nil {
			return err
		}
		if a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid || a.Rdev != b.Rdev ||
			(a.Mode&unix.S_IFMT != unix.S_IFDIR && a.Size != b.Size) || a.Mtim != b.Mtim {
			t.Errorf("%s: mode %o/%o uid %d/%d gid %d/%d rdev %d/%d size %d/%d mtime %v/%v", rel,
				a.Mode, b.Mode, a.Uid, b.Uid, a.Gid, b.Gid, a.Rdev, b.Rdev, a.Size, b.Size, a.Mtim, b.Mtim)
		}
		switch a.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			x, _ := os.Readlink(p)
			y, _ := os.Readlink(filepath.Join(dst, rel))
			if x != y {
				t.Errorf("%s: link %q vs %q", rel, x, y)
			}
		case unix.S_IFREG:
			x, _ := os.ReadFile(p)
			y, _ := os.ReadFile(filepath.Join(dst, rel))
			if !bytes.Equal(x, y) {
				t.Errorf("%s: content differs", rel)
			}
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d entries copied in %v", n, time.Since(start).Round(time.Millisecond))
}
