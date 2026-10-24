package microvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/agent/aether"
	"github.com/kernflux/opendsec/internal/images"
)

// ImageCache holds images flattened into read-only disks, one per distinct
// layer stack, shared by every microVM on the node (spec §19.3). Layers are
// immutable, so the stack's lowerdirs identify the content. Disks are ext4,
// or with Erofs EROFS (spec §29.4): for layers in Store, built once in the
// store and copied here.
type ImageCache struct {
	dir   string
	Store *images.Store
	Erofs bool

	mu       sync.Mutex
	building map[string]*build
}

type build struct {
	done chan struct{}
	err  error
}

// imageDiskFormat and imageErofsFormat version how images are flattened
// (part of the cache key).
const (
	imageDiskFormat  = "ext4-4k-2m"
	imageErofsFormat = "erofs-4k-2m-1"
)

// vmDiskBuildTimeout bounds building (or waiting for another edge to build)
// an image's disk in the store.
const vmDiskBuildTimeout = 30 * time.Minute

// NewImageCache keeps flattened images in dir.
func NewImageCache(dir string) *ImageCache {
	return &ImageCache{dir: dir, building: map[string]*build{}}
}

// GC removes image disks (flattened here, or fetched from peers with their
// snapshots) no VM or snapshot links (each VM hard-links its image disk,
// spec §19.10) and unused for ttl; it returns their paths.
func (c *ImageCache) GC(ttl time.Duration) []string {
	var ents []string
	for _, pat := range []string{"img-*.ext4", "img-*.erofs", "peer-*.ext4"} {
		m, _ := filepath.Glob(filepath.Join(c.dir, pat))
		ents = append(ents, m...)
	}
	var out []string
	for _, p := range ents {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil || st.Nlink > 1 || time.Since(time.Unix(st.Mtim.Unix())) < ttl {
			continue
		}
		if os.Remove(p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// Get returns the read-only disk for lower (overlay lowerdirs, topmost
// first), flattening it on first use.
func (c *ImageCache) Get(lower []string) (string, error) { return c.get(lower) }

// get returns the disk for lower (overlay lowerdirs, topmost first),
// making it on first use. Concurrent requests share one build.
func (c *ImageCache) get(lower []string) (string, error) {
	format, ext, mk := imageDiskFormat, ".ext4", c.flatten
	if c.Erofs {
		format, ext, mk = imageErofsFormat, ".erofs", c.erofs
	}
	h := sha256.Sum256([]byte(format + "\n" + strings.Join(lower, "\n")))
	p := filepath.Join(c.dir, "img-"+hex.EncodeToString(h[:16])+ext)
	if _, err := os.Stat(p); err == nil {
		now := time.Now() // last use, for GC
		os.Chtimes(p, now, now)
		return p, nil
	}
	c.mu.Lock()
	if b := c.building[p]; b != nil {
		c.mu.Unlock()
		<-b.done
		return p, b.err
	}
	b := &build{done: make(chan struct{})}
	c.building[p] = b
	c.mu.Unlock()
	tmp := p + ".tmp-" + images.NewDiffLayerID()[5:13]
	b.err = mk(tmp, lower)
	if b.err == nil {
		b.err = os.Rename(tmp, p)
	}
	os.Remove(tmp)
	c.mu.Lock()
	delete(c.building, p)
	c.mu.Unlock()
	close(b.done)
	return p, b.err
}

// mergedView calls fn with a directory holding the merged view of lower: a
// read-only overlay (whiteouts and opaque directories applied), or the one
// layer itself.
func mergedView(scratch string, lower []string, fn func(dir string) error) error {
	if len(lower) == 1 {
		return fn(lower[0])
	}
	mnt, err := os.MkdirTemp(scratch, "merge-")
	if err != nil {
		return err
	}
	defer os.Remove(mnt)
	if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+strings.Join(lower, ":")); err != nil {
		return fmt.Errorf("mount image layers: %w", err)
	}
	defer unix.Unmount(mnt, unix.MNT_DETACH)
	return fn(mnt)
}

// flatten makes lower's ext4 disk at dst.
func (c *ImageCache) flatten(dst string, lower []string) error {
	return mergedView(c.dir, lower, func(src string) error { return mkfsFrom(dst, src, 0) })
}

// erofs makes lower's EROFS disk at dst: for store layers, a copy of the
// store's disk of the stack, built there first if no edge has yet.
func (c *ImageCache) erofs(dst string, lower []string) error {
	build := func(dst string) error {
		return mergedView(c.dir, lower, func(src string) error { return mkfsErofs(dst, src) })
	}
	if c.Store == nil {
		return build(dst)
	}
	layers, ok := c.Store.LayersOf(lower)
	if !ok {
		return build(dst)
	}
	ctx, cancel := context.WithTimeout(context.Background(), vmDiskBuildTimeout)
	defer cancel()
	src, err := c.Store.VMDisk(ctx, layers, build)
	if err != nil {
		return fmt.Errorf("image disk in the store: %w", err)
	}
	return copyFile(src, dst, 0o644)
}

// mkfsErofs makes an uncompressed EROFS image of the tree src at img, 4 KB
// blocks (DAX on virtio-pmem needs both), its size a multiple of 2 MB (the
// pmem mapping unit, spec §19.13).
func mkfsErofs(img, src string) error {
	if out, err := exec.Command("mkfs.erofs", "--quiet", "-b4096", img, src).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.erofs %s: %v: %s", src, err, out)
	}
	fi, err := os.Stat(img)
	if err != nil {
		return err
	}
	return os.Truncate(img, (fi.Size()+2<<20-1)&^(2<<20-1))
}

// mkfsFrom creates an ext4 image at img holding the tree src. sizeMB 0 sizes
// the image to fit src.
func mkfsFrom(img, src string, sizeMB int64) error {
	inodes := int64(0)
	if sizeMB == 0 {
		var blocks int64
		filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			inodes++
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				blocks += (info.Size() + 4095) / 4096
			}
			return nil
		})
		// Data, a 256-byte inode and a directory block share per entry, plus
		// slack for ext4 metadata.
		bytes := blocks*4096 + inodes*512
		sizeMB = bytes*12/10>>20 + 32
		sizeMB = (sizeMB + 1) &^ 1 // virtio-pmem maps whole 2 MB pages (spec §19.13)
	}
	f, err := os.OpenFile(img, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	err = f.Truncate(sizeMB << 20)
	f.Close()
	if err != nil {
		return err
	}
	// 4 KB blocks (the page size): needed to mount the image with DAX.
	args := []string{"-q", "-F", "-b", "4096", "-O", "^has_journal", "-m", "0", "-E", "lazy_itable_init=1"}
	if inodes > 0 {
		args = append(args, "-N", fmt.Sprint(inodes*12/10+1024))
	}
	args = append(args, "-d", src, img)
	if out, err := exec.Command("mkfs.ext4", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 -d %s: %v: %s", src, err, out)
	}
	return nil
}

// agentDiskLayout versions the agent disk's layout (part of its cache key).
const agentDiskLayout = "layout-2: cfg"

// BuildAgentDisk makes the read-only boot disk: the agents, the VM init
// link and the guest's early mount points.
func BuildAgentDisk(cacheDir, agentDir string) (string, error) {
	h := sha256.New()
	for _, bin := range []string{"opendsec-aether", "opendsec-chronus"} {
		f, err := os.Open(filepath.Join(agentDir, bin))
		if err != nil {
			return "", fmt.Errorf("agent binary: %w", err)
		}
		io.Copy(h, f)
		f.Close()
	}
	h.Write([]byte(agentDiskLayout))
	p := filepath.Join(cacheDir, "agents-"+hex.EncodeToString(h.Sum(nil)[:12])+".ext4")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	stage, err := os.MkdirTemp(cacheDir, "agents-stage-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	for _, bin := range []string{"opendsec-aether", "opendsec-chronus"} {
		if err := copyFile(filepath.Join(agentDir, bin), filepath.Join(stage, bin), 0o755); err != nil {
			return "", err
		}
	}
	if err := os.Symlink("opendsec-aether", filepath.Join(stage, aether.VMInitName)); err != nil {
		return "", err
	}
	for _, d := range []string{"proc", "dev", "lower", "rw", "cfg", "newroot"} {
		os.Mkdir(filepath.Join(stage, d), 0o755)
	}
	tmp := p + ".tmp-" + images.NewDiffLayerID()[5:13]
	defer os.Remove(tmp)
	if err := mkfsFrom(tmp, stage, 0); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// MakeWritableDisk creates the sandbox's sparse writable ext4 disk of
// sizeMB holding the overlay upper/work dirs.
func MakeWritableDisk(img string, sizeMB int64) error {
	stage, err := os.MkdirTemp(filepath.Dir(img), "disk-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, d := range []string{"upper", "work"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o755); err != nil {
			return err
		}
	}
	return mkfsFrom(img, stage, sizeMB)
}

// MakeConfigDisk creates the small drive holding the guest config.
func MakeConfigDisk(img string, cfg []byte) error {
	stage, err := os.MkdirTemp(filepath.Dir(img), "cfg-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.WriteFile(filepath.Join(stage, aether.VMConfigFile), cfg, 0o600); err != nil {
		return err
	}
	return mkfsFrom(img, stage, 4)
}

// copySparse copies a disk image keeping it sparse (sharing blocks where the
// filesystem supports reflinks).
func copySparse(src, dst string) error {
	if out, err := exec.Command("cp", "--sparse=always", "--reflink=auto", "--", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("copy %s: %v: %s", src, err, out)
	}
	return nil
}

// diskID identifies the content of an ext4 or EROFS image by its
// filesystem UUID, random per mkfs: read-only disks are never modified, so
// two files with the same id hold the same bytes ("" if p is neither).
func diskID(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	var sb [0x78]byte // the superblock, at 1024
	if _, err := f.ReadAt(sb[:], 1024); err != nil {
		return ""
	}
	switch {
	case sb[0x38] == 0x53 && sb[0x39] == 0xef: // ext4 magic; s_uuid at 0x68
		return "ext4-" + hex.EncodeToString(sb[0x68:0x78])
	case binary.LittleEndian.Uint32(sb[0:4]) == erofsMagic: // uuid at 0x30
		return "erofs-" + hex.EncodeToString(sb[0x30:0x40])
	}
	return ""
}

// erofsMagic is EROFS_SUPER_MAGIC_V1, at the start of the superblock.
const erofsMagic = 0xE0F5E1E2

// LinkOrCopy hard-links src to dst, copying when they are on different
// filesystems.
func LinkOrCopy(src, dst string) error {
	err := os.Link(src, dst)
	if errors.Is(err, syscall.EXDEV) {
		return copyFile(src, dst, 0o644)
	}
	return err
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
