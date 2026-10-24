package microvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func (b *Backend) MemorySnapshots() bool { return true }

// Squeeze inflates the VM's balloon to mb (spec §24; needs
// free_page_reporting, which adds the balloon device). The guest gives up
// its free memory and caches first, and takes the pages back on OOM.
func (b *Backend) Squeeze(ctx context.Context, sb *backend.Sandbox, mb int64) error {
	if !b.opt.FreePageReporting {
		return rpcutil.Err(rpcutil.Unavailable, "microvm %s has no balloon", sb.ID)
	}
	s, err := b.get(sb.ID)
	if err != nil {
		return err
	}
	v := s.vm()
	if v == nil {
		return rpcutil.Err(rpcutil.Unavailable, "microvm %s is paused", sb.ID)
	}
	return v.api.call(ctx, "PATCH", "/balloon", map[string]int64{"amount_mib": mb}, nil)
}

// PauseReleasesMemory: pausing ends the VM process (spec §19.11).
func (b *Backend) PauseReleasesMemory() bool { return true }

// NetworkVM: the sandbox's namespace holds the VM's tap (spec §20).
func (b *Backend) NetworkVM() bool { return true }

// Snapshot records the sandbox, memory included, as snapshot id in the
// image store (spec §19): fork copies and CreateSnapshot images restore it.
// A running VM is paused for the memory snapshot and the copy of its
// writable disk, then resumed; a paused one already is its pause snapshot.
func (b *Backend) Snapshot(ctx context.Context, sb *backend.Sandbox, id string, memory bool) (*images.Snapshot, error) {
	if !memory {
		// A disk-only copy of a live guest would miss its unwritten page cache.
		return nil, rpcutil.Err(rpcutil.Invalid, "microvm snapshots include memory (set memory)")
	}
	return b.snapshot(ctx, sb, id, false)
}

// SnapshotHeld is Snapshot keeping the files in the node's snapshot cache,
// never published: other edges fetch them from this one (spec §26).
func (b *Backend) SnapshotHeld(ctx context.Context, sb *backend.Sandbox, id string) (*images.Snapshot, error) {
	return b.snapshot(ctx, sb, id, true)
}

// SnapshotFile returns the path of file name of a snapshot in the node's
// cache, and its content id for the read-only disks.
func (b *Backend) SnapshotFile(id, name string) (string, string, error) {
	if b.snaps == nil || !images.ValidSnapshotID(id) || !slices.Contains(vmSnapshotFiles, name) {
		return "", "", rpcutil.Err(rpcutil.NotFound, "snapshot file %s/%s", id, name)
	}
	p := filepath.Join(b.snaps.dir, id, name)
	if _, err := os.Stat(p); err != nil {
		return "", "", rpcutil.Err(rpcutil.NotFound, "snapshot file %s/%s", id, name)
	}
	var cid string
	if name == images.VMImageFile || name == images.VMAgentsFile {
		cid = diskID(p)
	}
	return p, cid, nil
}

func (b *Backend) snapshot(ctx context.Context, sb *backend.Sandbox, id string, held bool) (_ *images.Snapshot, err error) {
	if b.opt.Store == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "edge %s has no image store", b.opt.EdgeID)
	}
	s, err := b.get(sb.ID)
	if err != nil {
		return nil, err
	}
	storeDir, err := b.opt.Store.SnapshotDir(id)
	if err != nil {
		return nil, err
	}
	// The files go where this node's copies will use them: the store when
	// it is on the node's filesystem, else the node's snapshot cache, from
	// which they are published to the store in the background (unless held
	// here).
	dir, local := storeDir, b.snaps != nil && (held || !sameFS(storeDir, b.snaps.dir))
	if local {
		dir = filepath.Join(b.snaps.dir, id+".tmp-new")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
			os.RemoveAll(storeDir)
		}
	}()
	ctx = context.WithoutCancel(ctx)
	t0 := time.Now()
	var paused time.Duration
	typ := "Paused" // a paused VM's pause snapshot
	disk := filepath.Join(s.root, images.VMDiskFile)
	if v := s.vm(); v != nil {
		if err := v.api.setState(ctx, "Paused"); err != nil {
			return nil, err
		}
		// Taking the snapshot resets the guest's vsock connections: drop the
		// link first so its end is not taken for a loss, and redial after.
		v.setLink(nil)
		defer func() {
			watch, cerr := b.connect(ctx, s, v, time.Now().Add(startTimeout))
			if cerr != nil {
				b.opt.Log.Warn("microvm: reconnect after snapshot failed", "id", sb.ID, "err", cerr)
				b.onLost(s.id, "aether unreachable after snapshot: "+cerr.Error())
				return
			}
			go b.watch(s, v, v.link(), watch)
		}()
		// With a Base, only the pages dirtied since are written while the VM
		// is paused; the full memory is assembled after it resumes.
		typ = "Full"
		if s.st.Base != "" {
			typ = "Diff"
		}
		tmpState, tmpMem := "/snap-"+id+".vmstate", "/snap-"+id+".mem"
		defer os.Remove(filepath.Join(s.root, tmpState))
		defer os.Remove(filepath.Join(s.root, tmpMem))
		if err := v.api.call(ctx, "PUT", "/snapshot/create", map[string]string{"snapshot_type": typ,
			"snapshot_path": tmpState, "mem_file_path": tmpMem}, nil); err != nil {
			v.api.setState(ctx, "Resumed")
			return nil, fmt.Errorf("snapshot: %w", err)
		}
		// The dirty log is reset: until the snapshot's memory is the new
		// Base, there is none.
		base := s.st.Base
		s.st.Base, s.st.BaseOwned = "", false
		defer func() {
			if perr := s.persist(); perr != nil {
				b.opt.Log.Warn("microvm: persist runtime state", "id", sb.ID, "err", perr)
			}
		}()
		// The disk as of the same instant as the memory.
		err := copySparse(disk, filepath.Join(dir, images.VMDiskFile))
		if rerr := v.api.setState(ctx, "Resumed"); rerr != nil && err == nil {
			err = fmt.Errorf("resume after snapshot: %w", rerr)
		}
		paused = time.Since(t0)
		if err == nil && typ == "Diff" && base != zeroBase {
			err = assemble(filepath.Join(s.root, base), filepath.Join(s.root, tmpMem))
		}
		if err == nil && typ == "Full" {
			// All of memory, zeros included (an untracked VM's snapshots):
			// the store keeps only the data.
			digHolesNow(filepath.Join(s.root, tmpMem))
		}
		if err == nil {
			err = moveFile(filepath.Join(s.root, tmpState), filepath.Join(dir, images.VMStateFile))
		}
		if err == nil {
			// The snapshot's memory is the new Base, shared with its copies.
			os.Remove(filepath.Join(s.root, baseMem))
			// Not for a VM without a dirty page log: its next diff would
			// have nothing to go by.
			if !s.st.Untracked && os.Link(filepath.Join(s.root, tmpMem), filepath.Join(s.root, baseMem)) == nil {
				s.st.Base = baseMem
			}
			if base == pauseMem {
				os.Remove(filepath.Join(s.root, pauseMem)) // stale; the VM keeps its mapping
			}
			err = moveFile(filepath.Join(s.root, tmpMem), filepath.Join(dir, images.VMMemFile))
		}
		if err != nil {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
	} else {
		if err := LinkOrCopy(filepath.Join(s.root, pauseState), filepath.Join(dir, images.VMStateFile)); err != nil {
			return nil, err
		}
		if err := LinkOrCopy(filepath.Join(s.root, pauseMem), filepath.Join(dir, images.VMMemFile)); err != nil {
			return nil, err
		}
		// Now shared with the snapshot's copies: the next pause merges into
		// a copy.
		s.st.BaseOwned = false
		if err := s.persist(); err != nil {
			return nil, err
		}
		if err := copySparse(disk, filepath.Join(dir, images.VMDiskFile)); err != nil {
			return nil, err
		}
	}
	for _, f := range []string{images.VMAgentsFile, images.VMImageFile} {
		if err := LinkOrCopy(filepath.Join(s.root, f), filepath.Join(dir, f)); err != nil {
			return nil, err
		}
	}
	img := s.st.Image
	snap := &images.Snapshot{ID: id, Base: img.Base, Layers: img.Layers, Env: img.Env, Workdir: img.Workdir, User: img.User,
		Memory: true, Image: sb.Spec.GetImage(), Source: sb.ID, Size: allocated(dir),
		VM: &images.VMSnapshot{MemMB: s.st.MemMB, VCPUs: s.st.VCPUs, DiskMB: s.st.DiskMB}, Runtime: b.RuntimeVersions()}
	if local {
		if err := os.Rename(dir, filepath.Join(b.snaps.dir, id)); err != nil {
			return nil, err
		}
		dir = filepath.Join(b.snaps.dir, id)
		if held {
			snap.Holder = b.opt.EdgeID
		} else {
			snap.Publishing = b.opt.EdgeID
		}
	}
	if err := b.opt.Store.PutSnapshot(snap); err != nil {
		return nil, err
	}
	if local && !held {
		go b.snaps.publish(snap, b.opt.Log)
	}
	b.opt.Log.Debug("microvm snapshot", "id", sb.ID, "snapshot", id, "held", held, "type", typ, "paused", paused, "took", time.Since(t0))
	return snap, nil
}

// assemble turns the diff memory file mem into a full one: a copy of base
// (sharing its blocks where the filesystem reflinks) with the diff merged.
func assemble(base, mem string) error {
	full := mem + ".full"
	defer os.Remove(full)
	if err := copySparse(base, full); err != nil {
		return err
	}
	if _, err := mergeDiff(full, mem); err != nil {
		return err
	}
	if err := os.Chmod(full, 0o644); err != nil {
		return err
	}
	return os.Rename(full, mem)
}

// moveFile renames, or copies across filesystems.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if errors.Is(err, syscall.EXDEV) {
		if err := copySparse(src, dst); err != nil {
			return err
		}
		return os.Remove(src)
	}
	return err
}

// allocated sums the disk space used by the files in dir.
func allocated(dir string) int64 {
	var n int64
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if fi, err := e.Info(); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				n += st.Blocks * 512
			}
		}
	}
	return n
}
