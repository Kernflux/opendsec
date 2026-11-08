package microvm

import (
	"context"
	"path/filepath"
	"strconv"
)

// snapshotCreate has firecracker write a snapshot of s's VM (paused) to
// statePath and memPath, under s.root. Firecracker runs in the VM's cgroup,
// so the page cache of the memory file it writes is charged there, on top
// of the guest's own memory: a guest using most of its memory left no room,
// and the kernel (seen on 7.0) OOM-killed firecracker mid-write. For the
// write, the group gets the VM's memory size more (bounded, and only that
// long); then the files go to disk, their cache is dropped, and the limit
// is put back as it was.
func (b *Backend) snapshotCreate(ctx context.Context, s *sandbox, v *vm, typ, statePath, memPath string) error {
	restore := func() {}
	if s.cg != nil && s.st.MemMB > 0 {
		if was, err := s.cg.MemoryMax(); err == nil && was != "max" {
			if n, err := strconv.ParseInt(was, 10, 64); err == nil {
				if s.cg.SetMemoryMax(strconv.FormatInt(n+s.st.MemMB<<20, 10)) == nil {
					restore = func() {
						if err := s.cg.SetMemoryMax(was); err != nil {
							b.opt.Log.Warn("microvm: putting the memory limit back after a snapshot failed", "id", s.id, "err", err)
						}
					}
				}
			}
		}
	}
	err := v.api.call(ctx, "PUT", "/snapshot/create", map[string]string{"snapshot_type": typ,
		"snapshot_path": statePath, "mem_file_path": memPath}, nil)
	dropCache(filepath.Join(s.root, memPath))
	dropCache(filepath.Join(s.root, statePath))
	restore()
	return err
}
