// Package sandboxfs applies file access restrictions inside a sandbox's
// mount namespace (spec §21), from its own root: in a container after
// pivot_root, in a microVM guest likewise.
package sandboxfs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Container defaults, as runc / Docker: kernel interfaces a sandbox's root
// could use against the host. /proc/sys and the others stay readable.
var (
	ProcReadonly = []string{"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus", "/proc/fs"}
	ProcMasked   = []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug", "/proc/scsi",
		"/proc/acpi", "/proc/latency_stats", "/sys/firmware", "/sys/kernel/debug", "/proc/kallsyms"}
)

// Validate checks caller-given paths: absolute and clean.
func Validate(paths []string) error {
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsRune(p, 0) {
			return fmt.Errorf("path %q must be absolute, clean and not /", p)
		}
	}
	return nil
}

// Apply makes readonly read-only and hides masked; paths that do not exist
// are skipped.
func Apply(readonly, masked []string) error {
	for _, p := range readonly {
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("read-only %s: %w", p, err)
		}
		if err := readonlyTree(p); err != nil {
			return fmt.Errorf("read-only %s: %w", p, err)
		}
	}
	for _, p := range masked {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			err = unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=0,mode=755")
		} else {
			err = unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
		}
		if err != nil {
			return fmt.Errorf("mask %s: %w", p, err)
		}
	}
	return nil
}

// readonlyTree makes the mount at p read-only, with every mount below it
// (/dev/shm under /dev): a remount changes one mount only.
func readonlyTree(p string) error {
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
	err := unix.MountSetattr(unix.AT_FDCWD, p, unix.AT_RECURSIVE, attr)
	if !errors.Is(err, unix.ENOSYS) {
		return err
	}
	// Before Linux 5.12: each mount at or under p, by its mount point.
	points, err := mountsUnder(p)
	if err != nil {
		return err
	}
	for _, m := range points {
		if err := unix.Mount("", m, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return err
		}
	}
	return nil
}

// mountsUnder lists the mount points at or under p (/proc/self/mountinfo).
func mountsUnder(p string) ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		m := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		if m == p || strings.HasPrefix(m, p+"/") {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}
