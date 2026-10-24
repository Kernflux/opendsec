// Package sandboxfs applies file access restrictions inside a sandbox's
// mount namespace (spec §21), from its own root: in a container after
// pivot_root, in a microVM guest likewise.
package sandboxfs

import (
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
		if err := unix.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
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
