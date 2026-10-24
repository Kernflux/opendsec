package linuxrt

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Core scheduling (paper §5.2, spec §29.1): each sandbox gets its own
// cookie, and the kernel never runs tasks with different cookies on the two
// hardware threads of one core at the same time. A latency-sensitive
// sandbox then does not share its core with a busy neighbour, and code in
// one sandbox cannot watch another through SMT side channels. Cookies are
// inherited across fork, clone and exec, so setting one at the root of a
// sandbox's process tree covers all of it.

// CoreSchedSupported reports whether the kernel has core scheduling
// (CONFIG_SCHED_CORE): nil if it does.
func CoreSchedSupported() error {
	var cookie uint64
	if err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_GET, 0, unix.PR_SCHED_CORE_SCOPE_THREAD,
		uintptr(unsafe.Pointer(&cookie))); err != nil {
		return fmt.Errorf("core scheduling (CONFIG_SCHED_CORE) unavailable: %w", err)
	}
	return nil
}

// CoreSchedDefault resolves a backend's core_sched setting: absent means on
// where the kernel supports it.
func CoreSchedDefault(set *bool) bool {
	if set != nil {
		return *set
	}
	return CoreSchedSupported() == nil
}

// CoreSchedNew gives process pid (0: the caller), all its threads and
// everything it starts from now on a new core scheduling cookie.
func CoreSchedNew(pid int) error {
	if err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_CREATE, uintptr(pid),
		unix.PR_SCHED_CORE_SCOPE_THREAD_GROUP, 0); err != nil {
		return fmt.Errorf("core scheduling cookie for pid %d: %w", pid, err)
	}
	return nil
}

// CoreSchedCookie returns the cookie of thread pid (0: the caller); 0 means
// none.
func CoreSchedCookie(pid int) (uint64, error) {
	var cookie uint64
	err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_GET, uintptr(pid), unix.PR_SCHED_CORE_SCOPE_THREAD,
		uintptr(unsafe.Pointer(&cookie)))
	return cookie, err
}

// Threads returns the ids of every thread in the cgroup and its children.
func (c *Cgroup) Threads() []int {
	var out []int
	filepath.WalkDir(c.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.threads" {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, f := range strings.Fields(string(b)) {
			if tid, err := strconv.Atoi(f); err == nil {
				out = append(out, tid)
			}
		}
		return nil
	})
	return out
}
