package linuxrt

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Pause-time memory reclaim for containers (spec §22.1, paper §4.3): a
// frozen sandbox's memory is pushed out to swap; on resume it is read back
// ahead of use.

// SetSwap allows (or forbids) the cgroup to use swap.
func (c *Cgroup) SetSwap(allow bool) error {
	v := "0"
	if allow {
		v = "max"
	}
	return os.WriteFile(filepath.Join(c.Path, "memory.swap.max"), []byte(v), 0)
}

// Reclaim pushes the cgroup's anonymous memory out to swap and returns the
// bytes freed. Pages are written out with process_madvise(MADV_PAGEOUT) on
// each process (memory.reclaim alone would weigh them against page cache);
// memory.reclaim then drops what stays in the swap cache. That needs
// vm.swappiness > 0 (cgroup reclaim never takes anonymous pages otherwise;
// kernels before 6.10 take no swappiness of their own) and is bounded in
// time: on a frozen cgroup the kernel can retry for long.
func (c *Cgroup) Reclaim() int64 {
	before := c.MemoryCurrent()
	for _, pid := range c.Procs() {
		advise(pid, unix.MADV_PAGEOUT)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Ask for the swap cache only: asking for more (kernel memory, say)
		// keeps the kernel retrying.
		if n := c.stat("swapcached"); n > 0 {
			os.WriteFile(filepath.Join(c.Path, "memory.reclaim"), []byte(strconv.FormatInt(n, 10)), 0)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	return before - c.MemoryCurrent()
}

// Swappiness is the host's vm.swappiness.
func Swappiness() int {
	b, _ := os.ReadFile("/proc/sys/vm/swappiness")
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// Procs lists the processes of the cgroup and its descendants.
func (c *Cgroup) Procs() []int {
	var out []int
	filepath.WalkDir(c.Path, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		for _, f := range strings.Fields(string(b)) {
			if pid, err := strconv.Atoi(f); err == nil {
				out = append(out, pid)
			}
		}
		return nil
	})
	return out
}

// Prefetch asks the kernel to read back the swapped-out anonymous memory of
// the cgroup's processes (process_madvise MADV_WILLNEED); it returns the
// bytes advised. Reads happen asynchronously.
func (c *Cgroup) Prefetch() int64 {
	var total int64
	for _, pid := range c.Procs() {
		total += advise(pid, unix.MADV_WILLNEED)
	}
	return total
}

// advise applies advice to pid's private writable anonymous memory.
func advise(pid int, advice uintptr) int64 {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0
	}
	defer unix.Close(fd)
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	// struct iovec pairs (base, len) of the target's address space: plain
	// numbers here, never pointers of ours.
	var iov []uint64
	var total int64
	flush := func() {
		if len(iov) == 0 {
			return
		}
		unix.Syscall6(unix.SYS_PROCESS_MADVISE, uintptr(fd), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)/2),
			advice, 0, 0)

		iov = iov[:0]
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// start-end perms offset dev inode [path]: private writable
		// anonymous memory (heap, stacks, anonymous mappings).
		fs := strings.Fields(sc.Text())
		if len(fs) < 5 || len(fs[1]) < 4 || fs[1][1] != 'w' || fs[1][3] != 'p' || fs[4] != "0" {
			continue
		}
		if len(fs) >= 6 && !strings.HasPrefix(fs[5], "[") {
			continue
		}
		var start, end uint64
		if _, err := fmt.Sscanf(fs[0], "%x-%x", &start, &end); err != nil || end <= start {
			continue
		}
		iov = append(iov, start, end-start)
		total += int64(end - start)
		if len(iov) == 1024 {
			flush()
		}
	}
	flush()
	return total
}

// stat reads one field of memory.stat.
func (c *Cgroup) stat(key string) int64 {
	b, _ := os.ReadFile(filepath.Join(c.Path, "memory.stat"))
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == key {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}
