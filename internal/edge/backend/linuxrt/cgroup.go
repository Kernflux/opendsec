// Package linuxrt holds the Linux plumbing shared by the real runtimes
// (container, microvm): cgroup v2 groups, process identity, state files.
package linuxrt

import (
	"golang.org/x/sys/unix"

	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const CgroupRoot = "/sys/fs/cgroup"

// Cgroup is one sandbox's cgroup v2 directory.
type Cgroup struct{ Path string }

// EnsureParent creates rel's ancestors and delegates controllers down to
// it: cpu, memory, pids, and io when asked (only with disk_io limits: with
// it a sandbox's page cache writeback is its own, which a tight memory
// limit can turn into OOM kills on some kernels).
func EnsureParent(rel string, io bool) error {
	cur := CgroupRoot
	for _, part := range strings.Split(strings.Trim(rel, "/"), "/") {
		enableControllers(cur, io)
		cur = filepath.Join(cur, part)
		if err := os.MkdirAll(cur, 0o755); err != nil {
			return err
		}
	}
	enableControllers(cur, io)
	return nil
}

func enableControllers(dir string, io bool) {
	avail, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return
	}
	have := map[string]bool{}
	for _, c := range strings.Fields(string(avail)) {
		have[c] = true
	}
	var want []string
	ctl := []string{"cpu", "memory", "pids"}
	if io {
		ctl = append(ctl, "io")
	}
	for _, c := range ctl {
		if have[c] {
			want = append(want, "+"+c)
		}
	}
	os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(strings.Join(want, " ")), 0)
}

type Limits struct {
	CPUCores   float64
	MemoryMB   int64
	Pids       int
	BestEffort bool
}

func NewCgroup(parentRel, name string, l Limits) (*Cgroup, error) {
	cg := &Cgroup{Path: filepath.Join(CgroupRoot, parentRel, name)}
	if err := os.Mkdir(cg.Path, 0o755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := cg.SetLimits(l); err != nil {
		cg.Remove()
		return nil, err
	}
	return cg, nil
}

// SetLimits applies l (zero fields leave a limit as it is).
func (c *Cgroup) SetLimits(l Limits) error {
	set := func(file, val string, required bool) error {
		if err := os.WriteFile(filepath.Join(c.Path, file), []byte(val), 0); err != nil && required {
			return fmt.Errorf("cgroup %s=%s: %w", file, val, err)
		}
		return nil
	}
	var errs []error
	if l.MemoryMB > 0 {
		errs = append(errs, set("memory.max", strconv.FormatInt(l.MemoryMB<<20, 10), true))
		set("memory.swap.max", "0", false)
	}
	if l.CPUCores > 0 {
		const period = 100000
		errs = append(errs, set("cpu.max", fmt.Sprintf("%d %d", int64(l.CPUCores*period), period), true))
	}
	if l.Pids > 0 {
		errs = append(errs, set("pids.max", strconv.Itoa(l.Pids), true))
	}
	if l.BestEffort {
		// Best-effort QoS: SCHED_IDLE for the whole group (paper §4.3).
		set("cpu.idle", "1", false)
	}
	return errors.Join(errs...)
}

func (c *Cgroup) Open() (*os.File, error) {
	return os.OpenFile(c.Path, syscall.O_DIRECTORY|syscall.O_RDONLY, 0)
}

func (c *Cgroup) Freeze(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := os.WriteFile(filepath.Join(c.Path, "cgroup.freeze"), []byte(v), 0); err != nil {
		return err
	}
	// Wait until the kernel reports the transition complete.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c.Frozen() == on {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("cgroup freeze=%s did not settle", v)
}

func (c *Cgroup) Frozen() bool {
	b, err := os.ReadFile(filepath.Join(c.Path, "cgroup.events"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "frozen ") {
			return strings.TrimSpace(line[len("frozen "):]) == "1"
		}
	}
	return false
}

func (c *Cgroup) Populated() bool {
	b, err := os.ReadFile(filepath.Join(c.Path, "cgroup.events"))
	return err == nil && strings.Contains(string(b), "populated 1")
}

// Kill SIGKILLs every process in the cgroup and its descendants (works on
// frozen cgroups too) and waits, up to 5 s, until they are gone. It freezes
// the cgroup first, so that nothing forks out of the way, and thaws it
// after. Not cgroup.kill: on some kernels (Ubuntu 24.04's 6.8.0-1xx) a
// cgroup that has been through cgroup.kill kills every process cloned into
// it later (CLONE_INTO_CGROUP), and a paused microVM's cgroup is used again
// when it resumes.
func (c *Cgroup) Kill() {
	freeze := filepath.Join(c.Path, "cgroup.freeze")
	os.WriteFile(freeze, []byte("1"), 0)
	defer os.WriteFile(freeze, []byte("0"), 0)
	for deadline := time.Now().Add(5 * time.Second); ; {
		pids := c.Procs()
		if len(pids) == 0 || time.Now().After(deadline) {
			return
		}
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Remove kills remaining processes and deletes the cgroup.
func (c *Cgroup) Remove() {
	for i := 0; i < 200; i++ {
		if err := os.Remove(c.Path); err == nil || os.IsNotExist(err) {
			return
		}
		if c.Populated() {
			c.Kill()
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *Cgroup) MemoryCurrent() int64 {
	b, err := os.ReadFile(filepath.Join(c.Path, "memory.current"))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// IOLimit bounds a sandbox's disk I/O (io.max); zero fields are unlimited.
type IOLimit struct {
	ReadMBps, WriteMBps, ReadIOPS, WriteIOPS int64
}

func (l IOLimit) Zero() bool { return l == IOLimit{} }

// SetIO applies l on the block device dev (a stat's st_dev).
func (c *Cgroup) SetIO(dev uint64, l IOLimit) error {
	if l.Zero() {
		return nil
	}
	v := func(n, unit int64) string {
		if n <= 0 {
			return "max"
		}
		return strconv.FormatInt(n*unit, 10)
	}
	line := fmt.Sprintf("%d:%d rbps=%s wbps=%s riops=%s wiops=%s", unix.Major(dev), unix.Minor(dev),
		v(l.ReadMBps, 1<<20), v(l.WriteMBps, 1<<20), v(l.ReadIOPS, 1), v(l.WriteIOPS, 1))
	if err := os.WriteFile(filepath.Join(c.Path, "io.max"), []byte(line), 0); err != nil {
		return fmt.Errorf("io.max %s: %w", line, err)
	}
	return nil
}

// DeviceOf is the block device holding path's filesystem.
func DeviceOf(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Dev, nil
}
