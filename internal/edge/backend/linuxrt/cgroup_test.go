package linuxrt

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestKillThenReuse: a cgroup Kill emptied takes new processes (a paused
// microVM resumes into its cgroup), including through CLONE_INTO_CGROUP,
// which kernels kill after a cgroup.kill (Ubuntu 24.04's 6.8.0-1xx); and
// Kill gets processes forking as fast as they can.
func TestKillThenReuse(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root (cgroup v2)")
	}
	cg, err := NewCgroup("", "opendsec-test-kill-"+strconv.Itoa(os.Getpid()), Limits{})
	if err != nil {
		t.Skip("no cgroup v2:", err)
	}
	defer cg.Remove()
	start := func(script string) *exec.Cmd {
		f, err := cg.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		c := exec.Command("/bin/sh", "-c", script)
		c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for round := 0; round < 3; round++ {
		c := start("while :; do sleep 10 & sleep 0.005; done") // keeps forking
		time.Sleep(100 * time.Millisecond)
		cg.Kill()
		c.Wait()
		if cg.Populated() {
			t.Fatalf("round %d: processes left after Kill: %v", round, cg.Procs())
		}
		if err := start("exit 0").Wait(); err != nil {
			t.Fatalf("round %d: a process started after Kill: %v", round, err)
		}
	}
}
