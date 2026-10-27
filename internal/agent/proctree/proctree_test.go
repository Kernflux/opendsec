package proctree

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSignalForking: a tree that keeps forking is killed whole, including
// what it forked while being walked.
func TestSignalForking(t *testing.T) {
	mark := "opendsec-proctree-" + strconv.Itoa(os.Getpid())
	for round := range 5 {
		// The shell forks without pause; each child sleeps under a name
		// the test finds it by.
		cmd := exec.Command("bash", "-c", `while :; do (exec -a `+mark+` sleep 30) & done`)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		Signal(cmd.Process.Pid, syscall.SIGKILL, true)
		cmd.Wait()
		time.Sleep(100 * time.Millisecond)
		if left := byName(mark); len(left) > 0 {
			for _, p := range left {
				syscall.Kill(p, syscall.SIGKILL)
			}
			t.Fatalf("round %d: %d processes of the tree survived", round, len(left))
		}
	}
}

// byName lists the live processes whose argv[0] is name.
func byName(name string) []int {
	var out []int
	ps, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, f := range ps {
		b, err := os.ReadFile(f)
		if err != nil || !strings.HasPrefix(string(b), name+"\x00") {
			continue
		}
		p, _ := strconv.Atoi(filepath.Base(filepath.Dir(f)))
		if st, err := os.ReadFile(filepath.Join(filepath.Dir(f), "stat")); err == nil && strings.Contains(string(st), ") Z ") {
			continue
		}
		out = append(out, p)
	}
	return out
}
