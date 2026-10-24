package linuxrt

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func threads(t *testing.T) int {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Threads:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	t.Fatal("no Threads line")
	return 0
}

// TestWaitCmdThreads: waiting on many processes does not take a thread
// each (an edge waits on one per sandbox; the Go runtime dies past 10000).
func TestWaitCmdThreads(t *testing.T) {
	const n = 300
	before := threads(t)
	var wg sync.WaitGroup
	stdin, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		cmd := exec.Command("sh", "-c", "read x")
		cmd.Stdin = stdin
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); errs <- WaitCmd(cmd) }()
	}
	stdin.Close()
	// All n are running, each with a goroutine waiting on it.
	if d := threads(t) - before; d > 50 {
		t.Fatalf("%d more threads while waiting on %d processes", d, n)
	}
	release.Close() // EOF on their stdin: they all exit
	wg.Wait()
	close(errs)
	for err := range errs {
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
	}
}

// TestWaitCmdStatus: the exit status comes through as with cmd.Wait.
func TestWaitCmdStatus(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	err := WaitCmd(cmd)
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("WaitCmd = %v, want exit status 3", err)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("ProcessState not set")
	}
}
