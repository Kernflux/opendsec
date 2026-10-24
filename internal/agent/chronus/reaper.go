package chronus

import (
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// BecomeSubreaper makes this process the reaper for its orphaned descendants.
// Commands that daemonize (e.g. `(server &)`) then stay inside the session's
// process tree, so closing the session kills them too (paper §3: aether
// terminates the chronus process tree when a session ends).
//
// Orphans re-parented to us must be reaped here; skip(pid) reports pids that
// os/exec waits for itself (the shell), which must not be stolen.
func BecomeSubreaper(skip func(pid int) bool) error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGCHLD)
	go func() {
		t := time.NewTicker(2 * time.Second) // backstop for coalesced signals
		for {
			select {
			case <-sig:
			case <-t.C:
			}
			reapOrphans(skip)
		}
	}()
	return nil
}

func reapOrphans(skip func(int) bool) {
	self := os.Getpid()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || skip(pid) {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 || f[0] != "Z" || f[1] != strconv.Itoa(self) {
			continue
		}
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
	}
}
