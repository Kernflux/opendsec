package linuxrt

import (
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// WaitCmd waits for a started command to exit and reaps it, like
// cmd.Wait, but without holding an OS thread while it waits. os/exec blocks
// in waitid, so each waiting process pins a thread; an edge waits on one
// process per sandbox, and the Go runtime kills the program past 10000
// threads (debug.SetMaxThreads). Here the wait is a pidfd in the runtime's
// poller; cmd.Wait then returns at once. Without pidfd (kernel < 5.10) it
// falls back to cmd.Wait.
func WaitCmd(cmd *exec.Cmd) error {
	waitExited(cmd.Process.Pid)
	return cmd.Wait()
}

// waitExited returns once child pid has exited (it is left unreaped), or
// when that cannot be watched without blocking.
func waitExited(pid int) {
	fd, err := unix.PidfdOpen(pid, unix.PIDFD_NONBLOCK)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), "pidfd")
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		return
	}
	rc.Read(func(fd uintptr) bool {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PIDFD, int(fd), &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		// Not exited yet: waitid succeeds with no signal; the poller
		// then waits until the pidfd is readable, which it becomes on exit.
		return err != nil || info.Signo == int32(unix.SIGCHLD)
	})
}
