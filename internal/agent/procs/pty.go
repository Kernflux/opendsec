package procs

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// openPty opens a new terminal of size sz: its master side and its slave
// side (owned by cred's user, so what runs on it can reopen it). The master
// is non-blocking, in Go's poller: closing it ends a read in progress.
func openPty(sz *pb.PtySize, cred *syscall.Credential) (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	defer func() {
		if err != nil {
			master.Close()
		}
	}()
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil { // unlock
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	slave, err = os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if cred != nil {
		os.Chown(name, int(cred.Uid), int(cred.Gid))
	}
	if err := setSize(master, sz); err != nil {
		slave.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// setSize sets the terminal's size (through SyscallConn: Fd would switch
// the master to blocking mode).
func setSize(pty *os.File, sz *pb.PtySize) error {
	cols, rows := sz.Cols, sz.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	rc, err := pty.SyscallConn()
	if err != nil {
		return err
	}
	var ierr error
	if err := rc.Control(func(fd uintptr) {
		ierr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
	}); err != nil {
		return err
	}
	return ierr
}
