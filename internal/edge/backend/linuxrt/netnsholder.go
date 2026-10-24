package linuxrt

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// NetnsHolder is a minimal process (sleep) keeping a VM sandbox's network
// namespace alive while no VMM runs in it (paused) and across edge
// restarts. A named namespace (/run/netns) would be a mount on the host,
// copied by every new mount namespace: thousands of VMs slowed each start
// (the jailer's included) by the size of the host's mount table.
type NetnsHolder struct {
	Pid   int    `json:"pid"`
	Start uint64 `json:"start"`
}

// StartNetnsHolder starts a holder in a new network namespace, in cg (the
// backend's holders' cgroup: a sandbox's own is killed when its VM ends).
func StartNetnsHolder(cg *Cgroup) (*NetnsHolder, error) {
	fd, err := cg.Open()
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	path, err := exec.LookPath("sleep")
	if err != nil {
		return nil, fmt.Errorf("netns holder: %w", err)
	}
	cmd := exec.Command(path, "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Setsid: true,
		UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("netns holder: %w", err)
	}
	go WaitCmd(cmd) // reaped if it ends while this process runs
	h := &NetnsHolder{Pid: cmd.Process.Pid}
	for i := 0; i < 100; i++ { // its start time once exec'd
		if st, err := ProcStartTime(h.Pid); err == nil {
			h.Start = st
			break
		}
		time.Sleep(time.Millisecond)
	}
	return h, nil
}

// Path is the namespace, for setns and the jailer's --netns.
func (h *NetnsHolder) Path() string { return fmt.Sprintf("/proc/%d/ns/net", h.Pid) }

// Alive reports whether the holder is still the process recorded.
func (h *NetnsHolder) Alive() bool {
	st, err := ProcStartTime(h.Pid)
	return err == nil && st == h.Start
}

// Stop ends the holder (the namespace goes with its last user).
func (h *NetnsHolder) Stop() {
	if h != nil && h.Pid > 0 && h.Alive() {
		syscall.Kill(h.Pid, syscall.SIGKILL)
	}
}
