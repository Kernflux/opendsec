package container

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Container hardening (spec §21). Sandbox processes run as root in their
// own namespaces, but on the host's kernel: the setup process limits what
// that root can do before it execs aether (inherited by everything after).

// keptCaps is Docker's default capability set minus CAP_MKNOD (without a
// device cgroup a device node would reach the host's disks).
var keptCaps = []int{unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FSETID, unix.CAP_FOWNER, unix.CAP_NET_RAW,
	unix.CAP_SETGID, unix.CAP_SETUID, unix.CAP_SETFCAP, unix.CAP_SETPCAP, unix.CAP_NET_BIND_SERVICE,
	unix.CAP_SYS_CHROOT, unix.CAP_KILL, unix.CAP_AUDIT_WRITE}

// dropCaps removes every other capability from the bounding set (exec then
// grants root no more) and from the calling thread's inheritable set. The
// caller holds its OS thread: capabilities are per thread.
func dropCaps() error {
	last := unix.CAP_LAST_CAP
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			last = n
		}
	}
	keep := map[int]bool{}
	for _, c := range keptCaps {
		keep[c] = true
	}
	for c := 0; c <= last; c++ {
		if keep[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d: %w", c, err)
		}
	}
	unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	return nil
}

// Syscalls refused with EPERM (x86_64 numbers): mounts and namespace
// switches (they could undo the sandbox's file restrictions), kernel
// modules and kexec, bpf, keyrings, file handles (the "shocker" escape),
// userfaultfd, perf, raw I/O ports, swap, quotas, reboot. clone and
// unshare are refused only with CLONE_NEWUSER (a user namespace would give
// back the dropped capabilities over its own mounts); clone3 gets ENOSYS
// (its flags cannot be inspected), so libc falls back to clone.
var deniedSyscalls = []uint32{
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_SETNS,
	unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE,
	unix.SYS_MOUNT_SETATTR, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_BPF, unix.SYS_KEYCTL, unix.SYS_ADD_KEY,
	unix.SYS_REQUEST_KEY, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_USERFAULTFD,
	unix.SYS_PERF_EVENT_OPEN, unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
	unix.SYS_QUOTACTL, unix.SYS_REBOOT, unix.SYS_ACCT, unix.SYS_LOOKUP_DCOOKIE,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
}

const (
	auditArchX86_64 = 0xc000003e
	x32SyscallBit   = 0x40000000
	seccompDataNr   = 0
	seccompDataArch = 4
	seccompDataArg0 = 16 // low 32 bits on little endian
)

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// seccompFilter builds the BPF program: anything but native x86_64
// syscalls is refused (i386 and x32 entry points would bypass the numbers
// below), then the denials.
func seccompFilter() []unix.SockFilter {
	const (
		ld  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jst = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret = unix.BPF_RET | unix.BPF_K
	)
	eperm := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	enosys := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS))
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	f := []unix.SockFilter{
		stmt(ld, seccompDataArch),
		jump(jeq, auditArchX86_64, 1, 0),
		stmt(ret, eperm),
		stmt(ld, seccompDataNr),
		jump(jge, x32SyscallBit, 0, 1),
		stmt(ret, eperm),
		jump(jeq, unix.SYS_CLONE3, 0, 1),
		stmt(ret, enosys),
	}
	for _, nr := range deniedSyscalls {
		f = append(f, jump(jeq, nr, 0, 1), stmt(ret, eperm))
	}
	// clone(flags, ...) and unshare(flags): no CLONE_NEWUSER.
	for _, nr := range []uint32{unix.SYS_CLONE, unix.SYS_UNSHARE} {
		f = append(f,
			jump(jeq, nr, 0, 4),
			stmt(ld, seccompDataArg0),
			jump(jst, unix.CLONE_NEWUSER, 0, 1),
			stmt(ret, eperm),
			stmt(ret, allow),
		)
	}
	return append(f, stmt(ret, allow))
}

// installSeccomp applies the filter to every thread of the process (it is
// kept across exec and inherited by children).
func installSeccomp() error {
	f := seccompFilter()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	if _, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog))); e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}
