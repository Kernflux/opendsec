package chronus

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// asUser runs f with the file system identity of the session's user, so
// file calls see the permissions its shell does and create files it owns
// (spec §29.3). chronus itself stays root: running as the agent's user
// would let the agent tamper with it and its records.
//
// Linux keeps fsuid, fsgid and groups per thread, and the raw system calls
// below change only the calling one. f runs on a locked thread whose
// identity is put back afterwards; a thread that cannot be put back stays
// locked, so Go never runs anything else on it.
func asUser[T any](s *Server, f func() (T, error)) (T, error) {
	cred, err := s.Shell.fsCred()
	if err != nil {
		var zero T
		return zero, rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	if cred == nil {
		return f()
	}
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		groups, err := getgroups()
		if err == nil {
			err = setfsid(cred.Uid, cred.Gid, nil)
		}
		if err != nil {
			if setfsid(0, 0, groups) == nil {
				runtime.UnlockOSThread()
			}
			done <- result{err: rpcutil.Err(rpcutil.Internal, "%v", err)}
			return
		}
		var r result
		r.v, r.err = f()
		if setfsid(0, 0, groups) == nil {
			runtime.UnlockOSThread()
		}
		done <- r
	}()
	r := <-done
	return r.v, r.err
}

func getgroups() ([]uint32, error) {
	gs := make([]uint32, 256)
	n, _, e := syscall.RawSyscall(syscall.SYS_GETGROUPS, uintptr(len(gs)), uintptr(unsafe.Pointer(&gs[0])), 0)
	if e != 0 {
		return nil, fmt.Errorf("getgroups: %v", e)
	}
	return gs[:n], nil
}

// setfsid gives the calling thread file system identity uid:gid and the
// supplementary groups. A nonzero fsuid also drops the thread's file
// capabilities (CAP_DAC_OVERRIDE and the like); fsuid 0 brings them back.
func setfsid(uid, gid uint32, groups []uint32) error {
	var p uintptr
	if len(groups) > 0 {
		p = uintptr(unsafe.Pointer(&groups[0]))
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(len(groups)), p, 0); e != 0 {
		return fmt.Errorf("setgroups: %v", e)
	}
	syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
	syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
	// Both return the previous id, not an error: read them back (an
	// invalid id, -1, changes nothing).
	g, _, _ := syscall.RawSyscall(syscall.SYS_SETFSGID, ^uintptr(0), 0, 0)
	u, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, ^uintptr(0), 0, 0)
	if uint32(u) != uid || uint32(g) != gid {
		return fmt.Errorf("setfsuid %d:%d: still %d:%d", uid, gid, u, g)
	}
	return nil
}
