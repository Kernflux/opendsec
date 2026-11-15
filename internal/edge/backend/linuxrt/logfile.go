package linuxrt

import (
	"io"
	"os"
)

// A sandbox's log on the host (a container's init.log, a microVM's
// console.log) is written by the sandbox: its init's stderr, the guest's
// serial console. It is outside the sandbox's disk, so it is bounded here.

// MaxLog is the size a sandbox's log is cut back at.
const MaxLog = 4 << 20

// OpenLog opens a sandbox's log for its process to append to: appending,
// so that writes go on at the start after CapLog cut it.
func OpenLog(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

// CapLog empties the log at path once it is larger than MaxLog (a log
// opened without O_APPEND by an earlier release then becomes sparse: no
// disk is used, and ReadLog reads little of it).
func CapLog(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() && fi.Size() > MaxLog {
		os.Truncate(path, 0)
	}
}

// ReadLog returns the first head and the last tail bytes of the log at
// path (all of it, in head, if it is no longer than both): never more,
// whatever the sandbox wrote there.
func ReadLog(path string, head, tail int64) (first, last []byte) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	size := fi.Size()
	if size <= head+tail {
		b, _ := io.ReadAll(io.LimitReader(f, head+tail))
		return b, nil
	}
	first = make([]byte, head)
	n, _ := io.ReadFull(f, first)
	last = make([]byte, tail)
	m, _ := f.ReadAt(last, size-tail)
	return first[:n], last[:m]
}
