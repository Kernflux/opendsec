// Package host reads node resources and memory pressure from /proc.
package host

import (
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// MemInfo returns MemTotal and MemAvailable in MB.
func MemInfo() (totalMB, availableMB int64, err error) { return memInfo("/proc/meminfo") }

// CPUs returns the number of online CPUs.
func CPUs() int { return runtime.NumCPU() }

// Pressure reports whether the node is under critical memory pressure:
// MemAvailable below a reserve (paper §3: the edge rejects placements under
// critical resource pressure). Readings are cached briefly so the creation
// hot path does not reread /proc/meminfo every time.
type Pressure struct {
	ReserveMB int64

	mu      sync.Mutex
	at      time.Time
	availMB int64
	err     error
}

// DefaultReserveMB is 10% of host memory, at least 128 MB.
func DefaultReserveMB() int64 {
	total, _, err := MemInfo()
	if err != nil {
		return 128
	}
	return max(total/10, 128)
}

// Check returns the current MemAvailable and whether it is below the reserve.
func (p *Pressure) Check() (availableMB int64, under bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.at) > 100*time.Millisecond {
		_, p.availMB, p.err = MemInfo()
		p.at = time.Now()
	}
	if p.err != nil {
		return 0, false
	}
	return p.availMB, p.availMB < p.ReserveMB
}

// Invalidate forces the next Check to reread /proc/meminfo (after a sandbox
// starts, memory use changes quickly).
func (p *Pressure) Invalidate() {
	p.mu.Lock()
	p.at = time.Time{}
	p.mu.Unlock()
}

// DiskInfo returns the size and the space available to unprivileged users of
// the filesystem holding path, in MB.
func DiskInfo(path string) (totalMB, availableMB int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	return int64(st.Blocks * bs >> 20), int64(st.Bavail * bs >> 20), nil
}

// DefaultDiskReserveMB is 5% of the filesystem holding path, at least 1 GB.
func DefaultDiskReserveMB(path string) int64 {
	total, _, err := DiskInfo(path)
	if err != nil {
		return 1024
	}
	return max(total/20, 1024)
}

// DiskPressure reports whether the filesystem holding Path has less than
// ReserveMB free. Sandbox disks are sparse, so they fill the filesystem as
// sandboxes write: capacity accounting alone cannot see this.
type DiskPressure struct {
	Path      string
	ReserveMB int64

	mu      sync.Mutex
	at      time.Time
	availMB int64
	err     error
}

// Check returns the current free space and whether it is below the reserve.
func (p *DiskPressure) Check() (availableMB int64, under bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.at) > time.Second {
		_, p.availMB, p.err = DiskInfo(p.Path)
		p.at = time.Now()
	}
	if p.err != nil {
		return 0, false
	}
	return p.availMB, p.availMB < p.ReserveMB
}
