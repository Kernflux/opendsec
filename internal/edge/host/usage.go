package host

import (
	"bufio"
	"cmp"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Usage reads what the host actually uses (spec §3.4): CPU busy share from
// /proc/stat, smoothed like the kernel's avg10 (time constant 10 s), CPU
// pressure from /proc/pressure/cpu, and memory in use. Readings are cached
// for half a second: the watcher probes every second.
type Usage struct {
	// Paths default to the host's; tests point them at files.
	StatPath, PSIPath, MemPath string

	mu        sync.Mutex
	at        time.Time
	busy, all uint64 // last /proc/stat totals
	cpu       float64
	psi       float64
	mem       float64
	sampled   bool
}

// UsageReading is one reading of Usage.
type UsageReading struct {
	CPU      float64 // busy share of all CPUs, [0, 1], smoothed over ~10 s
	Pressure float64 // PSI "some" avg10, percent; 0 without PSI
	Mem      float64 // 1 - MemAvailable/MemTotal, [0, 1]
}

const usageTau = 10 * time.Second

// Read returns the current reading.
func (u *Usage) Read() UsageReading {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	if !u.sampled || now.Sub(u.at) >= 500*time.Millisecond {
		u.sample(now)
	}
	return UsageReading{CPU: u.cpu, Pressure: u.psi, Mem: u.mem}
}

func (u *Usage) sample(now time.Time) {
	if busy, all, err := cpuTimes(cmp.Or(u.StatPath, "/proc/stat")); err == nil {
		if u.sampled && all > u.all {
			cur := float64(busy-u.busy) / float64(all-u.all)
			// Exponential smoothing over the elapsed time, as PSI's avg10.
			a := 1 - math.Exp(-now.Sub(u.at).Seconds()/usageTau.Seconds())
			u.cpu += a * (cur - u.cpu)
		}
		u.busy, u.all = busy, all
	}
	if p, err := cpuPressure(cmp.Or(u.PSIPath, "/proc/pressure/cpu")); err == nil {
		u.psi = p
	}
	if total, avail, err := memInfo(cmp.Or(u.MemPath, "/proc/meminfo")); err == nil && total > 0 {
		u.mem = min(1, max(0, 1-float64(avail)/float64(total)))
	}
	u.at, u.sampled = now, true
}

// cpuTimes returns the busy and total jiffies of the "cpu" line of
// /proc/stat. Idle and iowait count as not busy; guest time is already
// part of user time.
func cpuTimes(path string) (busy, all uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 9 || fs[0] != "cpu" {
			continue
		}
		var v [8]uint64 // user nice system idle iowait irq softirq steal
		for i := range v {
			v[i], _ = strconv.ParseUint(fs[i+1], 10, 64)
		}
		for i, x := range v {
			all += x
			if i != 3 && i != 4 {
				busy += x
			}
		}
		return busy, all, nil
	}
	return 0, 0, os.ErrNotExist
}

// cpuPressure returns the "some" avg10 of a PSI file, in percent.
func cpuPressure(path string) (float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 2 || fs[0] != "some" {
			continue
		}
		if v, ok := strings.CutPrefix(fs[1], "avg10="); ok {
			return strconv.ParseFloat(v, 64)
		}
	}
	return 0, os.ErrNotExist
}

// memInfo is MemInfo for a given path.
func memInfo(path string) (totalMB, availableMB int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		switch k {
		case "MemTotal":
			totalMB = n / 1024
		case "MemAvailable":
			availableMB = n / 1024
		}
	}
	return totalMB, availableMB, sc.Err()
}
