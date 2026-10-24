package host

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUsage(t *testing.T) {
	dir := t.TempDir()
	u := &Usage{StatPath: filepath.Join(dir, "stat"), PSIPath: filepath.Join(dir, "psi"), MemPath: filepath.Join(dir, "meminfo")}
	// user nice system idle iowait irq softirq steal guest guest_nice
	writeFile(t, u.StatPath, "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0 0 0\n")
	writeFile(t, u.PSIPath, "some avg10=44.13 avg60=13.75 avg300=3.36 total=51570133\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	writeFile(t, u.MemPath, "MemTotal:       1048576 kB\nMemFree:          1024 kB\nMemAvailable:     262144 kB\n")

	r := u.Read() // the first reading only sets the CPU baseline
	if r.CPU != 0 || r.Pressure != 44.13 || r.Mem != 0.75 {
		t.Fatalf("first reading: %+v", r)
	}
	// Fully busy for the next interval: the smoothed value moves toward 1
	// by 1 - e^(-dt/10s).
	writeFile(t, u.StatPath, "cpu  600 0 600 800 0 0 0 0 0 0\n")
	u.at = u.at.Add(-5 * time.Second)
	r = u.Read()
	if want := 1 - math.Exp(-0.5); math.Abs(r.CPU-want) > 0.02 {
		t.Fatalf("cpu after 5 s fully busy: %.3f, want about %.3f", r.CPU, want)
	}
	// Idle again: it decays toward 0.
	before := r.CPU
	writeFile(t, u.StatPath, "cpu  600 0 600 1800 0 0 0 0 0 0\n")
	u.at = u.at.Add(-5 * time.Second)
	if r = u.Read(); r.CPU >= before || r.CPU <= 0 {
		t.Fatalf("cpu after 5 s idle: %.3f (was %.3f)", r.CPU, before)
	}
	// Readings within half a second are cached.
	writeFile(t, u.PSIPath, "some avg10=90.00 avg60=0 avg300=0 total=1\n")
	if r2 := u.Read(); r2.Pressure != r.Pressure {
		t.Fatalf("cached reading changed: %+v -> %+v", r, r2)
	}
}

func TestUsageWithoutPSI(t *testing.T) {
	dir := t.TempDir()
	u := &Usage{StatPath: filepath.Join(dir, "stat"), PSIPath: filepath.Join(dir, "absent"), MemPath: filepath.Join(dir, "absent")}
	writeFile(t, u.StatPath, "cpu  1 0 1 8 0 0 0 0 0 0\n")
	if r := u.Read(); r.Pressure != 0 || r.Mem != 0 {
		t.Fatalf("reading without PSI or meminfo: %+v", r)
	}
}
