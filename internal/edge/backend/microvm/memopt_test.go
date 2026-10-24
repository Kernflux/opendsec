package microvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/images"
)

// opendsecKernel is the guest kernel with the memory optimizations' options
// (deploy/guest-kernel), else "".
func opendsecKernel() string {
	k := os.Getenv("OPENDSEC_FC_OPENDSEC_KERNEL")
	if k == "" {
		k = "/data/opendsec-vm/vmlinux-6.1.167-opendsec"
	}
	if _, err := os.Stat(k); err != nil {
		return ""
	}
	return k
}

func memoptBackend(t *testing.T, edit func(*Options)) *fixture {
	t.Helper()
	k := opendsecKernel()
	if k == "" {
		t.Skip("no OpenDsec guest kernel (OPENDSEC_FC_OPENDSEC_KERNEL; deploy/guest-kernel/build.sh)")
	}
	return newBackendWith(t, func(o *Options) {
		o.Kernel = k
		if edit != nil {
			edit(o)
		}
	})
}

// bigImage adds image "big" to f: the mini image plus a 64 MB file.
func bigImage(t *testing.T, f *fixture) {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "srv"), 0o755)
	data := make([]byte, 64<<20)
	for i := range data {
		data[i] = byte(i*7 + i>>12)
	}
	if err := os.WriteFile(filepath.Join(dir, "srv/big"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	f.b.opt.Images["big"] = []string{dir, imageDir}
}

// TestPmemImage: with the image on virtio-pmem (DAX), VMs reading the same
// image file share one copy of it in the host's page cache; snapshots,
// copies and pauses keep working.
func TestPmemImage(t *testing.T) {
	read := func(t *testing.T, pmem bool) int64 {
		f := memoptBackend(t, func(o *Options) { o.ImagePmem = pmem; o.Images = map[string][]string{"mini": {imageDir}} })
		bigImage(t, f)
		const n = 6
		sbs := make([]*backend.Sandbox, n)
		for i := range sbs {
			sbs[i] = f.create(t, &pb.SandboxSpec{Image: "big", Resources: &pb.Resources{MemoryMb: 256}})
		}
		img, _ := filepath.Glob(filepath.Join(f.b.cacheDir(), "img-*.ext4"))
		for _, p := range img {
			dropCache(p) // every run starts uncached
		}
		before := memAvailableMB()
		var wg sync.WaitGroup
		for _, sb := range sbs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if r := sh(t, f.b, sb, `cat /srv/big | wc -c; test -e /sys/block/pmem0 && echo pmem`); !strings.HasPrefix(out(r), "67108864") {
					t.Errorf("read: %q %q", r.Stdout, r.Stderr)
				}
			}()
		}
		wg.Wait()
		used := before - memAvailableMB()
		r := sh(t, f.b, sbs[0], `test -e /sys/block/pmem0 && echo pmem || echo blk`)
		if want := map[bool]string{true: "pmem", false: "blk"}[pmem]; out(r) != want {
			t.Fatalf("image device %q, want %s", out(r), want)
		}
		if pmem {
			ctx := context.Background()
			if err := f.b.Pause(ctx, sbs[1]); err != nil {
				t.Fatal(err)
			}
			if err := f.b.Resume(ctx, sbs[1]); err != nil {
				t.Fatal(err)
			}
			snap, err := f.b.Snapshot(ctx, sbs[0], images.NewSnapshotID(), true)
			if err != nil {
				t.Fatal(err)
			}
			cp := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: &pb.Resources{MemoryMb: 256}})
			for _, sb := range []*backend.Sandbox{sbs[1], cp} {
				if r := sh(t, f.b, sb, `head -c 1000000 /srv/big | wc -c; touch /srv/new && echo rw`); out(r) != "1000000\nrw" {
					t.Fatalf("after pause / restore: %q %q", r.Stdout, r.Stderr)
				}
			}
		}
		t.Logf("pmem=%v: %d VMs reading a 64 MB image file: %d MB of host memory", pmem, n, used)
		return used
	}
	blk := read(t, false)
	pm := read(t, true)
	if pm*2 > blk {
		t.Errorf("pmem image used %d MB, block image %d MB: no sharing", pm, blk)
	}
}

// TestFreePageReporting: memory the guest frees goes back to the host.
func TestFreePageReporting(t *testing.T) {
	run := func(t *testing.T, report bool) (peak, after int64) {
		f := memoptBackend(t, func(o *Options) { o.FreePageReporting = report })
		sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 512}})
		s, _ := f.b.get(sb.ID)
		sh(t, f.b, sb, `head -c 300m /dev/zero | tr '\0' x > /dev/shm/x`)
		peak = s.cg.MemoryCurrent() >> 20
		sh(t, f.b, sb, `rm /dev/shm/x`)
		deadline := time.Now().Add(10 * time.Second)
		for {
			after = s.cg.MemoryCurrent() >> 20
			if !report && time.Now().After(deadline.Add(-7*time.Second)) || after < peak/2 || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Logf("free page reporting=%v: VM cgroup %d MB holding 300 MB, %d MB after freeing it", report, peak, after)
		return peak, after
	}
	_, off := run(t, false)
	peak, on := run(t, true)
	if on > peak/2 || on >= off {
		t.Errorf("with reporting %d MB stay (peak %d, without reporting %d)", on, peak, off)
	}
}

// TestColdReclaim: DAMON_RECLAIM in the guest pages memory idle for
// cold_age_s out to zram; the pages freed go back to the host. The data
// stays intact.
func TestColdReclaim(t *testing.T) {
	f := memoptBackend(t, func(o *Options) { o.FreePageReporting, o.ColdAgeS = true, 2 })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 512}})
	s, _ := f.b.get(sb.ID)
	if r := sh(t, f.b, sb, `cat /proc/swaps | wc -l; cat /sys/module/damon_reclaim/parameters/enabled`); out(r) != "2\nY" {
		t.Fatalf("guest memory setup: %q %q", r.Stdout, r.Stderr)
	}
	// Compressible, like most memory: text.
	sum := out(sh(t, f.b, sb, `yes "the quick brown fox jumps over the lazy dog $RANDOM" | head -c 300m > /dev/shm/x; cksum < /dev/shm/x`))
	peak := s.cg.MemoryCurrent() >> 20
	start := time.Now()
	var now int64
	var half time.Duration
	for time.Since(start) < 30*time.Second {
		time.Sleep(500 * time.Millisecond)
		now = s.cg.MemoryCurrent() >> 20
		if half == 0 && now < peak/2 {
			half = time.Since(start)
		}
		if half > 0 && time.Since(start) > half+5*time.Second {
			break
		}
	}
	t.Logf("half the VM's memory back to the host after %v", half.Round(100*time.Millisecond))
	r := sh(t, f.b, sb, `grep -E "^(SwapTotal|SwapFree|MemFree):" /proc/meminfo | tr -s ' ' | tr '\n' ' '; cat /sys/block/zram0/mm_stat`)
	t.Logf("VM cgroup %d MB holding 300 MB of idle data, %d MB after %v; guest: %s", peak, now, time.Since(start).Round(time.Second), out(r))
	if now > peak/2 {
		t.Errorf("cold memory not reclaimed: %d MB of %d MB", now, peak)
	}
	if got := out(sh(t, f.b, sb, `cksum < /dev/shm/x`)); got != sum {
		t.Fatalf("data after reclaim: %s, want %s", got, sum)
	}
	// Pause / resume and a snapshot copy with swap in use.
	ctx := context.Background()
	if err := f.b.Pause(ctx, sb); err != nil {
		t.Fatal(err)
	}
	// The pages given back are zeros in the file: punched out after.
	alloc := func() (int64, int64) {
		st, err := os.Stat(filepath.Join(s.root, pauseMem))
		if err != nil {
			return 0, 0
		}
		return st.Sys().(*syscall.Stat_t).Blocks * 512 >> 20, st.Size() >> 20
	}
	first, size := alloc()
	var after int64
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if after, _ = alloc(); after < first*3/4 {
			break
		}
	}
	t.Logf("pause memory file: %d MB allocated of %d MB, %d MB once holes are punched", first, size, after)
	if after >= first*3/4 {
		t.Errorf("no holes punched in the pause memory file (%d MB -> %d MB)", first, after)
	}
	if err := f.b.Resume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	snap, err := f.b.Snapshot(ctx, sb, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	cp := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: &pb.Resources{MemoryMb: 512}})
	for _, v := range []*backend.Sandbox{sb, cp} {
		if got := out(sh(t, f.b, v, `cksum < /dev/shm/x`)); got != sum {
			t.Fatalf("data after pause / restore: %s, want %s", got, sum)
		}
	}
}

// TestMemoryDensity (OPENDSEC_BENCH=1): 16 VMs that each read a 64 MB image
// file, fill 150 MB of memory, free a third of it and idle; host memory
// with and without the optimizations (spec §19.13).
func TestMemoryDensity(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	run := func(t *testing.T, on bool) int64 {
		f := memoptBackend(t, func(o *Options) {
			o.Images = map[string][]string{"mini": {imageDir}}
			o.ImagePmem, o.FreePageReporting = on, on
			if on {
				o.ColdAgeS = 5
			}
		})
		bigImage(t, f)
		const n = 16
		before := memAvailableMB()
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			sb := f.create(t, &pb.SandboxSpec{Image: "big", Resources: &pb.Resources{MemoryMb: 512}})
			wg.Add(1)
			go func() {
				defer wg.Done()
				sh(t, f.b, sb, `cat /srv/big > /dev/null; yes "line $RANDOM of some log or heap text" | head -c 100m > /dev/shm/keep; head -c 50m /dev/zero | tr '\0' y > /dev/shm/tmp; rm /dev/shm/tmp`)
			}()
		}
		wg.Wait()
		time.Sleep(40 * time.Second)
		used := before - memAvailableMB()
		t.Logf("optimizations=%v: %d idle VMs of 512 MB: %d MB of host memory (%d MB each)", on, n, used, used/n)
		return used
	}
	off := run(t, false)
	on := run(t, true)
	t.Logf("host memory with the optimizations: %d%% of without", on*100/off)
}

// TestDiskIOLimit (spec §24): the VM's disk writes are throttled on the
// host (the VMM's I/O is the VM's).
func TestDiskIOLimit(t *testing.T) {
	f := newBackendWith(t, func(o *Options) { o.DiskIO = linuxrt.IOLimit{WriteMBps: 8} })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 256}})
	start := time.Now()
	if r := sh(t, f.b, sb, `dd if=/dev/zero of=/root/f bs=1M count=24 conv=fsync status=none`); r.ExitCode != 0 {
		t.Fatalf("dd: %q", r.Stderr)
	}
	took := time.Since(start)
	t.Logf("24 MB at 8 MB/s in %v", took.Round(time.Millisecond))
	if took < 1500*time.Millisecond { // the bucket starts full: (24-8)/8 s
		t.Errorf("write not throttled: %v", took)
	}
}

// TestSqueeze (spec §24): inflating the balloon takes memory back from a
// running guest (here its page cache); deflating gives it back.
func TestSqueeze(t *testing.T) {
	f := memoptBackend(t, func(o *Options) { o.FreePageReporting = true })
	sb := f.create(t, &pb.SandboxSpec{Resources: &pb.Resources{MemoryMb: 512}})
	s, _ := f.b.get(sb.ID)
	sh(t, f.b, sb, `dd if=/dev/urandom of=/root/f bs=1M count=300 status=none; cat /root/f > /dev/null`)
	// The guest's memory on the host is the VMM's resident set (the
	// cgroup also holds the host's cache of the VM's disk file).
	rss := func() int64 {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", s.vm().pid))
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmRSS:" {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return n >> 10
			}
		}
		return 0
	}
	before := rss()
	ctx := context.Background()
	if err := f.b.Squeeze(ctx, sb, 300); err != nil {
		t.Fatal(err)
	}
	var after int64
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if after = rss(); after <= 512-300+64 {
			break
		}
	}
	t.Logf("VM resident %d MB, %d MB with a 300 MB balloon", before, after)
	// What the guest can still hold: its memory less the balloon (plus
	// the VMM's own).
	if after > 512-300+64 || after >= before {
		t.Errorf("balloon took back too little: %d MB -> %d MB", before, after)
	}
	if err := f.b.Squeeze(ctx, sb, 0); err != nil {
		t.Fatal(err)
	}
	if got := out(sh(t, f.b, sb, `head -c 1000000 /root/f | wc -c`)); got != "1000000" {
		t.Fatalf("after deflating: %q", got)
	}
}
