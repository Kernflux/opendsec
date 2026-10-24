package microvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/images"
)

// TestRestorePhases (OPENDSEC_BENCH=1): spec §19.15, where the time of a
// create from a memory snapshot goes, with the snapshot in the host page
// cache and dropped from it before each create.
func TestRestorePhases(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	// OPENDSEC_BENCH_NOTRACK=1: without dirty page tracking.
	// OPENDSEC_BENCH_JAILER: another jailer (e.g. a wrapper tracing it).
	f := newBackendWith(t, func(o *Options) {
		o.NoDirtyTracking = os.Getenv("OPENDSEC_BENCH_NOTRACK") != ""
		if j := os.Getenv("OPENDSEC_BENCH_JAILER"); j != "" {
			o.Jailer = j
		}
	})
	ctx := context.Background()
	res := &pb.Resources{CpuCores: 1, MemoryMb: 512}
	src := f.create(t, &pb.SandboxSpec{Resources: res})
	sh(t, f.b, src, `head -c 128m /dev/urandom > /dev/shm/data`)
	snap, err := f.b.Snapshot(ctx, src, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	f.b.Stop(ctx, src)
	dir, _ := f.opt.Store.SnapshotDir(snap.ID)
	const n = 20
	var b strings.Builder
	for _, cache := range []string{"warm", "dropped"} {
		steps := map[string][]time.Duration{}
		var order []string
		add := func(name string, d time.Duration) {
			if _, ok := steps[name]; !ok {
				order = append(order, name)
			}
			steps[name] = append(steps[name], d)
		}
		for i := 0; i < n; i++ {
			if cache == "dropped" {
				ents, _ := os.ReadDir(dir)
				for _, e := range ents {
					dropCache(filepath.Join(dir, e.Name()))
				}
			}
			t0 := time.Now()
			c, err := f.tryCreate(&pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
			if err != nil {
				t.Fatal(err)
			}
			add("create (total)", time.Since(t0))
			t1 := time.Now()
			sh(t, f.b, c, `true`)
			add("first exec", time.Since(t1))
			t1 = time.Now()
			sh(t, f.b, c, `cat /dev/shm/data | wc -c`)
			add("read 128 MB", time.Since(t1))
			s, _ := f.b.get(c.ID)
			for _, p := range s.lastRestore {
				add(p.Name, p.D)
			}
			f.b.Stop(ctx, c)
		}
		fmt.Fprintf(&b, "\n%s page cache, %d creates\n%-16s %9s %9s %9s\n", cache, n, "step", "p50", "p90", "max")
		for _, name := range order {
			d := slices.Clone(steps[name])
			slices.Sort(d)
			fmt.Fprintf(&b, "%-16s %9s %9s %9s\n", name, ms(d[len(d)/2]), ms(d[len(d)*9/10]), ms(d[len(d)-1]))
		}
	}
	t.Log(b.String())
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

// TestColdBootTracking (OPENDSEC_BENCH=1): spec §19.14, the time of a cold
// boot with and without dirty page tracking, by VM size, alternating.
func TestColdBootTracking(t *testing.T) {
	if os.Getenv("OPENDSEC_BENCH") == "" {
		t.Skip("set OPENDSEC_BENCH=1")
	}
	tracked := newBackendWith(t, nil)
	untracked := newBackendWith(t, func(o *Options) { o.UntrackedBoot = true })
	ctx := context.Background()
	const n = 15
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-8s %-10s %-14s %9s %9s %9s\n", "mem", "tracking", "step", "p50", "p90", "max")
	for _, mb := range []int64{512, 2048, 8192} {
		res := &pb.Resources{CpuCores: 2, MemoryMb: mb}
		steps := map[string]map[string][]time.Duration{"on": {}, "off": {}}
		for i := 0; i < n; i++ {
			for _, mode := range []string{"on", "off"} {
				f := tracked
				if mode == "off" {
					f = untracked
				}
				t0 := time.Now()
				c, err := f.tryCreate(&pb.SandboxSpec{Resources: res})
				if err != nil {
					t.Fatal(err)
				}
				steps[mode]["create"] = append(steps[mode]["create"], time.Since(t0))
				t1 := time.Now()
				sh(t, f.b, c, `true`)
				steps[mode]["first exec"] = append(steps[mode]["first exec"], time.Since(t1))
				t1 = time.Now()
				sh(t, f.b, c, `head -c 256m /dev/zero > /dev/shm/x`)
				steps[mode]["write 256 MB"] = append(steps[mode]["write 256 MB"], time.Since(t1))
				f.b.Stop(ctx, c)
			}
		}
		for _, mode := range []string{"on", "off"} {
			for _, name := range []string{"create", "first exec", "write 256 MB"} {
				d := slices.Clone(steps[mode][name])
				slices.Sort(d)
				fmt.Fprintf(&b, "%-8d %-10s %-14s %9s %9s %9s\n", mb, mode, name, ms(d[len(d)/2]), ms(d[len(d)*9/10]), ms(d[len(d)-1]))
			}
		}
	}
	t.Log(b.String())
}
