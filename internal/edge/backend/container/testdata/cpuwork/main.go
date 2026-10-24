// cpuwork runs a fixed unit of integer work in a loop on several threads
// and reports how long the units took (spec §29.1: the latency-sensitive
// side of the CPU QoS measurement, paper §8.5) and how many were done (the
// best-effort side).
//
//	cpuwork -threads N -d 15s [-unit 300000]
package main

import (
	"flag"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"
)

// table is looked up at random: an L2-sized working set, as a game-tree
// search's transposition table.
var table = func() []uint64 {
	t := make([]uint64, 1<<17) // 1 MB
	for i := range t {
		t[i] = uint64(i)*0x9E3779B97F4A7C15 + 1
	}
	return t
}()

// unit does n rounds of four independent xorshift chains, each also
// folding in a table entry: it keeps the core's execution units and caches
// busy, so a sibling hardware thread slows it down.
func unit(n int, seed uint64) uint64 {
	a, b, c, d := seed|1, seed*3|1, seed*5|1, seed*7|1
	m := uint64(len(table) - 1)
	for i := 0; i < n; i++ {
		a ^= a << 13
		a ^= a >> 7
		a ^= a << 17
		b ^= b << 13
		b ^= b >> 7
		b ^= b << 17
		c ^= c << 13
		c ^= c >> 7
		c ^= c << 17
		d ^= d << 13
		d ^= d >> 7
		d ^= d << 17
		a += table[(a^d)&m]
		c += table[(b^c)&m]
	}
	return a ^ b ^ c ^ d
}

func main() {
	threads := flag.Int("threads", 1, "worker threads")
	d := flag.Duration("d", 10*time.Second, "how long to run")
	n := flag.Int("unit", 100000, "iterations per unit")
	flag.Parse()
	runtime.GOMAXPROCS(*threads + 1)
	var mu sync.Mutex
	var lat []time.Duration
	var sink uint64
	end := time.Now().Add(*d)
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			runtime.LockOSThread()
			var mine []time.Duration
			var s uint64
			for time.Now().Before(end) {
				t0 := time.Now()
				s += unit(*n, seed+s)
				mine = append(mine, time.Since(t0))
			}
			mu.Lock()
			lat, sink = append(lat, mine...), sink+s
			mu.Unlock()
		}(uint64(i) + 1)
	}
	wg.Wait()
	slices.Sort(lat)
	var sum time.Duration
	for _, l := range lat {
		sum += l
	}
	us := func(x time.Duration) int64 { return x.Microseconds() }
	fmt.Printf("units=%d per_s=%.0f p50_us=%d p99_us=%d mean_us=%d sink=%d\n", len(lat), float64(len(lat))/d.Seconds(),
		us(lat[len(lat)/2]), us(lat[len(lat)*99/100]), us(sum/time.Duration(len(lat))), sink%10)
}
