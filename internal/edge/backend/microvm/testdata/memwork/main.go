// Command memwork runs memory workloads inside a guest for TestDirtyTracking
// (spec §19.14). The buffer is a file in /dev/shm, so it outlives each run:
//
//	memwork touch MB      create the buffer and write one byte per page
//	memwork rewrite MB    write one byte per page of the buffer
//	memwork read MB       read one byte per page of the buffer
//	memwork rand MB SEC   random 8-byte read-modify-writes over the buffer
//	memwork alloc SEC     allocate and drop small objects (GC pressure)
//
// Each prints one line: "ms=..." or "mops=...".
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const buf = "/dev/shm/memwork"

func main() {
	if len(os.Args) < 3 {
		fail(fmt.Errorf("usage: memwork touch|rewrite|read|rand|alloc ARGS"))
	}
	n := atoi(os.Args[2])
	switch os.Args[1] {
	case "touch":
		f, err := os.OpenFile(buf, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		fail(err)
		fail(f.Truncate(int64(n) << 20))
		f.Close()
		m := mapBuf(n, false)
		t := time.Now()
		pages(m, true)
		ms(t)
	case "rewrite", "read":
		m := mapBuf(n, false)
		t := time.Now()
		pages(m, os.Args[1] == "rewrite")
		ms(t)
	case "rand":
		m := mapBuf(n, true)
		w := unsafe.Slice((*uint64)(unsafe.Pointer(&m[0])), len(m)/8)
		d := time.Duration(atoi(os.Args[3])) * time.Second
		x, ops, t := uint64(88172645463325252), 0, time.Now()
		for time.Since(t) < d {
			for i := 0; i < 1<<16; i++ {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
				w[x%uint64(len(w))]++
			}
			ops += 1 << 16
		}
		fmt.Printf("mops=%.2f\n", float64(ops)/time.Since(t).Seconds()/1e6)
	case "alloc":
		d := time.Duration(n) * time.Second
		ring := make([][]byte, 1<<17)
		x, ops, t := uint64(88172645463325252), 0, time.Now()
		for time.Since(t) < d {
			for i := 0; i < 1<<12; i++ {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
				b := make([]byte, 16+x%4080)
				b[0] = byte(x)
				ring[x%uint64(len(ring))] = b
			}
			ops += 1 << 12
		}
		fmt.Printf("mops=%.2f\n", float64(ops)/time.Since(t).Seconds()/1e6)
	default:
		fail(fmt.Errorf("unknown workload %q", os.Args[1]))
	}
}

func mapBuf(mb int, populate bool) []byte {
	f, err := os.OpenFile(buf, os.O_RDWR, 0)
	fail(err)
	defer f.Close()
	flags := syscall.MAP_SHARED
	if populate {
		flags |= syscall.MAP_POPULATE
	}
	m, err := syscall.Mmap(int(f.Fd()), 0, mb<<20, syscall.PROT_READ|syscall.PROT_WRITE, flags)
	fail(err)
	return m
}

var sink byte

func pages(m []byte, write bool) {
	for i := 0; i < len(m); i += 4096 {
		if write {
			m[i]++
		} else {
			sink += m[i]
		}
	}
}

func ms(t time.Time) { fmt.Printf("ms=%.1f\n", float64(time.Since(t).Microseconds())/1000) }

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	fail(err)
	return n
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "memwork:", err)
		os.Exit(1)
	}
}
