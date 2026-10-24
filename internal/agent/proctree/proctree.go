// Package proctree finds and kills process trees via /proc (Linux).
package proctree

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Descendants returns every descendant of pid (not pid itself), parents first.
func Descendants(pid int) []int {
	children := map[int][]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// Format: pid (comm) state ppid ... ; comm may contain spaces or ')'.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		children[ppid] = append(children[ppid], p)
	}
	var out []int
	stack := []int{pid}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[cur] {
			out = append(out, c)
			stack = append(stack, c)
		}
	}
	return out
}

// Signal sends sig to every descendant of pid; with self, to pid as well.
func Signal(pid int, sig syscall.Signal, self bool) {
	// Stop the tree first so nothing forks while we walk it.
	victims := Descendants(pid)
	if self {
		victims = append([]int{pid}, victims...)
	}
	for _, p := range victims {
		syscall.Kill(p, sig)
	}
}
