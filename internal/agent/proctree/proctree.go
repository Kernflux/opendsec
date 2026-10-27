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
// The tree is stopped first, walking it again until no new process shows
// up: a process that forks after one walk is found by the next, and none
// leaves the tree (its parent killed, it would go to init) before it is
// found. The stopped processes are continued after sig, so a catchable one
// handles it.
func Signal(pid int, sig syscall.Signal, self bool) {
	var victims []int
	seen := map[int]bool{}
	if self {
		syscall.Kill(pid, syscall.SIGSTOP)
		victims, seen[pid] = append(victims, pid), true
	}
	for range 100 { // bounded: a parent left running (not self) may fork on
		found := false
		for _, p := range Descendants(pid) {
			if !seen[p] {
				syscall.Kill(p, syscall.SIGSTOP)
				victims, seen[p], found = append(victims, p), true, true
			}
		}
		if !found {
			break
		}
	}
	for _, p := range victims {
		syscall.Kill(p, sig)
	}
	for _, p := range victims {
		syscall.Kill(p, syscall.SIGCONT)
	}
}
