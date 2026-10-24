package linuxrt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcStartTime returns field 22 of /proc/<pid>/stat (start time in clock
// ticks since boot); a dead or zombie process is an error.
func ProcStartTime(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	f := strings.Fields(s[i+1:]) // f[0] is field 3 (state)
	if len(f) < 20 {
		return 0, fmt.Errorf("short stat for pid %d", pid)
	}
	if f[0] == "Z" || f[0] == "X" {
		return 0, fmt.Errorf("pid %d has exited", pid)
	}
	return strconv.ParseUint(f[19], 10, 64)
}

func WriteJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Mounted reports whether dir is a mount point in our mount namespace.
func Mounted(dir string) bool {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == abs {
			return true
		}
	}
	return false
}

// Has reports whether pid is a member of the cgroup.
func (c *Cgroup) Has(pid int) bool {
	b, err := os.ReadFile(filepath.Join(c.Path, "cgroup.procs"))
	if err != nil {
		return false
	}
	want := strconv.Itoa(pid)
	for _, p := range strings.Fields(string(b)) {
		if p == want {
			return true
		}
	}
	return false
}
