package main

import (
	"os/exec"
	"testing"
)

// TestShellCmd: exec's arguments reach the sandbox's shell as they were
// given; one argument is a command line of its own.
func TestShellCmd(t *testing.T) {
	cases := map[string][]string{
		"ls -la /tmp":             {"ls", "-la", "/tmp"},
		"python3 -c 'print(6*7)'": {"python3", "-c", "print(6*7)"},
		`echo 'it'\''s' 'a b' ''`: {"echo", "it's", "a b", ""},
		"cd /tmp && echo $(pwd)":  {"cd /tmp && echo $(pwd)"},
	}
	for want, args := range cases {
		if got := shellCmd(args); got != want {
			t.Errorf("shellCmd(%q) = %s, want %s", args, got, want)
		}
	}
	// Through a real shell: the arguments come out the same.
	args := []string{"printf", "[%s]", "it's", "a b", "", "$HOME", "x;y", "*"}
	out, err := exec.Command("sh", "-c", shellCmd(args)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "[it's][a b][][$HOME][x;y][*]"; string(out) != want {
		t.Errorf("shell got %s, want %s", out, want)
	}
}
