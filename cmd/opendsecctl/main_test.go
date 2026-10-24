package main

import (
	"flag"
	"slices"
	"testing"
)

func TestReorder(t *testing.T) {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.String("session", "", "")
	fs.String("addr", "", "")
	for _, c := range []struct {
		args []string
		stop int
		want []string
	}{
		{[]string{"sb", "-addr", "x"}, 0, []string{"-addr", "x", "--", "sb"}},
		{[]string{"sb", "python3", "-c", "print(1)"}, 2, []string{"--", "sb", "python3", "-c", "print(1)"}},
		{[]string{"sb", "-session", "s", "ls", "-la"}, 2, []string{"-session", "s", "--", "sb", "ls", "-la"}},
		{[]string{"-addr", "x", "sb", "--", "ls", "-la"}, 2, []string{"-addr", "x", "--", "sb", "ls", "-la"}},
	} {
		if got := reorder(fs, c.args, c.stop); !slices.Equal(got, c.want) {
			t.Errorf("reorder(%q, %d) = %q, want %q", c.args, c.stop, got, c.want)
		}
	}
}
