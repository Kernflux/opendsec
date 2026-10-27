package aether

import "testing"

// TestSessionNames: a session name becomes a directory and a socket name,
// so "." and ".." (the shared run dir and its parent) are refused.
func TestSessionNames(t *testing.T) {
	for name, ok := range map[string]bool{"default": true, "a.b-c_1": true, "_x": true, ".": false, "..": false,
		".hidden": false, "a/b": false, "": false} {
		if sessionRe.MatchString(name) != ok {
			t.Errorf("%q: valid=%v, want %v", name, !ok, ok)
		}
	}
}
