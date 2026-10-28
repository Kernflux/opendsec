package backend

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDialUnixLongPath: a socket whose path is longer than sun_path (a
// microVM's vsock under a long edge name) is still reached.
func TestDialUnixLongPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 60), strings.Repeat("e", 60))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "v.sock")
	if len(path) < sunPath {
		t.Fatalf("path too short for the test: %d", len(path))
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ln, err := net.Listen("unix", fmt.Sprintf("/proc/self/fd/%d/v.sock", d.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	c, err := DialUnix(context.Background(), path)
	if err != nil {
		t.Fatalf("dial %d-byte path: %v", len(path), err)
	}
	defer c.Close()
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "ok" {
		t.Fatalf("read: %q %v", b, err)
	}
}
