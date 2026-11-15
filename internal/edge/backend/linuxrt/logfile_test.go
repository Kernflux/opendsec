package linuxrt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLogBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	f, err := OpenLog(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("start\n")
	if first, last := ReadLog(p, 100, 100); string(first) != "start\n" || last != nil {
		t.Fatalf("short log: %q %q", first, last)
	}
	f.Write(bytes.Repeat([]byte("x"), MaxLog))
	f.WriteString("end\n")
	first, last := ReadLog(p, 6, 4)
	if string(first) != "start\n" || string(last) != "end\n" {
		t.Fatalf("long log: %q %q", first, last)
	}
	CapLog(p)
	f.WriteString("after\n") // appended at the start again
	if b, _ := os.ReadFile(p); string(b) != "after\n" {
		t.Fatalf("after the cut: %d bytes", len(b))
	}
	CapLog(p) // small: kept
	if fi, _ := os.Stat(p); fi.Size() != 6 {
		t.Fatalf("cut a small log: %d", fi.Size())
	}
}
