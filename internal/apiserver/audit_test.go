package apiserver

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRotation(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAuditor(dir, "t", 1, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	a.maxBytes = 600 // a few records per file
	for i := 0; i < 30; i++ {
		a.ch <- AuditRecord{Method: "CreateSandbox", Principal: "p", Project: "root/rl", Code: "OK"}
	}
	a.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-t-*.log"))
	if len(files) < 3 {
		t.Fatalf("expected rotation into several files, got %d", len(files))
	}
	n := 0
	for _, f := range files {
		st, _ := os.Stat(f)
		if st.Size() > 600+200 {
			t.Errorf("%s is %d bytes, over the rotation size", f, st.Size())
		}
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			var r AuditRecord
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("bad line: %v", err)
			}
			n++
		}
		fh.Close()
	}
	if n != 30 {
		t.Fatalf("records = %d, want 30 (none may be lost)", n)
	}
}

// TestAuditKeep: only the newest keep files stay, so the log cannot fill
// the disk; another apiserver's files in the same directory are left alone.
func TestAuditKeep(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "audit-u-20200101T000000.000000.log")
	os.WriteFile(other, nil, 0o600)
	a, err := NewAuditor(dir, "t", 1, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	a.maxBytes = 300
	for i := 0; i < 40; i++ {
		a.ch <- AuditRecord{Method: "CreateSandbox", Principal: "p", Project: "root/rl", Code: "OK"}
	}
	a.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-t-*.log"))
	if len(files) != 3 {
		t.Fatalf("%d audit files kept, want 3", len(files))
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("pruned another apiserver's file")
	}
}
