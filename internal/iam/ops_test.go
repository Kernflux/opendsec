package iam

import (
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"testing"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// TestBackupRestoreStandalone: a backup restores into a fresh standalone
// IAM (disaster recovery), persists there, and keeps live leases.
func TestBackupRestoreStandalone(t *testing.T) {
	m, admin := setup(t)
	m.CreateProject("admin", "root", "rl", map[string]float64{QSandboxes: 5})
	agentTok, _, _ := m.CreatePrincipal("admin", "root/rl", "agent", "agent", 0)
	m.Grant("admin", "root/rl", "agent", []string{SandboxCreate})
	if _, err := m.Backup("agent"); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("backup by a non-admin: %v", err)
	}
	b, err := m.Backup("admin")
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "iam.json")
	fresh, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Bootstrap("admin", admin, nil); err != nil {
		t.Fatal(err)
	}
	fresh.Reserve("live", "root", map[string]float64{QSandboxes: 1})
	before := fresh.SecurityEpoch()
	if err := fresh.Restore("admin", b); err != nil {
		t.Fatal(err)
	}
	if fresh.SecurityEpoch() <= before {
		t.Error("restore must move the security epoch")
	}
	if p, err := fresh.Authenticate(agentTok); err != nil || p.ID != "agent" {
		t.Fatalf("restored token: %v %v", p, err)
	}
	if err := fresh.Authorize("agent", "root/rl", SandboxCreate); err != nil {
		t.Fatal(err)
	}
	if v, _ := fresh.GetProject("", "root"); v.Usage[QSandboxes] != 1 {
		t.Fatalf("live lease lost: %v", v.Usage)
	}
	// Persisted: a restart reads the restored state.
	again, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Authorize("agent", "root/rl", SandboxCreate); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if err := fresh.Restore("admin", []byte("junk")); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("junk: %v", err)
	}
}

// TestRestoreLegacyFormat: a backup taken before the rename to OpenDsec
// (format "dsec-iam-backup/1") restores; any other format is refused.
func TestRestoreLegacyFormat(t *testing.T) {
	m, admin := setup(t)
	m.CreateProject("admin", "root", "rl", nil)
	tok, _, _ := m.CreatePrincipal("admin", "root/rl", "agent", "agent", 0)
	b, err := m.Backup("admin")
	if err != nil {
		t.Fatal(err)
	}
	reformat := func(format string) []byte {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(r)
		raw = bytes.Replace(raw, []byte(`"`+BackupFormat+`"`), []byte(`"`+format+`"`), 1)
		var z bytes.Buffer
		w := gzip.NewWriter(&z)
		w.Write(raw)
		w.Close()
		return z.Bytes()
	}
	fresh, err := New(filepath.Join(t.TempDir(), "iam.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Bootstrap("admin", admin, nil); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Restore("admin", reformat("other-backup/1")); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("unknown format: %v", err)
	}
	if err := fresh.Restore("admin", reformat(legacyBackupFormat)); err != nil {
		t.Fatal(err)
	}
	if p, err := fresh.Authenticate(tok); err != nil || p.ID != "agent" {
		t.Fatalf("restored token: %v %v", p, err)
	}
}
