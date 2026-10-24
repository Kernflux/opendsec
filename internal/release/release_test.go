package release

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeRelease(t *testing.T, version string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), version)
	for p, c := range map[string]string{
		"bin/opendsec-edge": "edge", "bin/firecracker": "fc", "units/opendsec-edge.service": "[Unit]",
		"deps.lock": "# pinned\nfirecracker v1.17.0 url:https://x/fc.tgz " + strings.Repeat("a", 64) + " bin/firecracker\n",
	} {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteSums(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPackVerifyUnpack(t *testing.T) {
	dir := makeRelease(t, "0.11.0-1")
	var tgz bytes.Buffer
	if err := Pack(dir, &tgz); err != nil {
		t.Fatal(err)
	}
	info, err := VerifyTarball(bytes.NewReader(tgz.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.11.0-1" || info.Deps["firecracker"] != "v1.17.0" {
		t.Fatalf("info: %+v", info)
	}
	parent := t.TempDir()
	if err := Unpack(bytes.NewReader(tgz.Bytes()), parent, "0.11.0-1"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDir(filepath.Join(parent, "0.11.0-1")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(parent, "0.11.0-1/bin/opendsec-edge")); string(b) != "edge" {
		t.Fatalf("unpacked: %q", b)
	}
	if err := Unpack(bytes.NewReader(tgz.Bytes()), parent, "other"); err == nil {
		t.Fatal("unpacked under the wrong version")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	dir := makeRelease(t, "v1")
	os.WriteFile(filepath.Join(dir, "bin/opendsec-edge"), []byte("evil"), 0o755)
	if err := VerifyDir(dir); err == nil {
		t.Fatal("tampered file passed")
	}
	if err := Pack(dir, &bytes.Buffer{}); err == nil {
		t.Fatal("packed a tampered release")
	}
	dir = makeRelease(t, "v2")
	os.WriteFile(filepath.Join(dir, "bin/extra"), []byte("x"), 0o755)
	if err := VerifyDir(dir); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Fatalf("uncovered file: %v", err)
	}
}
