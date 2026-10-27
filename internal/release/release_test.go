package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
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

// TestVerifyRejectsWhatUnpackCannot: a tarball listing a file twice (same
// contents, so the sums match) or a file where a directory goes passed
// verification at upload, then failed to unpack on every node.
func TestVerifyRejectsWhatUnpackCannot(t *testing.T) {
	dir := makeRelease(t, "0.11.0-1")
	var tgz bytes.Buffer
	if err := Pack(dir, &tgz); err != nil {
		t.Fatal(err)
	}
	// with re-packs the release, adding extra after its entries.
	with := func(extra ...*tar.Header) []byte {
		zr, _ := gzip.NewReader(bytes.NewReader(tgz.Bytes()))
		tr := tar.NewReader(zr)
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		tw := tar.NewWriter(zw)
		edge := []byte{}
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			b, _ := io.ReadAll(tr)
			if h.Name == "0.11.0-1/bin/opendsec-edge" {
				edge = b
			}
			tw.WriteHeader(h)
			tw.Write(b)
		}
		for _, h := range extra {
			if h.Typeflag == tar.TypeReg {
				h.Size = int64(len(edge))
			}
			tw.WriteHeader(h)
			if h.Typeflag == tar.TypeReg {
				tw.Write(edge)
			}
		}
		tw.Close()
		zw.Close()
		return out.Bytes()
	}
	for name, b := range map[string][]byte{
		"a file twice":          with(&tar.Header{Name: "0.11.0-1/bin/opendsec-edge", Typeflag: tar.TypeReg, Mode: 0o755}),
		"a file as a directory": with(&tar.Header{Name: "0.11.0-1/bin/opendsec-edge/", Typeflag: tar.TypeDir, Mode: 0o755}),
	} {
		if _, err := VerifyTarball(bytes.NewReader(b)); err == nil {
			err = Unpack(bytes.NewReader(b), t.TempDir(), "0.11.0-1")
			t.Errorf("%s: verified; unpacking it: %v", name, err)
		}
	}
}
