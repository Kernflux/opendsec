package images

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// untar unpacks an archive made of regular files into dir.
func untar(t *testing.T, file, dir string) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, h.Name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		b, _ := io.ReadAll(tr)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSaveImport (spec §38): a registry's image saved as an OCI layout tar
// imports into another store, from the tar or unpacked, the same as a pull;
// a tampered blob, a compressed archive and a wrong name are refused.
func TestSaveImport(t *testing.T) {
	base := mkLayer(t, []tarEntry{{name: "etc/base", body: "gzip\n"}})
	top := mkZstdLayer(t, []tarEntry{{name: "etc/top", body: "zstd\n"}})
	srv, _ := fakeRegistry(t, [][]byte{base, top}, map[string]any{
		"config": map[string]any{"Env": []string{"LANG=C.UTF-8"}, "WorkingDir": "/app"}})
	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/app:v1"
	ctx := context.Background()

	pulled, _ := NewStore(t.TempDir())
	want, err := (&Puller{Store: pulled, PlainHTTP: true, Platform: "linux/amd64"}).Pull(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "app.tar")
	var buf bytes.Buffer
	if err := (&Puller{PlainHTTP: true, Platform: "linux/amd64"}).Save(ctx, ref, &buf); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(file, buf.Bytes(), 0o644)
	unpacked := filepath.Join(dir, "layout")
	untar(t, file, unpacked)

	for _, src := range []string{file, unpacked, file + "#" + ref} {
		s, _ := NewStore(t.TempDir())
		res, err := (&Puller{Store: s, Platform: "linux/amd64"}).Import(ctx, src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if strings.Join(res.Layers, ",") != strings.Join(want.Layers, ",") || res.Pulled != 2 ||
			res.Env["LANG"] != "C.UTF-8" || res.Workdir != "/app" || !strings.HasPrefix(res.Source, "file://") {
			t.Fatalf("%s: %+v, want the layers %v", src, res, want.Layers)
		}
		if b, _ := os.ReadFile(filepath.Join(s.LayerRootfs(res.Layers[1]), "etc/top")); string(b) != "zstd\n" {
			t.Fatalf("%s: content %q", src, b)
		}
	}

	s, _ := NewStore(t.TempDir())
	imp := &Puller{Store: s, Platform: "linux/amd64"}
	if _, err := imp.Import(ctx, file+"#other:v1"); err == nil || !strings.Contains(err.Error(), "no image other:v1") {
		t.Fatalf("wrong name: %v", err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(buf.Bytes())
	zw.Close()
	os.WriteFile(file+".gz", gz.Bytes(), 0o644)
	if _, err := imp.Import(ctx, file+".gz"); err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("compressed archive: %v", err)
	}
	// A tampered layer fails its digest and never lands.
	blob := filepath.Join(unpacked, "blobs/sha256", strings.TrimPrefix(digest(top), "sha256:"))
	b, _ := os.ReadFile(blob)
	b[len(b)/2] ^= 0xff
	os.WriteFile(blob, b, 0o644)
	if _, err := imp.Import(ctx, unpacked); err == nil {
		t.Fatal("tampered layer imported")
	}
	if s.HasLayer(want.Layers[1]) {
		t.Fatal("tampered layer in the store")
	}
}

// TestImportDockerSave: an archive of `docker save` before Docker 25
// (manifest.json, uncompressed layer files) with two images, picked by tag.
func TestImportDockerSave(t *testing.T) {
	raw := func(entries []tarEntry) []byte {
		gz, _ := gzip.NewReader(bytes.NewReader(mkLayer(t, entries)))
		b, _ := io.ReadAll(gz)
		return b
	}
	l1, l2 := raw([]tarEntry{{name: "etc/one", body: "1\n"}}), raw([]tarEntry{{name: "etc/two", body: "2\n"}})
	cfg := func(layers ...[]byte) []byte {
		var ids []string
		for _, l := range layers {
			ids = append(ids, digest(l))
		}
		b, _ := json.Marshal(map[string]any{"config": map[string]any{"Env": []string{"X=y"}}, "rootfs": map[string]any{"type": "layers", "diff_ids": ids}})
		return b
	}
	c1, c2 := cfg(l1, l2), cfg(l1)
	man, _ := json.Marshal([]map[string]any{
		{"Config": "c1.json", "RepoTags": []string{"app:v1"}, "Layers": []string{"a/layer.tar", "b/layer.tar"}},
		{"Config": "c2.json", "RepoTags": []string{"base:v1"}, "Layers": []string{"a/layer.tar"}},
	})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, b := range map[string][]byte{"manifest.json": man, "c1.json": c1, "c2.json": c2, "a/layer.tar": l1, "b/layer.tar": l2} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	file := filepath.Join(t.TempDir(), "save.tar")
	os.WriteFile(file, buf.Bytes(), 0o644)

	s, _ := NewStore(t.TempDir())
	p := &Puller{Store: s}
	if _, err := p.Import(context.Background(), file); err == nil || !strings.Contains(err.Error(), "holds 2 images") {
		t.Fatalf("two images, no name: %v", err)
	}
	res, err := p.Import(context.Background(), file+"#docker.io/library/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Layers) != 2 || res.Layers[1] != "sha256-"+strings.TrimPrefix(digest(l2), "sha256:") || res.Env["X"] != "y" {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(s.LayerRootfs(res.Layers[1]), "etc/two")); string(b) != "2\n" {
		t.Fatalf("content %q", b)
	}
	if res, err := p.Import(context.Background(), file+"#base:v1"); err != nil || len(res.Layers) != 1 || res.Pulled != 0 {
		t.Fatalf("second image (its layer already stored): %+v %v", res, err)
	}
}
