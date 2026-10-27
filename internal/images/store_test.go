package images

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

func TestParseName(t *testing.T) {
	cases := map[string][3]string{
		"root/rl/python:3.12": {"root/rl", "python", "3.12"},
		"root/base":           {"root", "base", "latest"},
	}
	for in, want := range cases {
		p, r, tg, err := ParseName(in)
		if err != nil || [3]string{p, r, tg} != want {
			t.Errorf("ParseName(%q) = %q %q %q %v", in, p, r, tg, err)
		}
	}
	for _, bad := range []string{"python:3.12", "/python", "root/../x:1", "root/Py:1", "root/x:", "root//x"} {
		if _, _, _, err := ParseName(bad); err == nil {
			t.Errorf("ParseName(%q) should fail", bad)
		}
	}
}

func layer(t *testing.T, s *Store, id string, files map[string]string) {
	t.Helper()
	w, exists, err := s.BeginLayer(id)
	if err != nil || exists {
		t.Fatalf("begin %s: %v %v", id, exists, err)
	}
	for p, c := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(w.Rootfs, p)), 0o755)
		os.WriteFile(filepath.Join(w.Rootfs, p), []byte(c), 0o644)
	}
	if _, err := w.Commit(LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
}

func TestStore(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := "sha256-" + strings.Repeat("a", 64)
	tool := "sha256-" + strings.Repeat("b", 64)
	layer(t, s, base, map[string]string{"etc/os-release": "base"})
	layer(t, s, tool, map[string]string{"opt/tool/run": "tool"})
	// Same digest again: already there, nothing to write (dedup).
	if _, exists, _ := s.BeginLayer(base); !exists {
		t.Fatal("existing layer not detected")
	}
	if err := s.PutManifest(&Manifest{Name: "root/rl/py", Layers: []string{base, "sha256-" + strings.Repeat("c", 64)}}, false); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("manifest with a missing layer: %v", err)
	}
	if err := s.PutManifest(&Manifest{Name: "root/rl/py:3.12", Layers: []string{base, tool}, Env: map[string]string{"A": "1"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.PutManifest(&Manifest{Name: "root/rl/py:3.12", Layers: []string{base}}, false); err == nil {
		t.Fatal("overwrote without overwrite")
	}
	m, err := s.GetManifest("root/rl/py:3.12")
	if err != nil || m.Env["A"] != "1" {
		t.Fatalf("get: %+v %v", m, err)
	}
	low, _ := s.Lowerdirs(m)
	if len(low) != 2 || low[0] != s.LayerRootfs(tool) || low[1] != s.LayerRootfs(base) {
		t.Fatalf("lowerdirs must be topmost first: %v", low)
	}
	s.PutManifest(&Manifest{Name: "root/other/x", Layers: []string{base}}, false)
	if l, _ := s.List("root/rl"); len(l) != 1 || l[0].Name != "root/rl/py:3.12" {
		t.Fatalf("list root/rl: %v", l)
	}
	if l, _ := s.List("root"); len(l) != 2 {
		t.Fatalf("list root: %d", len(l))
	}
	if l, err := s.List("root/none"); err != nil || len(l) != 0 {
		t.Fatalf("list empty: %v %v", l, err)
	}
	if err := s.DeleteManifest("root/rl/py:3.12"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetManifest("root/rl/py:3.12"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("deleted manifest still readable: %v", err)
	}
}

func TestPublishLayerDirScrubs(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	src := t.TempDir()
	for _, p := range []string{"app/main.py", "tmp/build.log", "root/.cache/pip/x", "root/.bash_history", ".opendsec/run/x"} {
		os.MkdirAll(filepath.Dir(filepath.Join(src, p)), 0o755)
		os.WriteFile(filepath.Join(src, p), []byte("x"), 0o644)
	}
	id := NewDiffLayerID()
	if !ValidLayerID(id) {
		t.Fatalf("bad id %s", id)
	}
	meta, err := s.PublishLayerDir(id, src, nil, DefaultScrub, LayerMeta{})
	if err != nil {
		t.Fatal(err)
	}
	root := s.LayerRootfs(id)
	if _, err := os.Stat(filepath.Join(root, "app/main.py")); err != nil {
		t.Fatal("content missing")
	}
	for _, gone := range []string{"tmp/build.log", "root/.cache", "root/.bash_history", ".opendsec"} {
		if _, err := os.Lstat(filepath.Join(root, gone)); err == nil {
			t.Errorf("%s was not scrubbed", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "tmp")); err != nil {
		t.Error("tmp/ itself should remain (only its contents are scrubbed)")
	}
	if meta.Size == 0 {
		t.Error("size not recorded")
	}
}

// TestScrubStaysInside: scrub patterns never reach outside the layer: not
// with "..", and not through a link the sandbox made (tmp -> /), which
// would have the edge, as root, remove the host's files.
func TestScrubStaysInside(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	host := t.TempDir() // stands for the host's /
	for _, p := range []string{"etc/passwd", "keep/x"} {
		os.MkdirAll(filepath.Join(host, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(host, p), []byte("x"), 0o644)
	}
	src := t.TempDir()
	os.Symlink(host, filepath.Join(src, "tmp"))
	os.MkdirAll(filepath.Join(src, "home"), 0o755)
	os.Symlink(host, filepath.Join(src, "home", "u"))
	os.MkdirAll(filepath.Join(src, "var"), 0o755)
	os.WriteFile(filepath.Join(src, "var", "f"), []byte("x"), 0o644)
	id := NewDiffLayerID()
	if _, err := s.PublishLayerDir(id, src, nil, append(DefaultScrub, "home/*/keep"), LayerMeta{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"etc/passwd", "keep/x"} {
		if _, err := os.Stat(filepath.Join(host, p)); err != nil {
			t.Errorf("scrub removed %s outside the layer", p)
		}
	}
	if fi, err := os.Lstat(filepath.Join(s.LayerRootfs(id), "tmp")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link itself should stay (tmp/* matches inside a directory only): %v", err)
	}
	for _, bad := range []string{"../x", "a/../../x", "/etc", "a//b", ".", "", "[x"} {
		if _, err := s.PublishLayerDir(NewDiffLayerID(), src, nil, []string{bad}, LayerMeta{}); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Errorf("scrub %q: %v, want invalid", bad, err)
		}
	}
}

func TestSnapshots(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	w, _, _ := st.BeginLayer(NewDiffLayerID())
	os.WriteFile(filepath.Join(w.Rootfs, "f"), []byte("x"), 0o644)
	l, err := w.Commit(LayerMeta{})
	if err != nil {
		t.Fatal(err)
	}
	id := NewSnapshotID()
	if !ValidSnapshotID(id) || ValidSnapshotID("snap-../x") {
		t.Fatalf("snapshot id validation: %s", id)
	}
	if err := st.PutSnapshot(&Snapshot{ID: id, Layers: []string{l.ID, "diff-aaaaaaaaaaaaaaaaaaaaaaaa"}}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("snapshot with a missing layer: %v", err)
	}
	if err := st.PutSnapshot(&Snapshot{ID: id, Base: "host", Layers: []string{l.ID}, Env: map[string]string{"A": "1"}}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSnapshot(id)
	if err != nil || got.Base != "host" || got.Env["A"] != "1" || got.CreatedAt == 0 {
		t.Fatalf("get: %+v %v", got, err)
	}
	if dirs, err := st.SnapshotLowerdirs(got); err != nil || len(dirs) != 1 || dirs[0] != st.LayerRootfs(l.ID) {
		t.Fatalf("lowerdirs: %v %v", dirs, err)
	}
	if _, err := st.GetSnapshot(NewSnapshotID()); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("unknown snapshot: %v", err)
	}
	if _, err := st.GetSnapshot("../../etc"); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("bad id: %v", err)
	}
}

// TestManifestCacheShared: a tag overwritten through another Store on the
// same root (another process: an apiserver, while an edge reads) is seen.
func TestManifestCacheShared(t *testing.T) {
	root := t.TempDir()
	a, _ := NewStore(root)
	b, _ := NewStore(root)
	var layers []string
	for _, id := range []string{"diff-aaaaaaaaaaaaaaaa", "diff-bbbbbbbbbbbbbbbb"} {
		w, _, _ := a.BeginLayer(id)
		w.Commit(LayerMeta{})
		layers = append(layers, id)
	}
	if err := a.PutManifest(&Manifest{Name: "root/x:1", Layers: layers[:1]}, false); err != nil {
		t.Fatal(err)
	}
	if m, err := b.GetManifest("root/x:1"); err != nil || m.Layers[0] != layers[0] {
		t.Fatal(m, err)
	}
	if err := a.PutManifest(&Manifest{Name: "root/x:1", Layers: layers[1:]}, true); err != nil {
		t.Fatal(err)
	}
	if m, err := b.GetManifest("root/x:1"); err != nil || m.Layers[0] != layers[1] {
		t.Fatalf("after another store overwrote the tag: %v %v", m.Layers, err)
	}
	if err := a.DeleteManifest("root/x:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetManifest("root/x:1"); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("after another store deleted it: %v", err)
	}
}
