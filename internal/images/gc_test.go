package images

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestGC(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	layer := func(id string) {
		w, exists, err := st.BeginLayer(id)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			return
		}
		os.WriteFile(filepath.Join(w.Rootfs, "f"), []byte(id), 0o644)
		if _, err := w.Commit(LayerMeta{Source: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	age := func(p string) {
		old := time.Now().Add(-48 * time.Hour)
		os.Chtimes(p, old, old)
	}
	ids := map[string]string{}
	for _, n := range []string{"image", "snap", "inuse", "orphan", "young", "deleted"} {
		ids[n] = "diff-" + (n + "aaaaaaaaaaaaaaaa")[:16]
		layer(ids[n])
		if n != "young" {
			age(filepath.Join(st.layerDir(ids[n]), "meta.json"))
		}
	}
	if err := st.PutManifest(&Manifest{Name: "root/a:1", Layers: []string{ids["image"]}}, false); err != nil {
		t.Fatal(err)
	}
	// A snapshot an image names keeps its layers; an old unnamed one goes.
	kept, gone := NewSnapshotID(), NewSnapshotID()
	for _, id := range []string{kept, gone} {
		st.SnapshotDir(id)
		layers := []string{ids["snap"]}
		if id == gone {
			layers = []string{ids["deleted"]}
		}
		if err := st.PutSnapshot(&Snapshot{ID: id, Layers: layers}); err != nil {
			t.Fatal(err)
		}
		age(filepath.Join(st.snapshotDir(id), "snapshot.json"))
	}
	st.PutManifest(&Manifest{Name: "root/warm:1", Layers: []string{ids["snap"]}, Snapshot: kept}, false)
	st.MarkInUse("e1.container.lease", []string{ids["inuse"]})
	res, err := st.GC(24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(res.Layers)
	want := []string{ids["deleted"], ids["orphan"]}
	slices.Sort(want)
	if !slices.Equal(res.Layers, want) || !slices.Equal(res.Snapshots, []string{gone}) {
		t.Fatalf("dry run: layers %v snapshots %v; want %v, [%s]", res.Layers, res.Snapshots, want, gone)
	}
	if _, err := st.GC(24*time.Hour, false); err != nil {
		t.Fatal(err)
	}
	for n, id := range ids {
		if want := n != "orphan" && n != "deleted"; st.HasLayer(id) != want {
			t.Errorf("layer %s present=%v", n, !want)
		}
	}
	if _, err := st.GetSnapshot(gone); err == nil {
		t.Error("unnamed old snapshot kept")
	}
	// Released, the in-use layer goes on the next pass; a reused layer is young again.
	st.ReleaseInUse("e1.container.lease")
	layer(ids["inuse"]) // re-published: exists, refreshed
	st.GC(24*time.Hour, false)
	if !st.HasLayer(ids["inuse"]) {
		t.Error("layer used again was collected")
	}
}
