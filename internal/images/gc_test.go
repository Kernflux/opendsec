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
	for n, id := range ids { // writing the references touched them
		if n != "young" {
			age(filepath.Join(st.layerDir(id), "meta.json"))
		}
	}
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

// TestGCStopsOnUnreadable: a reference GC cannot read (a manifest, a
// snapshot record, an in-use marker) stops it before it removes anything,
// since what it missed may be the only reference to a layer.
func TestGCStopsOnUnreadable(t *testing.T) {
	for _, bad := range []string{"manifest", "snapshot", "inuse"} {
		t.Run(bad, func(t *testing.T) {
			st, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			id := "diff-aaaaaaaaaaaaaaaa"
			w, _, err := st.BeginLayer(id)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Commit(LayerMeta{Source: "test"}); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-48 * time.Hour)
			os.Chtimes(filepath.Join(st.layerDir(id), "meta.json"), old, old)
			var p string
			switch bad {
			case "manifest":
				st.PutManifest(&Manifest{Name: "root/a:1", Layers: []string{id}}, false)
				ps, _ := filepath.Glob(filepath.Join(st.Root, "images", "root", "*", "*.json"))
				if len(ps) == 0 {
					ps, _ = filepath.Glob(filepath.Join(st.Root, "images", "root", "*.json"))
				}
				if len(ps) != 1 {
					t.Fatalf("manifest files %v", ps)
				}
				p = ps[0]
			case "snapshot":
				sid := NewSnapshotID()
				st.SnapshotDir(sid)
				st.PutSnapshot(&Snapshot{ID: sid, Layers: []string{id}})
				p = filepath.Join(st.snapshotDir(sid), "snapshot.json")
				os.Chtimes(p, old, old)
			case "inuse":
				st.MarkInUse("e1.container.lease", []string{id})
				p = filepath.Join(st.inuseDir(), "e1.container.lease")
			}
			os.Chtimes(filepath.Join(st.layerDir(id), "meta.json"), old, old) // writing the reference touched it
			os.WriteFile(p, []byte("{not json"), 0o644) // as a read failing midway
			res, err := st.GC(24*time.Hour, false)
			if err == nil || res != nil {
				t.Fatalf("GC = %v, %v; want it stopped", res, err)
			}
			if !st.HasLayer(id) {
				t.Fatal("the layer went")
			}
		})
	}
}

// TestGCRace: a layer or snapshot a record names that was written after GC
// read the references (an image tagged from an old layer) stays.
func TestGCRace(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	lid := "diff-aaaaaaaaaaaaaaaa"
	w, _, _ := st.BeginLayer(lid)
	if _, err := w.Commit(LayerMeta{}); err != nil {
		t.Fatal(err)
	}
	sid := NewSnapshotID()
	st.SnapshotDir(sid)
	if err := st.PutSnapshot(&Snapshot{ID: sid, Layers: []string{lid}}); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(filepath.Join(st.layerDir(lid), "meta.json"), old, old)
	os.Chtimes(filepath.Join(st.snapshotDir(sid), "snapshot.json"), old, old)
	gcScanned = func() {
		if err := st.PutManifest(&Manifest{Name: "root/late:1", Layers: []string{lid}, Snapshot: sid}, false); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { gcScanned = nil }()
	res, err := st.GC(24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasLayer(lid) || len(res.Layers) != 0 {
		t.Fatalf("a layer named since GC read the references was removed: %v", res.Layers)
	}
	if _, err := st.GetSnapshot(sid); err != nil || len(res.Snapshots) != 0 {
		t.Fatalf("a snapshot named since was removed: %v %v", res.Snapshots, err)
	}
}

// TestPutManifestOnce: of two creations of one name without overwrite, one
// fails; the other's content stays.
func TestPutManifestOnce(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	var layers []string
	for _, id := range []string{"diff-aaaaaaaaaaaaaaaa", "diff-bbbbbbbbbbbbbbbb"} {
		w, _, _ := st.BeginLayer(id)
		w.Commit(LayerMeta{})
		layers = append(layers, id)
	}
	for range 20 {
		name := "root/x:" + NewDiffLayerID()[5:13]
		errs := make(chan error, 2)
		for _, l := range layers {
			go func() { errs <- st.PutManifest(&Manifest{Name: name, Layers: []string{l}}, false) }()
		}
		failed := 0
		for range 2 {
			if <-errs != nil {
				failed++
			}
		}
		if failed != 1 {
			t.Fatalf("%d of two creations of %s failed", failed, name)
		}
	}
}
