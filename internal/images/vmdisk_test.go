package images

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func addLayer(t *testing.T, st *Store, id string) {
	t.Helper()
	w, _, err := st.BeginLayer(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(LayerMeta{}); err != nil {
		t.Fatal(err)
	}
}

// TestVMDisk (spec §29.4): one build per layer stack across concurrent
// callers (edges sharing the store), a failed build leaves nothing, a dead
// builder's lock is taken over, lowerdirs map back to layers.
func TestVMDisk(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, b := NewDiffLayerID(), NewDiffLayerID()
	addLayer(t, st, a)
	addLayer(t, st, b)
	layers, ok := st.LayersOf([]string{st.LayerRootfs(b), st.LayerRootfs(a)}) // topmost first
	if !ok || len(layers) != 2 || layers[0] != a || layers[1] != b {
		t.Fatalf("LayersOf: %v %v", layers, ok)
	}
	if _, ok := st.LayersOf([]string{"/srv/images/x", st.LayerRootfs(a)}); ok {
		t.Fatal("a lowerdir outside the store mapped to layers")
	}
	if VMDiskKey([]string{a, b}) == VMDiskKey([]string{b, a}) {
		t.Fatal("the key ignores the order of the layers")
	}

	var builds atomic.Int32
	build := func(dst string) error {
		builds.Add(1)
		time.Sleep(300 * time.Millisecond) // long enough for the others to wait
		return os.WriteFile(dst, []byte("disk of a, b"), 0o644)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	paths := make([]string, 8)
	for i := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if paths[i], err = st.VMDisk(ctx, layers, build); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := builds.Load(); n != 1 {
		t.Fatalf("%d builds for one stack", n)
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err != nil || string(b) != "disk of a, b" {
			t.Fatalf("disk %s: %q %v", p, b, err)
		}
	}

	// A failed build leaves no disk and no lock; the next call builds.
	failing := func(string) error { return errors.New("mkfs failed") }
	if _, err := st.VMDisk(ctx, []string{b}, failing); err == nil {
		t.Fatal("a failed build succeeded")
	}
	if left, _ := filepath.Glob(filepath.Join(st.vmDiskDir(), VMDiskKey([]string{b})+".*")); len(left) != 1 { // its record
		t.Fatalf("after a failed build: %v", left)
	}
	if _, err := st.VMDisk(ctx, []string{b}, build); err != nil {
		t.Fatal(err)
	}

	// A lock without a builder: waited for, then taken over once stale.
	lock := filepath.Join(st.vmDiskDir(), VMDiskKey([]string{a})+".lock")
	os.WriteFile(lock, nil, 0o644)
	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	_, err = st.VMDisk(short, []string{a}, build)
	cancel()
	if err == nil {
		t.Fatal("did not wait for a held lock")
	}
	old := time.Now().Add(-vmDiskLockStale - time.Minute)
	os.Chtimes(lock, old, old)
	if _, err := st.VMDisk(ctx, []string{a}, build); err != nil {
		t.Fatalf("stale lock: %v", err)
	}
}

// TestVMDiskGC: a disk goes with any of its layers; others stay.
func TestVMDiskGC(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kept, dropped := NewDiffLayerID(), NewDiffLayerID()
	addLayer(t, st, kept)
	addLayer(t, st, dropped)
	if err := st.PutManifest(&Manifest{Name: "root/keep:1", Layers: []string{kept}}, false); err != nil {
		t.Fatal(err)
	}
	write := func(dst string) error { return os.WriteFile(dst, []byte("x"), 0o644) }
	keepDisk, _ := st.VMDisk(context.Background(), []string{kept}, write)
	goneDisk, _ := st.VMDisk(context.Background(), []string{kept, dropped}, write)
	old := time.Now().Add(-48 * time.Hour)
	ents, _ := os.ReadDir(st.vmDiskDir())
	for _, e := range ents {
		os.Chtimes(filepath.Join(st.vmDiskDir(), e.Name()), old, old)
	}
	os.Chtimes(filepath.Join(st.layerDir(dropped), "meta.json"), old, old)
	res, err := st.GC(24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Layers) != 1 || res.Layers[0] != dropped || len(res.VMDisks) != 2 {
		t.Fatalf("gc: layers %v disks %v", res.Layers, res.VMDisks)
	}
	if _, err := os.Stat(goneDisk); err == nil {
		t.Error("the disk of a removed layer survived")
	}
	if _, err := os.Stat(keepDisk); err != nil {
		t.Errorf("a kept disk went: %v", err)
	}
}
