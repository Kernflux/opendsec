package images

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Garbage collection (spec §24). Layers and snapshots stay while anything
// can still need them: an image manifest, a snapshot record, or a running
// sandbox. Edges record the layers their container sandboxes stack on as
// in-use markers (<root>/inuse/<holder>, holder = the sandbox id), since a
// sandbox can outlive its image. Everything else older than the grace
// period goes: unreferenced layers, snapshots no image names (fork's are
// only needed while its copies start; VM copies hold links to the files),
// interrupted writes.

// gcScanned, if set, runs between GC's reading of the references and its
// removals (tests).
var gcScanned func()

func (s *Store) inuseDir() string { return filepath.Join(s.Root, "inuse") }

// MarkInUse records that holder runs on layers.
func (s *Store) MarkInUse(holder string, layers []string) error {
	if err := os.MkdirAll(s.inuseDir(), 0o755); err != nil {
		return err
	}
	s.touch(layers, "")
	return writeJSON(filepath.Join(s.inuseDir(), holder), layers)
}

// ReleaseInUse drops holder's marker.
func (s *Store) ReleaseInUse(holder string) {
	os.Remove(filepath.Join(s.inuseDir(), holder))
}

// InUseHolders lists the markers whose holder starts with prefix (an
// edge's sandboxes: "<edge>.").
func (s *Store) InUseHolders(prefix string) []string {
	ents, _ := os.ReadDir(s.inuseDir())
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// readDir is os.ReadDir for GC: a directory not made yet is empty, any other
// error stops it.
func readDir(dir string) ([]os.DirEntry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("gc stopped, nothing removed: %w", err)
	}
	return ents, nil
}

// GCResult lists what GC removed (or would remove, with dryRun).
type GCResult struct {
	Layers, Snapshots, Partial []string
	VMDisks                    []string // image disks of layer stacks no longer kept (spec §29.4)
	Bytes                      int64
}

// Refs are what garbage collection keeps, besides in-use markers: image
// manifests and snapshot records. They come from the image catalog
// (spec §42); FileRefs reads them from the store's own files.
type Refs struct {
	Images    []*Manifest
	Snapshots []*Snapshot
}

// FileRefs reads the references from the store's files: the manifests and
// snapshot records written there (the only ones before spec §42).
func (s *Store) FileRefs() (*Refs, error) {
	ms, err := s.list("", true)
	if err != nil {
		return nil, fmt.Errorf("gc stopped, nothing removed: %w", err)
	}
	snaps, err := s.ListSnapshots(true)
	if err != nil {
		return nil, fmt.Errorf("gc stopped, nothing removed: %w", err)
	}
	return &Refs{Images: ms, Snapshots: snaps}, nil
}

// GC is GCRefs with the references in the store's files.
func (s *Store) GC(grace time.Duration, dryRun bool) (*GCResult, error) {
	refs, err := s.FileRefs()
	if err != nil {
		return nil, err
	}
	return s.GCRefs(refs, grace, dryRun, nil)
}

// GCRefs removes what nothing references and is older than grace. A
// reference it cannot read (a shared store failing for a moment) stops it
// before it removes anything: what it missed might be the only reference
// to a layer. Snapshots it removes are first dropped from the catalog with
// forget (nil: their records are only the store's files).
func (s *Store) GCRefs(refs *Refs, grace time.Duration, dryRun bool, forget func(ids []string) error) (*GCResult, error) {
	keepLayers, keepSnaps := map[string]bool{}, map[string]bool{}
	for _, m := range refs.Images {
		for _, l := range m.Layers {
			keepLayers[l] = true
		}
		if m.Snapshot != "" {
			keepSnaps[m.Snapshot] = true
		}
	}
	recorded := map[string]*Snapshot{}
	for _, snap := range refs.Snapshots {
		recorded[snap.ID] = snap
	}
	cutoff := time.Now().Add(-grace)
	old := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.ModTime().Before(cutoff)
	}
	res := &GCResult{}
	snaps, err := readDir(filepath.Join(s.Root, "snapshots"))
	if err != nil {
		return nil, err
	}
	withFiles := map[string]bool{}
	for _, e := range snaps {
		id := e.Name()
		p := filepath.Join(s.Root, "snapshots", id)
		if !ValidSnapshotID(id) {
			if old(p) {
				res.Partial = append(res.Partial, p)
			}
			continue
		}
		withFiles[id] = true
		snap := recorded[id]
		if snap == nil {
			if old(p) { // files without a record: an interrupted snapshot
				res.Partial = append(res.Partial, p)
			}
			continue
		}
		since := filepath.Join(p, "snapshot.json")
		if _, err := os.Stat(since); err != nil {
			since = p
		}
		if keepSnaps[id] || !old(since) {
			for _, l := range snap.Layers {
				keepLayers[l] = true
			}
			continue
		}
		res.Snapshots = append(res.Snapshots, id)
		res.Bytes += du(p)
	}
	// Records without files in the store (held by an edge, spec §26, or
	// files removed): dropped from the catalog once old and unnamed.
	for id, snap := range recorded {
		if withFiles[id] {
			continue
		}
		created := time.Unix(0, int64(snap.CreatedAt*1e9))
		if keepSnaps[id] || !created.Before(cutoff) {
			for _, l := range snap.Layers {
				keepLayers[l] = true
			}
			continue
		}
		res.Snapshots = append(res.Snapshots, id)
	}
	ents, err := readDir(s.inuseDir())
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			continue // being written; the marker it becomes is read next time
		}
		var layers []string
		switch err := readJSON(filepath.Join(s.inuseDir(), e.Name()), &layers); {
		case err == nil:
			for _, l := range layers {
				keepLayers[l] = true
			}
		case !os.IsNotExist(err): // released meanwhile: fine
			return nil, fmt.Errorf("gc stopped, nothing removed: in-use marker %s: %w", e.Name(), err)
		}
	}
	layers, err := readDir(filepath.Join(s.Root, "layers"))
	if err != nil {
		return nil, err
	}
	for _, e := range layers {
		id := e.Name()
		p := s.layerDir(id)
		if !ValidLayerID(id) {
			if strings.Contains(id, ".tmp-") && old(p) {
				res.Partial = append(res.Partial, p)
			}
			continue
		}
		if keepLayers[id] || !old(filepath.Join(p, "meta.json")) {
			continue
		}
		res.Layers = append(res.Layers, id)
		res.Bytes += du(p)
	}
	// Disks of layer stacks some layer of which goes: nothing can run them.
	keepAll := map[string]bool{}
	for _, e := range layers {
		if id := e.Name(); ValidLayerID(id) && !slices.Contains(res.Layers, id) {
			keepAll[id] = true
		}
	}
	for _, p := range s.gcVMDisks(keepAll, cutoff) {
		res.VMDisks = append(res.VMDisks, p)
		if fi, err := os.Stat(p); err == nil {
			res.Bytes += fi.Size()
		}
	}
	if dryRun {
		return res, nil
	}
	if gcScanned != nil {
		gcScanned()
	}
	// What a record written since the references were read names was
	// touched (Store.touch): checked again here, it stays, with a kept
	// snapshot's layers.
	revived := map[string]bool{}
	var snapsGone []string
	for _, id := range res.Snapshots {
		if withFiles[id] && !old(filepath.Join(s.snapshotDir(id), "snapshot.json")) {
			for _, l := range recorded[id].Layers {
				revived[l] = true
			}
			continue
		}
		snapsGone = append(snapsGone, id)
	}
	// The records go first: files without a record are removed by a later
	// run, a record without files would name a snapshot nobody can start.
	if forget != nil && len(snapsGone) > 0 {
		if err := forget(snapsGone); err != nil {
			return res, fmt.Errorf("gc stopped, no snapshot removed: dropping their records: %w", err)
		}
	}
	for _, id := range snapsGone {
		if !withFiles[id] {
			continue
		}
		if err := s.DeleteSnapshot(id); err != nil {
			return res, fmt.Errorf("snapshot %s: %w", id, err)
		}
	}
	res.Snapshots = snapsGone
	var layersGone []string
	for _, id := range res.Layers {
		if revived[id] || !old(filepath.Join(s.layerDir(id), "meta.json")) {
			continue
		}
		layersGone = append(layersGone, id)
		// Rename first: a reader never sees half a layer.
		tmp := s.layerDir(id) + ".tmp-gc"
		if err := os.Rename(s.layerDir(id), tmp); err != nil {
			return res, fmt.Errorf("layer %s: %w", id, err)
		}
		os.RemoveAll(tmp)
	}
	res.Layers = layersGone
	for _, p := range res.Partial {
		os.RemoveAll(p)
	}
	for _, p := range res.VMDisks {
		os.Remove(p)
	}
	return res, nil
}
