package images

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
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

// GC removes what nothing references and is older than grace. A reference
// it cannot read (a shared store failing for a moment) stops it before it
// removes anything: what it missed might be the only reference to a layer.
func (s *Store) GC(grace time.Duration, dryRun bool) (*GCResult, error) {
	keepLayers, keepSnaps := map[string]bool{}, map[string]bool{}
	ms, err := s.list("", true)
	if err != nil {
		return nil, fmt.Errorf("gc stopped, nothing removed: %w", err)
	}
	for _, m := range ms {
		for _, l := range m.Layers {
			keepLayers[l] = true
		}
		if m.Snapshot != "" {
			keepSnaps[m.Snapshot] = true
		}
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
	for _, e := range snaps {
		id := e.Name()
		p := filepath.Join(s.Root, "snapshots", id)
		if !ValidSnapshotID(id) {
			if old(p) {
				res.Partial = append(res.Partial, p)
			}
			continue
		}
		snap, err := s.GetSnapshot(id)
		if err != nil {
			if rpcutil.Reason(err) != rpcutil.NotFound {
				return nil, fmt.Errorf("gc stopped, nothing removed: snapshot %s: %w", id, err)
			}
			if old(p) { // files without a record: an interrupted snapshot
				res.Partial = append(res.Partial, p)
			}
			continue
		}
		if keepSnaps[id] || !old(filepath.Join(p, "snapshot.json")) {
			for _, l := range snap.Layers {
				keepLayers[l] = true
			}
			continue
		}
		res.Snapshots = append(res.Snapshots, id)
		res.Bytes += du(p)
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
		if !old(filepath.Join(s.snapshotDir(id), "snapshot.json")) {
			if snap, err := s.GetSnapshot(id); err == nil {
				for _, l := range snap.Layers {
					revived[l] = true
				}
			}
			continue
		}
		if err := s.DeleteSnapshot(id); err != nil {
			return res, fmt.Errorf("snapshot %s: %w", id, err)
		}
		snapsGone = append(snapsGone, id)
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
