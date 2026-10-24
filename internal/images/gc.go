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

func (s *Store) inuseDir() string { return filepath.Join(s.Root, "inuse") }

// MarkInUse records that holder runs on layers.
func (s *Store) MarkInUse(holder string, layers []string) error {
	if err := os.MkdirAll(s.inuseDir(), 0o755); err != nil {
		return err
	}
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

// GCResult lists what GC removed (or would remove, with dryRun).
type GCResult struct {
	Layers, Snapshots, Partial []string
	VMDisks                    []string // image disks of layer stacks no longer kept (spec §29.4)
	Bytes                      int64
}

// GC removes what nothing references and is older than grace.
func (s *Store) GC(grace time.Duration, dryRun bool) (*GCResult, error) {
	keepLayers, keepSnaps := map[string]bool{}, map[string]bool{}
	ms, err := s.List("")
	if err != nil {
		return nil, err
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
	snaps, _ := os.ReadDir(filepath.Join(s.Root, "snapshots"))
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
	ents, _ := os.ReadDir(s.inuseDir())
	for _, e := range ents {
		var layers []string
		if readJSON(filepath.Join(s.inuseDir(), e.Name()), &layers) == nil {
			for _, l := range layers {
				keepLayers[l] = true
			}
		}
	}
	layers, _ := os.ReadDir(filepath.Join(s.Root, "layers"))
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
	for _, id := range res.Snapshots {
		if err := s.DeleteSnapshot(id); err != nil {
			return res, fmt.Errorf("snapshot %s: %w", id, err)
		}
	}
	for _, id := range res.Layers {
		// Rename first: a reader never sees half a layer.
		tmp := s.layerDir(id) + ".tmp-gc"
		if err := os.Rename(s.layerDir(id), tmp); err != nil {
			return res, fmt.Errorf("layer %s: %w", id, err)
		}
		os.RemoveAll(tmp)
	}
	for _, p := range res.Partial {
		os.RemoveAll(p)
	}
	for _, p := range res.VMDisks {
		os.Remove(p)
	}
	return res, nil
}
