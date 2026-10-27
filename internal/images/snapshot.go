package images

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Snapshot is a saved sandbox (spec §19): the layer stack it ran on plus its
// writable layer, frozen at one instant, and (microvm, later phases) its
// memory. Forks start their copies from a snapshot, and CreateSnapshot names
// one as an image. Snapshots are immutable; they live at
//
//	<root>/snapshots/<id>/snapshot.json
type Snapshot struct {
	ID string `json:"id"`
	// Base is the edge-local image under Layers, for sandboxes started from
	// a static image ("host" in development); empty for store images.
	Base      string            `json:"base,omitempty"`
	Layers    []string          `json:"layers"` // bottom first, the writable layer last
	Env       map[string]string `json:"env,omitempty"`
	Workdir   string            `json:"workdir,omitempty"`
	User      string            `json:"user,omitempty"`
	Memory    bool              `json:"memory,omitempty"`
	VM        *VMSnapshot       `json:"vm,omitempty"`     // microvm snapshots (files in the snapshot dir)
	Size      int64             `json:"size"`             // bytes the snapshot added (writable layer, memory)
	Image     string            `json:"image,omitempty"`  // the source sandbox's image
	Source    string            `json:"source,omitempty"` // the source sandbox
	CreatedAt float64           `json:"created_at"`
	// Publishing names the edge still copying the snapshot's files into
	// the store (spec §19.14): written on its node first, they are usable
	// there at once; other edges wait until it is empty.
	Publishing string `json:"publishing,omitempty"`
	// Holder names the edge keeping the files of an ephemeral snapshot,
	// never copied into the store: other edges fetch them from it (spec §26).
	Holder string `json:"holder,omitempty"`
	// Runtime holds the versions of the runtime that made it (e.g.
	// firecracker -> 1.17.0): memory snapshots restore only on edges running
	// the same (spec §28.12).
	Runtime map[string]string `json:"runtime,omitempty"`
}

// VMSnapshot describes a microVM snapshot (spec §19.3). Its directory holds
// the VM's disks as they were (VMDiskFile, and the read-only VMImageFile and
// VMAgentsFile it had mounted, which must be the same files to restore), and
// with Snapshot.Memory its state and memory (VMStateFile, VMMemFile).
// Sandboxes restored from it run with exactly MemMB and VCPUs.
type VMSnapshot struct {
	MemMB  int64 `json:"mem_mb"`
	VCPUs  int   `json:"vcpus"`
	DiskMB int64 `json:"disk_mb"`
}

const (
	VMStateFile  = "vmstate"
	VMMemFile    = "mem"
	VMDiskFile   = "disk.ext4"
	VMImageFile  = "image.ext4"
	VMAgentsFile = "agents.ext4"
)

var snapshotRe = regexp.MustCompile(`^snap-[a-z2-7]{24}$`)

func ValidSnapshotID(id string) bool { return snapshotRe.MatchString(id) }

// NewSnapshotID returns a fresh snapshot id.
func NewSnapshotID() string {
	var b [15]byte
	rand.Read(b[:])
	return "snap-" + strings.ToLower(idEnc.EncodeToString(b[:]))
}

func (s *Store) snapshotDir(id string) string { return filepath.Join(s.Root, "snapshots", id) }

// SnapshotDir is where a backend writes snapshot id's files before
// PutSnapshot records it.
func (s *Store) SnapshotDir(id string) (string, error) {
	if !ValidSnapshotID(id) {
		return "", rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", id)
	}
	d := s.snapshotDir(id)
	return d, os.MkdirAll(d, 0o755)
}

// DeleteSnapshot removes a snapshot and its files. Running sandboxes restored
// from it are unaffected (they hold their own links or mappings).
func (s *Store) DeleteSnapshot(id string) error {
	if !ValidSnapshotID(id) {
		return rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", id)
	}
	return os.RemoveAll(s.snapshotDir(id))
}

// PutSnapshot records snap; its layers must already be in the store.
func (s *Store) PutSnapshot(snap *Snapshot) error {
	if !ValidSnapshotID(snap.ID) {
		return rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", snap.ID)
	}
	s.touch(snap.Layers, "")
	for _, l := range snap.Layers {
		if !ValidLayerID(l) || !s.HasLayer(l) {
			return rpcutil.Err(rpcutil.NotFound, "layer %q (needed by snapshot %s) is not in the image store", l, snap.ID)
		}
	}
	if snap.CreatedAt == 0 {
		snap.CreatedAt = float64(time.Now().UnixNano()) / 1e9
	}
	dir := s.snapshotDir(snap.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "snapshot.json"), snap)
}

func (s *Store) GetSnapshot(id string) (*Snapshot, error) {
	if !ValidSnapshotID(id) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad snapshot id %q", id)
	}
	var snap Snapshot
	if err := readJSON(filepath.Join(s.snapshotDir(id), "snapshot.json"), &snap); err != nil {
		if os.IsNotExist(err) {
			return nil, rpcutil.Err(rpcutil.NotFound, "snapshot %s", id)
		}
		return nil, err
	}
	return &snap, nil
}

// SnapshotLowerdirs returns snap's store layers as overlay lowerdirs, topmost
// first (the caller appends Base's own lowerdirs, if any).
func (s *Store) SnapshotLowerdirs(snap *Snapshot) ([]string, error) {
	return s.Lowerdirs(&Manifest{Name: "snapshot " + snap.ID, Layers: snap.Layers})
}
