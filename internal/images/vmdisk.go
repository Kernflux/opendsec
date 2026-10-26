package images

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VM image disks (spec §29.4): a microVM runs its image from one read-only
// EROFS disk. The store keeps one per layer stack, built once by whichever
// edge first needs it, and each node copies it (one sequential read)
// instead of flattening the layers itself.
//
//	<root>/vmdisks/<key>.erofs   the disk
//	<root>/vmdisks/<key>.json    its layers (bottom first), for GC
//	<root>/vmdisks/<key>.lock    held while one edge builds it

// vmDiskFormat versions how disks are built (part of the key).
const vmDiskFormat = "erofs-4k-2m-1"

// vmDiskLockStale: a lock older than this is a builder that died.
const vmDiskLockStale = 30 * time.Minute

// VMDiskKey names the disk of a layer stack (bottom first).
func VMDiskKey(layers []string) string {
	h := sha256.Sum256([]byte(vmDiskFormat + "\n" + strings.Join(layers, "\n")))
	return "vd-" + hex.EncodeToString(h[:16])
}

func (s *Store) vmDiskDir() string { return filepath.Join(s.Root, "vmdisks") }

// VMDiskPath is where the disk of key lives (whether built or not).
func (s *Store) VMDiskPath(key string) string { return filepath.Join(s.vmDiskDir(), key+".erofs") }

// LayersOf maps overlay lowerdirs (topmost first) back to store layers
// (bottom first); ok is false if any is not a store layer.
func (s *Store) LayersOf(lower []string) (layers []string, ok bool) {
	for i := len(lower) - 1; i >= 0; i-- {
		rel, err := filepath.Rel(filepath.Join(s.Root, "layers"), lower[i])
		id, rootfs, found := strings.Cut(filepath.ToSlash(rel), "/")
		if err != nil || !found || rootfs != "rootfs" || !ValidLayerID(id) {
			return nil, false
		}
		layers = append(layers, id)
	}
	return layers, len(layers) > 0
}

// VMDisk returns the disk of layers, built by build (writing the disk to
// the path it is given) if no edge has built it yet. One edge builds at a
// time, under an exclusive lock file; the others wait for it, until ctx
// ends.
func (s *Store) VMDisk(ctx context.Context, layers []string, build func(dst string) error) (string, error) {
	key := VMDiskKey(layers)
	final := s.VMDiskPath(key)
	lock := filepath.Join(s.vmDiskDir(), key+".lock")
	if err := os.MkdirAll(s.vmDiskDir(), 0o755); err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(final); err == nil {
			return final, nil
		}
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			err := s.buildVMDisk(key, layers, final, build)
			os.Remove(lock)
			if err != nil {
				return "", err
			}
			return final, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if fi, err := os.Stat(lock); err == nil && time.Since(fi.ModTime()) > vmDiskLockStale {
			os.Remove(lock) // its builder died; take over
			continue
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for image disk %s: %w", key, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (s *Store) buildVMDisk(key string, layers []string, final string, build func(string) error) error {
	if err := writeJSON(filepath.Join(s.vmDiskDir(), key+".json"), layers); err != nil {
		return err
	}
	tmp := final + ".tmp-" + NewDiffLayerID()[5:13]
	defer os.Remove(tmp)
	if err := build(tmp); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// gcVMDisks lists disks (and their records) whose layers are not all kept,
// and leftovers of builds that died, older than cutoff.
func (s *Store) gcVMDisks(keep map[string]bool, cutoff time.Time) []string {
	ents, _ := os.ReadDir(s.vmDiskDir())
	var out []string
	for _, e := range ents {
		p := filepath.Join(s.vmDiskDir(), e.Name())
		fi, err := e.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		name := e.Name()
		switch {
		case strings.Contains(name, ".tmp-"):
			out = append(out, p)
		case strings.HasSuffix(name, ".erofs"):
			var layers []string
			if err := readJSON(strings.TrimSuffix(p, ".erofs")+".json", &layers); err != nil {
				if os.IsNotExist(err) {
					out = append(out, p) // no record: from a build that died
				}
				continue // unreadable: kept, as it may be in use
			}
			for _, l := range layers {
				if !keep[l] {
					out = append(out, p, strings.TrimSuffix(p, ".erofs")+".json")
					break
				}
			}
		}
	}
	return out
}
