// Package images is the shared image store (paper §4.1/§4.4, spec §17.2):
// immutable layers and image manifests on a filesystem every edge and
// apiserver mounts (3FS in the paper; CephFS, JuiceFS, NFS, ... here). Edges
// stack an image's layers directly from the store with overlayfs, so a
// sandbox reads only the files it touches (on-demand loading).
//
//	<root>/layers/<id>/rootfs/...   layer content, overlay format (whiteouts = 0:0 char devices)
//	<root>/layers/<id>/meta.json
//	<root>/images/<project>/<repo>/<tag>.json
//	<root>/snapshots/<id>/...       sandbox snapshots (snapshot.go)
package images

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Manifest describes an image: an ordered stack of layers plus defaults.
type Manifest struct {
	Name      string            `json:"name"`
	Layers    []string          `json:"layers"` // bottom first
	Env       map[string]string `json:"env,omitempty"`
	Workdir   string            `json:"workdir,omitempty"`
	User      string            `json:"user,omitempty"`
	Parent    string            `json:"parent,omitempty"` // pack_diff source image
	Source    string            `json:"source,omitempty"` // e.g. docker://python:3.12
	CreatedAt float64           `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	// Snapshot is set for images made by CreateSnapshot (spec §19); Memory
	// when that snapshot includes memory, so sandboxes resume from it.
	Snapshot string `json:"snapshot,omitempty"`
	Memory   bool   `json:"memory,omitempty"`
}

type LayerMeta struct {
	ID        string  `json:"id"`
	Size      int64   `json:"size"`
	Source    string  `json:"source,omitempty"`
	CreatedAt float64 `json:"created_at"`
	CreatedBy string  `json:"created_by,omitempty"`
}

var (
	layerRe   = regexp.MustCompile(`^(sha256-[0-9a-f]{64}|diff-[a-z2-7]{16,32}|opq-[0-9a-f]{32})$`)
	repoRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	idEnc     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// IsStoreName reports whether name refers to the shared store
// ("<project>/<repo>:<tag>") rather than an edge-local static image.
func IsStoreName(name string) bool { return strings.Contains(name, "/") }

// ParseName splits "root/rl/python:3.12" into project "root/rl", repo
// "python" and tag "3.12" (tag defaults to "latest").
func ParseName(name string) (project, repo, tag string, err error) {
	slash := strings.LastIndexByte(name, '/')
	if slash <= 0 {
		return "", "", "", rpcutil.Err(rpcutil.Invalid, "image name %q must be <project>/<repo>[:<tag>]", name)
	}
	project, rest := name[:slash], name[slash+1:]
	repo, tag, ok := strings.Cut(rest, ":")
	if !ok {
		tag = "latest"
	}
	for _, seg := range strings.Split(project, "/") {
		if !segmentRe.MatchString(seg) {
			return "", "", "", rpcutil.Err(rpcutil.Invalid, "bad project %q in image name %q", project, name)
		}
	}
	if !repoRe.MatchString(repo) || !tagRe.MatchString(tag) {
		return "", "", "", rpcutil.Err(rpcutil.Invalid, "bad repo or tag in image name %q", name)
	}
	return project, repo, tag, nil
}

// Canonical returns name with an explicit tag.
func Canonical(name string) (string, error) {
	p, r, t, err := ParseName(name)
	if err != nil {
		return "", err
	}
	return p + "/" + r + ":" + t, nil
}

func ValidLayerID(id string) bool { return layerRe.MatchString(id) }

// NewDiffLayerID returns a fresh id for a pack_diff layer.
func NewDiffLayerID() string {
	var b [15]byte
	rand.Read(b[:])
	return "diff-" + strings.ToLower(idEnc.EncodeToString(b[:]))
}

// DefaultScrub lists paths removed from a writable layer before packing, so
// build-time residue never ships in an image (spec §17.4).
var DefaultScrub = []string{"tmp/*", "var/tmp/*", "root/.cache", "root/.bash_history", "home/*/.bash_history",
	"root/.python_history", ".opendsec"}

// ValidScrub checks a scrub pattern: a relative glob (filepath.Match) inside
// the layer, clean, without "..".
func ValidScrub(pat string) error {
	if pat == "" || filepath.IsAbs(pat) || filepath.Clean(pat) != pat || pat == "." || strings.ContainsRune(pat, 0) ||
		slices.Contains(strings.Split(pat, "/"), "..") {
		return rpcutil.Err(rpcutil.Invalid, "scrub %q: a relative path inside the image, without ..", pat)
	}
	if _, err := filepath.Match(pat, ""); err != nil {
		return rpcutil.Err(rpcutil.Invalid, "scrub %q: %v", pat, err)
	}
	return nil
}

// scrubPath removes what the pattern's components match under dir, one
// directory level each, never through a symbolic link: the layer is the
// sandbox's, and a link in it (tmp -> /) points into the host, where this
// runs as root.
func scrubPath(dir string, parts []string) {
	ents, err := os.ReadDir(dir) // dir is a directory, not a link (checked by the caller)
	if err != nil {
		return
	}
	for _, e := range ents {
		if ok, _ := filepath.Match(parts[0], e.Name()); !ok {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if len(parts) == 1 {
			os.RemoveAll(p) // a link itself, not what it points to
		} else if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			scrubPath(p, parts[1:])
		}
	}
}

type Store struct {
	Root string

	mu    sync.Mutex
	cache map[string]*Manifest // manifests are immutable once written (unless overwritten)
}

func NewStore(root string) (*Store, error) {
	for _, d := range []string{"layers", "images"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{Root: root, cache: map[string]*Manifest{}}, nil
}

func (s *Store) layerDir(id string) string { return filepath.Join(s.Root, "layers", id) }

// LayerRootfs is the directory overlayfs uses as the layer's lowerdir.
func (s *Store) LayerRootfs(id string) string { return filepath.Join(s.layerDir(id), "rootfs") }

func (s *Store) HasLayer(id string) bool {
	_, err := os.Stat(filepath.Join(s.layerDir(id), "meta.json"))
	return err == nil
}

func (s *Store) LayerMeta(id string) (*LayerMeta, error) {
	var m LayerMeta
	if err := readJSON(filepath.Join(s.layerDir(id), "meta.json"), &m); err != nil {
		if os.IsNotExist(err) {
			return nil, rpcutil.Err(rpcutil.NotFound, "layer %s", id)
		}
		return nil, err
	}
	return &m, nil
}

// LayerWriter stages a new layer; Commit publishes it atomically.
type LayerWriter struct {
	s       *Store
	id, tmp string
	Rootfs  string // write the layer's files here
}

// BeginLayer starts staging layer id. If the layer already exists (same
// content digest), exists is true and nothing needs to be written.
func (s *Store) BeginLayer(id string) (w *LayerWriter, exists bool, err error) {
	if !ValidLayerID(id) {
		return nil, false, rpcutil.Err(rpcutil.Invalid, "bad layer id %q", id)
	}
	if s.HasLayer(id) {
		// Used again: young again for GC (spec §24).
		now := time.Now()
		os.Chtimes(filepath.Join(s.layerDir(id), "meta.json"), now, now)
		return nil, true, nil
	}
	tmp := s.layerDir(id) + ".tmp-" + NewDiffLayerID()[5:13]
	if err := os.MkdirAll(filepath.Join(tmp, "rootfs"), 0o755); err != nil {
		return nil, false, err
	}
	return &LayerWriter{s: s, id: id, tmp: tmp, Rootfs: filepath.Join(tmp, "rootfs")}, false, nil
}

// Commit records meta and moves the staged layer into place. A concurrent
// publisher of the same id wins harmlessly (layers are immutable).
func (w *LayerWriter) Commit(meta LayerMeta) (*LayerMeta, error) {
	meta.ID = w.id
	if meta.CreatedAt == 0 {
		meta.CreatedAt = float64(time.Now().UnixNano()) / 1e9
	}
	if meta.Size == 0 {
		meta.Size = du(w.Rootfs)
	}
	if err := writeJSON(filepath.Join(w.tmp, "meta.json"), meta); err != nil {
		w.Abort()
		return nil, err
	}
	if err := os.Rename(w.tmp, w.s.layerDir(w.id)); err != nil {
		w.Abort()
		if w.s.HasLayer(w.id) {
			return w.s.LayerMeta(w.id)
		}
		return nil, err
	}
	return &meta, nil
}

func (w *LayerWriter) Abort() { os.RemoveAll(w.tmp) }

// PublishLayerDir publishes a copy of src, an overlay upper dir over lower
// (lowerdirs, topmost first), as layer id, minus scrub patterns (relative
// globs). Whiteouts, owners and hard links are preserved (cp -a); opaque
// directories are expanded over lower (spec §29.5).
func (s *Store) PublishLayerDir(id, src string, lower []string, scrub []string, meta LayerMeta) (*LayerMeta, error) {
	for _, pat := range scrub {
		if err := ValidScrub(pat); err != nil {
			return nil, err
		}
	}
	w, exists, err := s.BeginLayer(id)
	if err != nil {
		return nil, err
	}
	if exists {
		return s.LayerMeta(id)
	}
	if out, err := exec.Command("cp", "-a", "--", strings.TrimSuffix(src, "/")+"/.", w.Rootfs+"/").CombinedOutput(); err != nil {
		w.Abort()
		return nil, fmt.Errorf("copy layer: %v: %s", err, out)
	}
	for _, pat := range scrub {
		scrubPath(w.Rootfs, strings.Split(pat, "/"))
	}
	if dirs := opaqueDirs(src); len(dirs) > 0 {
		if err := expandOpaque(w.Rootfs, dirs, lower); err != nil {
			w.Abort()
			return nil, fmt.Errorf("opaque directories: %w", err)
		}
	}
	return w.Commit(meta)
}

// ---- manifests -------------------------------------------------------------------

func (s *Store) manifestPath(name string) (string, error) {
	p, r, t, err := ParseName(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.Root, "images", filepath.FromSlash(p), r, t+".json"), nil
}

// PutManifest validates and writes m. Existing names are only replaced with overwrite.
func (s *Store) PutManifest(m *Manifest, overwrite bool) error {
	name, err := Canonical(m.Name)
	if err != nil {
		return err
	}
	m.Name = name
	if len(m.Layers) == 0 {
		return rpcutil.Err(rpcutil.Invalid, "image %s has no layers", name)
	}
	if len(m.Layers) > 125 { // overlayfs supports at most ~500 lowerdirs; keep stacks shallow
		return rpcutil.Err(rpcutil.Invalid, "image %s has %d layers (max 125)", name, len(m.Layers))
	}
	s.touch(m.Layers, m.Snapshot)
	for _, l := range m.Layers {
		if !ValidLayerID(l) || !s.HasLayer(l) {
			return rpcutil.Err(rpcutil.NotFound, "layer %q (needed by %s) is not in the image store", l, name)
		}
	}
	if m.CreatedAt == 0 {
		m.CreatedAt = float64(time.Now().UnixNano()) / 1e9
	}
	path, _ := s.manifestPath(name)
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Without overwrite, the name is taken atomically: of two at once, one fails.
	if err := writeJSONAs(path, m, overwrite); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
		return err
	}
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
	return nil
}

// GetManifest reads an image manifest (cached: only overwrite changes it).
func (s *Store) GetManifest(name string) (*Manifest, error) {
	name, err := Canonical(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if m, ok := s.cache[name]; ok {
		s.mu.Unlock()
		return m, nil
	}
	s.mu.Unlock()
	path, _ := s.manifestPath(name)
	var m Manifest
	if err := readJSON(path, &m); err != nil {
		if os.IsNotExist(err) {
			return nil, rpcutil.Err(rpcutil.NotFound, "image %s", name)
		}
		return nil, err
	}
	s.mu.Lock()
	s.cache[name] = &m
	s.mu.Unlock()
	return &m, nil
}

// Refresh drops a cached manifest (e.g. after another apiserver overwrote it).
func (s *Store) Refresh(name string) {
	if n, err := Canonical(name); err == nil {
		s.mu.Lock()
		delete(s.cache, n)
		s.mu.Unlock()
	}
}

// DeleteManifest removes an image name; its layers stay until garbage-collected.
func (s *Store) DeleteManifest(name string) error {
	path, err := s.manifestPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return rpcutil.Err(rpcutil.NotFound, "image %s", name)
		}
		return err
	}
	s.Refresh(name)
	return nil
}

// List returns the manifests under project (and its subprojects).
func (s *Store) List(project string) ([]*Manifest, error) {
	return s.list(project, false)
}

// list is List; strict fails on a manifest it cannot read instead of
// skipping it (GC must not miss a reference).
func (s *Store) list(project string, strict bool) ([]*Manifest, error) {
	base := filepath.Join(s.Root, "images", filepath.FromSlash(project))
	var out []*Manifest
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		var m Manifest
		switch err := readJSON(p, &m); {
		case err == nil:
			out = append(out, &m)
		case strict && !errors.Is(err, fs.ErrNotExist): // removed meanwhile: fine
			return fmt.Errorf("image %s: %w", p, err)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// Lowerdirs returns m's layers as overlay lowerdirs, topmost first.
// lowerdirs maps layers (bottom first) to overlay lowerdirs (topmost first).
func (s *Store) lowerdirs(layers []string) []string {
	out := make([]string, 0, len(layers))
	for i := len(layers) - 1; i >= 0; i-- {
		out = append(out, s.LayerRootfs(layers[i]))
	}
	return out
}

func (s *Store) Lowerdirs(m *Manifest) ([]string, error) {
	out := make([]string, 0, len(m.Layers))
	for i := len(m.Layers) - 1; i >= 0; i-- {
		if !s.HasLayer(m.Layers[i]) {
			return nil, rpcutil.Err(rpcutil.NotFound, "layer %s of image %s is missing from the store", m.Layers[i], m.Name)
		}
		out = append(out, s.LayerRootfs(m.Layers[i]))
	}
	return out, nil
}

// ---- helpers ---------------------------------------------------------------------

func writeJSON(path string, v any) error { return writeJSONAs(path, v, true) }

// writeJSONAs writes v to path atomically; without replace, only if path
// does not exist (a link of the written file: fs.ErrExist if it does).
func writeJSONAs(path string, v any, replace bool) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp-" + NewDiffLayerID()[5:13]
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if replace {
		return os.Rename(tmp, path)
	}
	err = os.Link(tmp, path)
	os.Remove(tmp)
	return err
}

// touch marks the layers (and snapshot) a record about to be written
// names as used now: GC, which read the references before, checks again
// right before it removes anything, and keeps what was touched since.
func (s *Store) touch(layers []string, snapshot string) {
	now := time.Now()
	for _, l := range layers {
		os.Chtimes(filepath.Join(s.layerDir(l), "meta.json"), now, now)
	}
	if snapshot != "" && ValidSnapshotID(snapshot) {
		os.Chtimes(filepath.Join(s.snapshotDir(snapshot), "snapshot.json"), now, now)
	}
}

// readJSON reads a JSON file of the store. On a network filesystem (NFS)
// a file replaced by rename while being opened reads as ESTALE: open the
// new one.
func readJSON(path string, v any) error {
	var b []byte
	var err error
	for try := 0; try < 5; try++ {
		if b, err = os.ReadFile(path); !errors.Is(err, syscall.ESTALE) {
			break
		}
		time.Sleep(time.Duration(try+1) * 10 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func du(root string) int64 {
	var n int64
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}
