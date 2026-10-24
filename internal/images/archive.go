package images

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Images as files (spec §38), for machines without a registry: Import reads
// an OCI image layout (a directory, or a tar of one: skopeo's oci-archive,
// `docker save` of Docker 25 and later) or an older `docker save` archive;
// Save writes a registry's image as an OCI layout tar. Offline installs
// carry their base images this way.

// archive is a source over the files of an image archive.
type archive struct {
	open  func(name string) (io.ReadCloser, error)
	blobs map[string]string // digest -> file, for `docker save` archives
	close func() error
}

func (a *archive) blob(_ context.Context, digest string) (io.ReadCloser, error) {
	if name, ok := a.blobs[digest]; ok {
		return a.open(name)
	}
	hexd, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexd) != 64 {
		return nil, fmt.Errorf("unsupported digest %q", digest)
	}
	if _, err := hex.DecodeString(hexd); err != nil {
		return nil, fmt.Errorf("bad digest %q", digest)
	}
	return a.open("blobs/sha256/" + hexd)
}

func (a *archive) manifest(ctx context.Context, digest string) ([]byte, error) {
	rc, err := a.blob(ctx, digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 16<<20))
}

func (a *archive) readAll(name string) ([]byte, error) {
	rc, err := a.open(name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 64<<20))
}

// openArchive opens a directory or a tar file.
func openArchive(p string) (*archive, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return &archive{
			open: func(name string) (io.ReadCloser, error) {
				if !validName(name) {
					return nil, fmt.Errorf("bad path %q in archive", name)
				}
				f, err := os.Open(filepath.Join(p, filepath.FromSlash(name)))
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("%s: no %s", p, name)
				}
				return f, err
			},
			close: func() error { return nil },
		}, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	if n, _ := f.ReadAt(magic[:], 0); n >= 2 && (magic[0] == 0x1f && magic[1] == 0x8b || n == 4 && bytes.Equal(magic[:], []byte{0x28, 0xb5, 0x2f, 0xfd})) {
		f.Close()
		return nil, fmt.Errorf("%s is compressed: decompress it first (gunzip, zstd -d), an image archive is read in place", p)
	}
	// Index the tar: each regular file's offset and size, read in place.
	type entry struct{ off, size int64 }
	files := map[string]entry{}
	cr := &countingReader{r: f}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: not a tar archive: %w", p, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			files[path.Clean(strings.TrimPrefix(hdr.Name, "./"))] = entry{cr.n, hdr.Size}
		}
	}
	return &archive{
		open: func(name string) (io.ReadCloser, error) {
			e, ok := files[path.Clean(name)]
			if !ok {
				return nil, fmt.Errorf("%s: no %s", p, name)
			}
			return io.NopCloser(io.NewSectionReader(f, e.off, e.size)), nil
		},
		close: f.Close,
	}, nil
}

func validName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "/") && path.Clean(name) == name && !strings.HasPrefix(name, "../") && name != ".."
}

// countingReader counts the bytes read: archive/tar reads exactly the
// headers, so after Next the count is the entry's data offset.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// IsArchive reports whether ref names an image archive on disk ("PATH" or
// "PATH#NAME") rather than an image in a registry.
func IsArchive(ref string) bool {
	p, _, _ := strings.Cut(ref, "#")
	_, err := os.Stat(p)
	return err == nil
}

// Import stores an image from the archive ref names: "PATH", or
// "PATH#NAME" to pick one of several images by name (as tagged when
// saved, e.g. python:3.12).
func (p *Puller) Import(ctx context.Context, ref string) (*ImportResult, error) {
	p.init()
	file, name, _ := strings.Cut(ref, "#")
	a, err := openArchive(file)
	if err != nil {
		return nil, err
	}
	defer a.close()
	top, label, err := a.top(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	abs, _ := filepath.Abs(file)
	return p.load(ctx, a, top, ref, "file://"+abs+"#"+label)
}

// top returns the manifest (or index) of the archive's image name ("" when
// it holds one image), and a label for it.
func (a *archive) top(ctx context.Context, name string) ([]byte, string, error) {
	if b, err := a.readAll("index.json"); err == nil {
		var idx struct {
			Manifests []struct {
				descriptor
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(b, &idx); err != nil {
			return nil, "", fmt.Errorf("index.json: %w", err)
		}
		var names []string
		for _, m := range idx.Manifests {
			label := m.Annotations["io.containerd.image.name"]
			if label == "" {
				label = m.Annotations["org.opencontainers.image.ref.name"]
			}
			names = append(names, label)
			if name != "" && !sameImage(name, m.Annotations["io.containerd.image.name"], m.Annotations["org.opencontainers.image.ref.name"]) {
				continue
			}
			if name == "" && len(idx.Manifests) > 1 {
				break
			}
			raw, err := a.manifest(ctx, m.Digest)
			if err != nil {
				return nil, "", err
			}
			if err := verifyDigest(raw, m.Digest); err != nil {
				return nil, "", fmt.Errorf("manifest %w", err)
			}
			return raw, cmpOr(label, m.Digest), nil
		}
		return nil, "", pickErr(name, names)
	}
	// `docker save` before Docker 25: manifest.json lists each image's
	// config and uncompressed layer files, whose digests are the config's
	// diff_ids.
	b, err := a.readAll("manifest.json")
	if err != nil {
		return nil, "", errors.New("neither an OCI image layout (index.json) nor a docker save archive (manifest.json)")
	}
	var images []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if err := json.Unmarshal(b, &images); err != nil {
		return nil, "", fmt.Errorf("manifest.json: %w", err)
	}
	var names []string
	for _, im := range images {
		names = append(names, strings.Join(im.RepoTags, ","))
		match := name == "" && len(images) == 1
		for _, t := range im.RepoTags {
			match = match || name != "" && sameImage(name, t)
		}
		if !match {
			continue
		}
		cfg, err := a.readAll(im.Config)
		if err != nil {
			return nil, "", err
		}
		var c struct {
			RootFS struct {
				DiffIDs []string `json:"diff_ids"`
			} `json:"rootfs"`
		}
		if err := json.Unmarshal(cfg, &c); err != nil {
			return nil, "", fmt.Errorf("image config: %w", err)
		}
		if len(c.RootFS.DiffIDs) != len(im.Layers) {
			return nil, "", fmt.Errorf("image config lists %d layers, manifest.json %d", len(c.RootFS.DiffIDs), len(im.Layers))
		}
		h := sha256.Sum256(cfg)
		cfgDigest := "sha256:" + hex.EncodeToString(h[:])
		a.blobs = map[string]string{cfgDigest: im.Config}
		man := manifestDoc{MediaType: mtDockerMan, Config: descriptor{Digest: cfgDigest, Size: int64(len(cfg))}}
		for i, l := range im.Layers {
			a.blobs[c.RootFS.DiffIDs[i]] = l
			man.Layers = append(man.Layers, descriptor{MediaType: "application/vnd.docker.image.rootfs.diff.tar", Digest: c.RootFS.DiffIDs[i]})
		}
		raw, _ := json.Marshal(man)
		label := cfgDigest
		if len(im.RepoTags) > 0 {
			label = im.RepoTags[0]
		}
		return raw, label, nil
	}
	return nil, "", pickErr(name, names)
}

func pickErr(name string, names []string) error {
	sort.Strings(names)
	if name == "" {
		return fmt.Errorf("it holds %d images (%s): pick one with PATH#NAME", len(names), strings.Join(names, " "))
	}
	return fmt.Errorf("no image %s in it (it holds: %s)", name, strings.Join(names, " "))
}

// sameImage reports whether name and one of the given names refer to the
// same image: equal, or the same once parsed (python:3.12 and
// docker.io/library/python:3.12), or name is a bare tag of an OCI
// ref.name annotation.
func sameImage(name string, others ...string) bool {
	want, werr := ParseReference(name)
	for _, o := range others {
		if o == "" {
			continue
		}
		if o == name {
			return true
		}
		if got, err := ParseReference(o); werr == nil && err == nil && got == want {
			return true
		}
	}
	return false
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Save writes ref's image for p's platform as an OCI image layout tar to w:
// what Import reads, on a machine without the registry.
func (p *Puller) Save(ctx context.Context, refStr string, w io.Writer) error {
	ref, err := ParseReference(refStr)
	if err != nil {
		return err
	}
	p.init()
	src := registry{p, ref}
	top, err := src.manifest(ctx, ref.Ref)
	if err != nil {
		return err
	}
	man, raw, err := p.resolve(ctx, src, top, refStr)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return err
	}
	for i, d := range append([]descriptor{man.Config}, man.Layers...) {
		hexd, ok := strings.CutPrefix(d.Digest, "sha256:")
		if !ok || len(hexd) != 64 {
			return fmt.Errorf("blob %d: unsupported digest %q", i, d.Digest)
		}
		if i > 0 {
			p.Log("layer %d/%d %s: %d bytes", i, len(man.Layers), d.Digest[:19], d.Size)
		}
		if d.Size <= 0 { // no size given (an image config): read it whole
			b, err := readBlob(ctx, src, d.Digest)
			if err == nil {
				err = put("blobs/sha256/"+hexd, b)
			}
			if err != nil {
				return fmt.Errorf("blob %s: %w", d.Digest, err)
			}
			continue
		}
		rc, err := src.blob(ctx, d.Digest)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: "blobs/sha256/" + hexd, Mode: 0o644, Size: d.Size, Typeflag: tar.TypeReg}); err != nil {
			rc.Close()
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, h), io.LimitReader(rc, d.Size+1))
		rc.Close()
		if err != nil {
			return fmt.Errorf("blob %s: %w", d.Digest, err)
		}
		if n != d.Size {
			return fmt.Errorf("blob %s: %d bytes, the manifest says %d", d.Digest, n, d.Size)
		}
		if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
			return fmt.Errorf("blob %s: digest mismatch: got %s", d.Digest, got)
		}
	}
	h := sha256.Sum256(raw)
	mdigest := "sha256:" + hex.EncodeToString(h[:])
	if err := put("blobs/sha256/"+hex.EncodeToString(h[:]), raw); err != nil {
		return err
	}
	mt := man.MediaType
	if mt == "" {
		mt = mtOCIMan
	}
	goos, arch, _ := strings.Cut(p.Platform, "/")
	idx := map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []any{map[string]any{
		"mediaType": mt, "digest": mdigest, "size": len(raw),
		"platform":    map[string]string{"os": goos, "architecture": arch},
		"annotations": map[string]string{"io.containerd.image.name": ref.Registry + "/" + ref.Repo + ":" + ref.Ref, "org.opencontainers.image.ref.name": ref.Ref},
	}}}
	b, _ := json.Marshal(idx)
	if err := put("index.json", b); err != nil {
		return err
	}
	return tw.Close()
}
