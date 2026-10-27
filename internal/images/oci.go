package images

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

// Reference is a parsed registry image reference.
type Reference struct {
	Registry string // host[:port]
	Repo     string // e.g. library/python
	Ref      string // tag or digest
}

// ParseReference parses "docker://python:3.12", "ghcr.io/org/img:tag",
// "localhost:5000/x/y@sha256:...". Docker Hub is the default registry, and
// its names docker.io and index.docker.io mean it too (its API is served
// from registry-1.docker.io; docker.io itself is the web site).
func ParseReference(s string) (Reference, error) {
	s = strings.TrimPrefix(s, "docker://")
	r := Reference{Registry: "registry-1.docker.io"}
	if i := strings.IndexByte(s, '/'); i > 0 {
		if first := s[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			r.Registry, s = first, s[i+1:]
		}
	}
	if r.Registry == "docker.io" || r.Registry == "index.docker.io" {
		r.Registry = "registry-1.docker.io"
	}
	switch {
	case strings.Contains(s, "@"):
		// name:tag@digest: the digest decides, as in docker.
		r.Repo, r.Ref, _ = strings.Cut(s, "@")
		if i := strings.LastIndexByte(r.Repo, ':'); i > strings.LastIndexByte(r.Repo, '/') {
			r.Repo = r.Repo[:i]
		}
	default:
		r.Repo, r.Ref = s, "latest"
		if i := strings.LastIndexByte(s, ':'); i > strings.LastIndexByte(s, '/') {
			r.Repo, r.Ref = s[:i], s[i+1:]
		}
	}
	if r.Repo == "" || r.Ref == "" {
		return r, fmt.Errorf("bad image reference %q", s)
	}
	if r.Registry == "registry-1.docker.io" && !strings.Contains(r.Repo, "/") {
		r.Repo = "library/" + r.Repo
	}
	return r, nil
}

// ImportResult is what a pull produced.
type ImportResult struct {
	Layers  []string // bottom first
	Env     map[string]string
	Workdir string
	User    string
	Source  string
	Pulled  int // layers downloaded (the rest were already in the store)
}

type Puller struct {
	Store     *Store
	Client    *http.Client
	PlainHTTP bool // registries without TLS (tests, local mirrors)
	Platform  string
	Log       func(format string, args ...any)
	// Creds log in to the registry pulled from; nil: anonymous.
	Creds *Credentials

	token string
	basic bool // the registry wants Basic auth on every request
}

const (
	mtOCIIndex   = "application/vnd.oci.image.index.v1+json"
	mtDockerList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIMan     = "application/vnd.oci.image.manifest.v1+json"
	mtDockerMan  = "application/vnd.docker.distribution.manifest.v2+json"
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"` // index / list
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
}

// source serves an image's manifests and blobs: a registry (Pull), or an
// archive on disk (Import, spec §38).
type source interface {
	// manifest returns the raw manifest or index named by a tag or digest.
	manifest(ctx context.Context, ref string) ([]byte, error)
	blob(ctx context.Context, digest string) (io.ReadCloser, error)
}

// registry is a source pulling ref's repository from its registry.
type registry struct {
	p   *Puller
	ref Reference
}

const manifestAccept = mtOCIIndex + ", " + mtDockerList + ", " + mtOCIMan + ", " + mtDockerMan

func (r registry) manifest(ctx context.Context, ref string) ([]byte, error) {
	resp, err := r.p.get(ctx, r.ref, "manifests/"+ref, manifestAccept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func (r registry) blob(ctx context.Context, digest string) (io.ReadCloser, error) {
	resp, err := r.p.get(ctx, r.ref, "blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (p *Puller) init() {
	if p.Client == nil {
		p.Client = &http.Client{Timeout: 30 * time.Minute}
	}
	c := *p.Client
	c.CheckRedirect = noAuthElsewhere
	p.Client = &c
	if p.Platform == "" {
		p.Platform = "linux/" + runtime.GOARCH
	}
	if p.Log == nil {
		p.Log = func(string, ...any) {}
	}
}

// Pull downloads ref into the store (layers already present are skipped)
// and returns the layer stack and image defaults.
func (p *Puller) Pull(ctx context.Context, refStr string) (*ImportResult, error) {
	ref, err := ParseReference(refStr)
	if err != nil {
		return nil, err
	}
	p.init()
	src := registry{p, ref}
	top, err := src.manifest(ctx, ref.Ref)
	if err != nil {
		return nil, err
	}
	return p.load(ctx, src, top, refStr, "docker://"+ref.Registry+"/"+ref.Repo+":"+ref.Ref)
}

// resolve returns the image manifest for p's platform from top, a
// manifest or an index (multi-platform), and its raw bytes.
func (p *Puller) resolve(ctx context.Context, src source, top []byte, name string) (manifestDoc, []byte, error) {
	var man manifestDoc
	if err := json.Unmarshal(top, &man); err != nil {
		return man, nil, fmt.Errorf("%s: manifest: %w", name, err)
	}
	if len(man.Manifests) == 0 {
		return man, top, nil
	}
	var pick *descriptor
	for i, d := range man.Manifests {
		if d.Platform != nil && d.Platform.OS+"/"+d.Platform.Architecture == p.Platform {
			pick = &man.Manifests[i]
			break
		}
	}
	if pick == nil {
		return man, nil, fmt.Errorf("%s has no %s image", name, p.Platform)
	}
	raw, err := src.manifest(ctx, pick.Digest)
	if err != nil {
		return man, nil, err
	}
	if err := verifyDigest(raw, pick.Digest); err != nil {
		return man, nil, fmt.Errorf("%s: manifest %w", name, err)
	}
	man = manifestDoc{}
	if err := json.Unmarshal(raw, &man); err != nil {
		return man, nil, fmt.Errorf("%s: manifest: %w", name, err)
	}
	return man, raw, nil
}

func verifyDigest(b []byte, digest string) error {
	h := sha256.Sum256(b)
	if got := "sha256:" + hex.EncodeToString(h[:]); got != digest {
		return fmt.Errorf("digest mismatch: got %s, want %s", got, digest)
	}
	return nil
}

// readBlob reads a small blob (an image config), checking its digest.
func readBlob(ctx context.Context, src source, digest string) ([]byte, error) {
	rc, err := src.blob(ctx, digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 16<<20))
	if err != nil {
		return nil, err
	}
	return b, verifyDigest(b, digest)
}

// load stores the image top names (for p's platform) from src.
func (p *Puller) load(ctx context.Context, src source, top []byte, name, sourceName string) (*ImportResult, error) {
	man, _, err := p.resolve(ctx, src, top, name)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Config struct {
			Env        []string `json:"Env"`
			WorkingDir string   `json:"WorkingDir"`
			User       string   `json:"User"`
		} `json:"config"`
	}
	b, err := readBlob(ctx, src, man.Config.Digest)
	if err == nil {
		err = json.Unmarshal(b, &cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	res := &ImportResult{Env: map[string]string{}, Workdir: cfg.Config.WorkingDir, User: cfg.Config.User, Source: sourceName}
	for _, kv := range cfg.Config.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			res.Env[k] = v
		}
	}
	for i, l := range man.Layers {
		hexd, ok := strings.CutPrefix(l.Digest, "sha256:")
		if !ok || len(hexd) != 64 {
			return nil, fmt.Errorf("layer %d: unsupported digest %q", i, l.Digest)
		}
		id := "sha256-" + hexd
		// A layer with opaque directories is kept expanded over the layers
		// beneath it (spec §29.5), under an id of its own for them.
		chain := OpaqueLayerID(hexd, res.Layers)
		if p.Store.HasLayer(chain) {
			p.Log("layer %d/%d %s: already in store", i+1, len(man.Layers), l.Digest[:19])
			res.Layers = append(res.Layers, chain)
			continue
		}
		w, exists, err := p.Store.BeginLayer(id)
		if err != nil {
			return nil, err
		}
		if exists {
			p.Log("layer %d/%d %s: already in store", i+1, len(man.Layers), l.Digest[:19])
			res.Layers = append(res.Layers, id)
			continue
		}
		p.Log("layer %d/%d %s: unpacking %d bytes", i+1, len(man.Layers), l.Digest[:19], l.Size)
		opaque, err := p.pullLayer(ctx, src, l, w.Rootfs)
		if err != nil {
			w.Abort()
			return nil, fmt.Errorf("layer %s: %w", l.Digest, err)
		}
		if len(opaque) > 0 {
			if err := expandOpaque(w.Rootfs, opaque, p.Store.lowerdirs(res.Layers)); err != nil {
				w.Abort()
				return nil, fmt.Errorf("layer %s: opaque directories: %w", l.Digest, err)
			}
			w.id, id = chain, chain
		}
		res.Layers = append(res.Layers, id)
		if _, err := w.Commit(LayerMeta{Source: res.Source}); err != nil {
			return nil, err
		}
		res.Pulled++
	}
	return res, nil
}

func (p *Puller) url(ref Reference, rest string) string {
	scheme := "https"
	if p.PlainHTTP {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/v2/%s/%s", scheme, ref.Registry, ref.Repo, rest)
}

// get performs an authenticated GET, handling the registry token challenge.
func (p *Puller) get(ctx context.Context, ref Reference, rest, accept string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url(ref, rest), nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if p.basic {
			req.SetBasicAuth(p.Creds.Username, p.Creds.Password)
		} else if p.token != "" {
			req.Header.Set("Authorization", "Bearer "+p.token)
		}
		resp, err := p.Client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			chal := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if err := p.authenticate(ctx, ref, chal); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, p.denied(ref)
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %s: %s", rest, resp.Status, strings.TrimSpace(string(b)))
		}
		return resp, nil
	}
	return nil, p.denied(ref)
}

// noAuthElsewhere drops the credentials on a redirect away from the
// registry's host and port: blobs are often served from a CDN or an object
// store. Go's own rule keeps them for the same host name on another port,
// and for subdomains.
func noAuthElsewhere(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header.Del("Authorization")
	}
	return nil
}

// denied is the error for a registry refusing access to ref.
func (p *Puller) denied(ref Reference) error {
	if p.Creds.empty() {
		return fmt.Errorf("%s refused access to %s without credentials: for a private repository, "+
			"run docker login %s on this machine, or pass -username and -password-stdin", ref.Registry, ref.Repo, ref.Registry)
	}
	who := "the identity token"
	if p.Creds.IdentityToken == "" {
		who = fmt.Sprintf("user %q", p.Creds.Username)
	}
	return fmt.Errorf("%s refused access to %s for %s: check the credentials and the pull permission on the repository",
		ref.Registry, ref.Repo, who)
}

// authenticate answers a WWW-Authenticate challenge: Basic auth from now
// on, or a bearer token from the challenge's realm, with the credentials if
// any (anonymous otherwise).
func (p *Puller) authenticate(ctx context.Context, ref Reference, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	switch strings.ToLower(scheme) {
	case "basic":
		if p.Creds.empty() || p.Creds.IdentityToken != "" && p.Creds.Username == "" {
			return p.denied(ref)
		}
		p.basic = true
		return nil
	case "bearer":
	default:
		return fmt.Errorf("unsupported registry auth %q", challenge)
	}
	kv := map[string]string{}
	for _, part := range strings.Split(params, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		kv[k] = strings.Trim(v, `"`)
	}
	u, err := url.Parse(kv["realm"])
	if err != nil || kv["realm"] == "" {
		return fmt.Errorf("bad auth realm in %q", challenge)
	}
	q := u.Query()
	for _, k := range []string{"service", "scope"} {
		if kv[k] != "" {
			q.Set(k, kv[k])
		}
	}
	var req *http.Request
	if c := p.Creds; c != nil && c.IdentityToken != "" {
		// OAuth2 refresh-token grant, as docker does with an identity token.
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c.IdentityToken},
			"client_id": {"opendsec"}, "service": {kv["service"]}, "scope": {kv["scope"]}}
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		u.RawQuery = q.Encode()
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if !p.Creds.empty() {
			req.SetBasicAuth(p.Creds.Username, p.Creds.Password)
		}
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return p.denied(ref)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("registry token: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("auth token: %w", err)
	}
	p.token = tok.Token
	if p.token == "" {
		p.token = tok.AccessToken
	}
	if p.token == "" {
		return errors.New("registry token: none in the answer")
	}
	return nil
}

// OpaqueLayerID names layer digest hexd expanded over layers (spec §29.5).
func OpaqueLayerID(hexd string, layers []string) string {
	h := sha256.Sum256([]byte(hexd + "\n" + strings.Join(layers, "\n")))
	return "opq-" + hex.EncodeToString(h[:16])
}

// pullLayer extracts layer l into dst; it returns the layer's opaque
// directories (relative to dst).
func (p *Puller) pullLayer(ctx context.Context, src source, l descriptor, dst string) ([]string, error) {
	rc, err := src.blob(ctx, l.Digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	h := sha256.New()
	body := io.TeeReader(rc, h)
	var r io.Reader = body
	switch {
	case strings.HasSuffix(l.MediaType, "gzip") || l.MediaType == "":
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	case strings.HasSuffix(l.MediaType, "zstd"): // application/vnd.oci.image.layer.v1.tar+zstd
		zr, err := zstd.NewReader(body, zstd.WithDecoderConcurrency(4))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case strings.HasSuffix(l.MediaType, ".tar") || strings.HasSuffix(l.MediaType, "tar"):
	default:
		return nil, fmt.Errorf("unsupported layer media type %q", l.MediaType)
	}
	opaque, err := ExtractLayer(r, dst)
	if err != nil {
		return nil, err
	}
	io.Copy(io.Discard, body) // hash the full blob
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != l.Digest {
		return nil, fmt.Errorf("digest mismatch: got %s", got)
	}
	return opaque, nil
}

// ---- layer extraction -------------------------------------------------------------

// ExtractLayer unpacks an OCI layer tarball into root, converting OCI
// whiteouts to overlayfs format: ".wh.<name>" becomes a 0:0 character device
// <name>. The directories ".wh..wh..opq" marks opaque are returned
// (relative to root), not marked: no xattr survives on NFS, they are
// expanded over the layers beneath instead (spec §29.5).
//
// It refuses absolute paths and "..", never writes through a symlink (a
// malicious layer could otherwise plant "etc -> /" and then write
// "etc/passwd" on the host), and only hard-links to files inside root.
func ExtractLayer(r io.Reader, root string) ([]string, error) {
	tr := tar.NewReader(r)
	var opaque []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return opaque, nil
		}
		if err != nil {
			return nil, err
		}
		if err := extractEntry(tr, hdr, root, &opaque); err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
	}
}

var errUnsafePath = errors.New("unsafe path in layer")

// safeJoin returns root/name after checking that no existing component of
// its parent directory is a symlink. The final component is not checked.
func safeJoin(root, name string) (string, error) {
	if strings.Contains(name, "\x00") {
		return "", errUnsafePath
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", errUnsafePath
		}
	}
	clean := path.Clean("/" + name)
	if clean == "/" {
		return root, nil
	}
	cur := root
	segs := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for _, seg := range segs[:len(segs)-1] {
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			break // the rest will be created as directories
		}
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %s traverses a symlink", errUnsafePath, name)
		}
		if !st.IsDir() {
			return "", fmt.Errorf("%w: parent of %s is not a directory", errUnsafePath, name)
		}
	}
	return filepath.Join(root, clean), nil
}

func extractEntry(tr *tar.Reader, hdr *tar.Header, root string, opaque *[]string) error {
	dst, err := safeJoin(root, hdr.Name)
	if err != nil {
		return err
	}
	if dst == root {
		return nil
	}
	dir, base := filepath.Dir(dst), filepath.Base(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if wh, ok := strings.CutPrefix(base, ".wh."); ok {
		if wh == ".wh..opq" {
			rel, _ := filepath.Rel(root, dir)
			*opaque = append(*opaque, rel)
			return nil
		}
		target := filepath.Join(dir, wh)
		os.RemoveAll(target)
		return unix.Mknod(target, unix.S_IFCHR, 0)
	}
	mode := uint32(hdr.Mode & 0o7777)
	switch hdr.Typeflag {
	case tar.TypeDir:
		if st, err := os.Lstat(dst); err == nil && !st.IsDir() {
			os.Remove(dst)
		}
		if err := os.Mkdir(dst, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
		// os.FileMode keeps only the permission bits of a raw mode: sticky
		// (/tmp's 1777) and setgid go through setBits.
		if err := os.Chmod(dst, os.FileMode(mode&0o777)|setBits(mode)); err != nil {
			return err
		}
	case tar.TypeReg:
		os.RemoveAll(dst)
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	case tar.TypeSymlink:
		os.RemoveAll(dst)
		if err := os.Symlink(hdr.Linkname, dst); err != nil {
			return err
		}
	case tar.TypeLink:
		src, err := safeJoin(root, hdr.Linkname)
		if err != nil {
			return err
		}
		st, err := os.Lstat(src)
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%w: hard link target %s is not a regular file in the layer", errUnsafePath, hdr.Linkname)
		}
		os.RemoveAll(dst)
		if err := os.Link(src, dst); err != nil {
			return err
		}
		return nil // shares inode, owner and mode with its target
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		os.RemoveAll(dst)
		kind := map[byte]uint32{tar.TypeChar: unix.S_IFCHR, tar.TypeBlock: unix.S_IFBLK, tar.TypeFifo: unix.S_IFIFO}[hdr.Typeflag]
		if err := unix.Mknod(dst, kind|mode, int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))); err != nil {
			return err
		}
	default:
		return nil // e.g. PAX global headers: nothing to create
	}
	if err := os.Lchown(dst, hdr.Uid, hdr.Gid); err != nil && !os.IsPermission(err) {
		return err
	}
	if hdr.Typeflag != tar.TypeSymlink {
		// chmod after chown: chown clears setuid/setgid bits.
		if hdr.Typeflag != tar.TypeDir {
			os.Chmod(dst, os.FileMode(mode)|setBits(mode))
		}
		os.Chtimes(dst, hdr.ModTime, hdr.ModTime)
	}
	for k, v := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
			unix.Lsetxattr(dst, name, []byte(v), 0)
		}
	}
	return nil
}

// setBits maps tar's setuid/setgid/sticky bits onto os.FileMode.
func setBits(mode uint32) os.FileMode {
	var m os.FileMode
	if mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}
