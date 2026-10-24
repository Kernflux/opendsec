package images

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func mkLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// mkZstdLayer is mkLayer compressed with zstd instead of gzip.
func mkZstdLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(mkLayer(t, entries)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	if _, err := io.Copy(zw, gz); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func isZstd(b []byte) bool { return bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}) }

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// fakeRegistry serves one multi-platform image behind an anonymous
// bearer-token challenge.
func fakeRegistry(t *testing.T, layers [][]byte, config map[string]any) (*httptest.Server, *int) {
	return fakeRegistryAuth(t, layers, config, "anon")
}

// Credentials the private fake registries accept.
const (
	fakeUser    = "alice"
	fakePass    = "s3cret"
	fakeRefresh = "rt-1"
)

// fakeRegistryAuth serves one multi-platform image behind auth:
//   - "anon": a bearer-token challenge, tokens for anyone;
//   - "bearer": a bearer-token challenge, tokens for fakeUser:fakePass
//     (Basic auth at the token endpoint);
//   - "refresh": a bearer-token challenge, tokens for the OAuth2
//     refresh-token grant of fakeRefresh;
//   - "basic": Basic auth with fakeUser:fakePass on every request, and
//     layer blobs redirected to another host, which must see no
//     Authorization header.
func fakeRegistryAuth(t *testing.T, layers [][]byte, config map[string]any, auth string) (*httptest.Server, *int) {
	t.Helper()
	blobs := map[string][]byte{}
	cfgB, _ := json.Marshal(config)
	blobs[digest(cfgB)] = cfgB
	var layerDescs []map[string]any
	for _, l := range layers {
		blobs[digest(l)] = l
		mt := "application/vnd.oci.image.layer.v1.tar+gzip"
		if isZstd(l) {
			mt = "application/vnd.oci.image.layer.v1.tar+zstd"
		}
		layerDescs = append(layerDescs, map[string]any{"mediaType": mt, "digest": digest(l), "size": len(l)})
	}
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIMan,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(cfgB)}, "layers": layerDescs})
	blobs[digest(man)] = man
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []map[string]any{
		{"mediaType": mtOCIMan, "digest": "sha256:" + strings.Repeat("0", 64), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
		{"mediaType": mtOCIMan, "digest": digest(man), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
	}})
	pulls := 0
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("credentials sent to the blob host: %q", r.Header.Get("Authorization"))
		}
		pulls++
		w.Write(blobs[strings.TrimPrefix(r.URL.Path, "/")])
	}))
	t.Cleanup(cdn.Close)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			scope := r.URL.Query().Get("scope")
			switch auth {
			case "bearer":
				if u, p, ok := r.BasicAuth(); !ok || u != fakeUser || p != fakePass {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			case "refresh":
				r.ParseForm()
				if r.Method != http.MethodPost || r.PostForm.Get("grant_type") != "refresh_token" ||
					r.PostForm.Get("refresh_token") != fakeRefresh {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				scope = r.PostForm.Get("scope")
				json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-" + scope})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"token": "tok-" + scope})
			return
		}
		if auth == "basic" {
			if u, p, ok := r.BasicAuth(); !ok || u != fakeUser || p != fakePass {
				w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else if r.Header.Get("Authorization") != "Bearer tok-repository:test/app:pull" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="fake",scope="repository:test/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v2/test/app/")
		switch {
		case rest == "manifests/v1":
			w.Header().Set("Content-Type", mtOCIIndex)
			w.Write(index)
		case strings.HasPrefix(rest, "manifests/"):
			w.Write(blobs[strings.TrimPrefix(rest, "manifests/")])
		case strings.HasPrefix(rest, "blobs/"):
			b, ok := blobs[strings.TrimPrefix(rest, "blobs/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if len(b) > 0 && b[0] == 0x1f || isZstd(b) { // a layer
				if auth == "basic" {
					http.Redirect(w, r, cdn.URL+"/"+strings.TrimPrefix(rest, "blobs/"), http.StatusTemporaryRedirect)
					return
				}
				pulls++
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &pulls
}

func TestPullConvertsWhiteoutsAndDedups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("whiteout devices and overlay mounts need root")
	}
	base := mkLayer(t, []tarEntry{
		{name: "etc/", typ: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", body: "ID=test\n"},
		{name: "usr/bin/tool", body: "#!/bin/sh\necho tool\n", mode: 0o755},
		{name: "usr/bin/tool-alias", typ: tar.TypeLink, link: "usr/bin/tool"},
		{name: "usr/bin/sh-link", typ: tar.TypeSymlink, link: "/bin/sh"},
		{name: "var/cache/big", body: "remove me"},
		{name: "opt/data/old", body: "old"},
	})
	top := mkLayer(t, []tarEntry{
		{name: "var/cache/.wh.big"},
		{name: "opt/data/.wh..wh..opq"},
		{name: "opt/data/new", body: "new"},
		{name: "app/main.py", body: "print(1)\n"},
	})
	srv, pulls := fakeRegistry(t, [][]byte{base, top}, map[string]any{
		"config": map[string]any{"Env": []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, "WorkingDir": "/app", "User": "1000"}})
	s, _ := NewStore(t.TempDir())
	p := &Puller{Store: s, PlainHTTP: true, Platform: "linux/amd64"}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/app:v1"
	res, err := p.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Layers) != 2 || res.Pulled != 2 || res.Workdir != "/app" || res.User != "1000" || res.Env["LANG"] != "C.UTF-8" {
		t.Fatalf("result: %+v", res)
	}
	baseRoot, topRoot := s.LayerRootfs(res.Layers[0]), s.LayerRootfs(res.Layers[1])
	if b, _ := os.ReadFile(filepath.Join(baseRoot, "etc/os-release")); string(b) != "ID=test\n" {
		t.Fatal("file content")
	}
	var a, b unix.Stat_t
	unix.Stat(filepath.Join(baseRoot, "usr/bin/tool"), &a)
	unix.Stat(filepath.Join(baseRoot, "usr/bin/tool-alias"), &b)
	if a.Ino != b.Ino || a.Mode&0o111 == 0 {
		t.Fatal("hard link / exec bit not preserved")
	}
	if l, _ := os.Readlink(filepath.Join(baseRoot, "usr/bin/sh-link")); l != "/bin/sh" {
		t.Fatalf("symlink = %q", l)
	}
	var wh unix.Stat_t
	if err := unix.Lstat(filepath.Join(topRoot, "var/cache/big"), &wh); err != nil || wh.Mode&unix.S_IFMT != unix.S_IFCHR || wh.Rdev != 0 {
		t.Fatalf("whiteout not converted to a 0:0 char device: %v %o", err, wh.Mode)
	}
	if _, err := os.Lstat(filepath.Join(topRoot, "var/cache/.wh.big")); err == nil {
		t.Fatal("OCI whiteout file left in the layer")
	}
	// The opaque directory is expanded over the base layer (spec §29.5): a
	// whiteout for what the base holds there, no xattr (NFS drops them), and
	// the layer is named for the layers beneath it.
	if !strings.HasPrefix(res.Layers[1], "opq-") {
		t.Fatalf("top layer id %s: not an expanded layer's", res.Layers[1])
	}
	if err := unix.Lstat(filepath.Join(topRoot, "opt/data/old"), &wh); err != nil || wh.Mode&unix.S_IFMT != unix.S_IFCHR || wh.Rdev != 0 {
		t.Fatalf("opaque directory not expanded into a whiteout: %v", err)
	}
	if isOpaque(filepath.Join(topRoot, "opt/data")) {
		t.Fatal("the opaque xattr is still set")
	}
	mnt := t.TempDir()
	if err := unix.Mount("overlay", mnt, "overlay", unix.MS_RDONLY, "lowerdir="+topRoot+":"+baseRoot); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(mnt, "opt/data"))
	_, big := os.Lstat(filepath.Join(mnt, "var/cache/big"))
	unix.Unmount(mnt, unix.MNT_DETACH)
	if len(ents) != 1 || ents[0].Name() != "new" || big == nil {
		t.Fatalf("merged view: opt/data %v, var/cache/big %v", ents, big)
	}
	// A second import of the same image downloads nothing (layers dedup by digest).
	before := *pulls
	res2, err := (&Puller{Store: s, PlainHTTP: true, Platform: "linux/amd64"}).Pull(context.Background(), ref)
	if err != nil || res2.Pulled != 0 || *pulls != before {
		t.Fatalf("re-import pulled again: %+v %v (%d -> %d)", res2, err, before, *pulls)
	}
}

func TestExtractRejectsMaliciousLayers(t *testing.T) {
	outside := t.TempDir()
	cases := map[string][]tarEntry{
		"dot-dot":         {{name: "../../escape", body: "x"}},
		"through symlink": {{name: "evil", typ: tar.TypeSymlink, link: outside}, {name: "evil/pwned", body: "x"}},
		"nested symlink":  {{name: "a/", typ: tar.TypeDir, mode: 0o755}, {name: "a/b", typ: tar.TypeSymlink, link: outside}, {name: "a/b/c/d", body: "x"}},
		"hardlink out":    {{name: "h", typ: tar.TypeLink, link: "../../../etc/passwd"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			raw := mkLayer(t, entries)
			gz, _ := gzip.NewReader(bytes.NewReader(raw))
			root := t.TempDir()
			if _, err := ExtractLayer(gz, root); err == nil {
				t.Fatal("malicious layer extracted without error")
			}
			ents, _ := os.ReadDir(outside)
			if len(ents) != 0 {
				t.Fatalf("wrote outside the layer: %v", ents)
			}
		})
	}
	// Absolute names are confined to the layer, not rejected.
	root := t.TempDir()
	gz, _ := gzip.NewReader(bytes.NewReader(mkLayer(t, []tarEntry{{name: "/etc/abs", body: "x"}})))
	if _, err := ExtractLayer(gz, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/abs")); err != nil {
		t.Fatal("absolute name not confined to the layer")
	}
}

func TestParseReference(t *testing.T) {
	cases := map[string]Reference{
		"docker://python:3.12-slim":       {"registry-1.docker.io", "library/python", "3.12-slim"},
		"alpine":                          {"registry-1.docker.io", "library/alpine", "latest"},
		"ghcr.io/org/img:v2":              {"ghcr.io", "org/img", "v2"},
		"localhost:5000/team/x@sha256:ab": {"localhost:5000", "team/x", "sha256:ab"},
		"user/repo:tag":                   {"registry-1.docker.io", "user/repo", "tag"},
		// Docker Hub's own names (docker.io is its web site, not the API).
		"docker.io/library/alpine:3.20": {"registry-1.docker.io", "library/alpine", "3.20"},
		"docker.io/alpine":              {"registry-1.docker.io", "library/alpine", "latest"},
		"index.docker.io/user/repo:tag": {"registry-1.docker.io", "user/repo", "tag"},
		// A tag next to a digest: the digest decides.
		"python:3.12@sha256:ab":              {"registry-1.docker.io", "library/python", "sha256:ab"},
		"localhost:5000/team/x:v1@sha256:ab": {"localhost:5000", "team/x", "sha256:ab"},
	}
	for in, want := range cases {
		if got, err := ParseReference(in); err != nil || got != want {
			t.Errorf("ParseReference(%q) = %+v %v", in, got, err)
		}
	}
}

// TestPullPrivateRegistry: each way registries take credentials (a token
// endpoint with Basic auth, an identity token, Basic auth on the registry),
// and the errors without or with wrong credentials say which.
func TestPullPrivateRegistry(t *testing.T) {
	layer := mkLayer(t, []tarEntry{{name: "etc/private", body: "ok\n"}})
	good := map[string]*Credentials{
		"bearer":  {Username: fakeUser, Password: fakePass},
		"refresh": {IdentityToken: fakeRefresh},
		"basic":   {Username: fakeUser, Password: fakePass},
	}
	bad := map[string]*Credentials{
		"bearer":  {Username: fakeUser, Password: "wrong"},
		"refresh": {IdentityToken: "rt-old"},
		"basic":   {Username: "mallory", Password: fakePass},
	}
	for _, auth := range []string{"bearer", "refresh", "basic"} {
		t.Run(auth, func(t *testing.T) {
			srv, pulls := fakeRegistryAuth(t, [][]byte{layer}, map[string]any{"config": map[string]any{}}, auth)
			ref := strings.TrimPrefix(srv.URL, "http://") + "/test/app:v1"
			pull := func(c *Credentials) (*ImportResult, error) {
				s, _ := NewStore(t.TempDir())
				res, err := (&Puller{Store: s, PlainHTTP: true, Platform: "linux/amd64", Creds: c}).Pull(context.Background(), ref)
				if err == nil {
					if b, _ := os.ReadFile(filepath.Join(s.LayerRootfs(res.Layers[0]), "etc/private")); string(b) != "ok\n" {
						t.Fatalf("layer content %q", b)
					}
				}
				return res, err
			}
			if res, err := pull(good[auth]); err != nil || res.Pulled != 1 || *pulls != 1 {
				t.Fatalf("with credentials: %+v %v (%d blob downloads)", res, err, *pulls)
			}
			if _, err := pull(nil); err == nil || !strings.Contains(err.Error(), "without credentials") ||
				!strings.Contains(err.Error(), "docker login") {
				t.Fatalf("without credentials: %v", err)
			}
			_, err := pull(bad[auth])
			if err == nil || !strings.Contains(err.Error(), "refused access to test/app for") {
				t.Fatalf("wrong credentials: %v", err)
			}
			if strings.Contains(err.Error(), fakePass) || strings.Contains(err.Error(), "wrong") {
				t.Fatalf("the error shows the secret: %v", err)
			}
		})
	}
}

func TestLoadAuthFile(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	f := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(f, []byte(`{
		"auths": {
			"https://index.docker.io/v1/": {"auth": "`+b64("hubuser:hub:pass")+`"},
			"harbor.example.com": {"username": "robot$ci", "password": "tok"},
			"https://acr.example.io": {"identitytoken": "rt"},
			"stored.example.com": {}
		},
		"credsStore": "desktop",
		"credHelpers": {"gcr.io": "gcloud"}
	}`), 0o600)
	ra, err := LoadAuthFile(f)
	if err != nil {
		t.Fatal(err)
	}
	for reg, want := range map[string]Credentials{
		"registry-1.docker.io": {Username: "hubuser", Password: "hub:pass"},
		"harbor.example.com":   {Username: "robot$ci", Password: "tok"},
		"acr.example.io":       {IdentityToken: "rt"},
	} {
		if c, err := ra.For(reg); err != nil || c == nil || *c != want {
			t.Errorf("%s: %+v %v", reg, c, err)
		}
	}
	for reg, helper := range map[string]string{"stored.example.com": "desktop", "gcr.io": "gcloud"} {
		if _, err := ra.For(reg); err == nil || !strings.Contains(err.Error(), "docker-credential-"+helper) {
			t.Errorf("%s: %v", reg, err)
		}
	}
	if c, err := ra.For("other.example.com"); c != nil || err != nil {
		t.Errorf("unknown registry: %+v %v", c, err)
	}
	if ra, err := LoadAuthFile(filepath.Join(t.TempDir(), "none.json")); err != nil {
		t.Fatal(err)
	} else if c, _ := ra.For("registry-1.docker.io"); c != nil {
		t.Fatal("credentials from a missing file")
	}
}

// TestPullZstdLayers: an image mixing gzip and zstd layers (as images
// rebuilt with zstd on a gzip base are).
func TestPullZstdLayers(t *testing.T) {
	base := mkLayer(t, []tarEntry{{name: "etc/base", body: "gzip\n"}, {name: "etc/gone", body: "x"}})
	top := mkZstdLayer(t, []tarEntry{{name: "etc/top", body: "zstd\n"}, {name: "etc/.wh.gone"}})
	srv, pulls := fakeRegistry(t, [][]byte{base, top}, map[string]any{"config": map[string]any{}})
	s, _ := NewStore(t.TempDir())
	res, err := (&Puller{Store: s, PlainHTTP: true, Platform: "linux/amd64"}).Pull(context.Background(),
		strings.TrimPrefix(srv.URL, "http://")+"/test/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Layers) != 2 || *pulls != 2 {
		t.Fatalf("%+v, %d downloads", res, *pulls)
	}
	if b, _ := os.ReadFile(filepath.Join(s.LayerRootfs(res.Layers[1]), "etc/top")); string(b) != "zstd\n" {
		t.Fatalf("zstd layer content %q", b)
	}
	var wh unix.Stat_t
	if err := unix.Lstat(filepath.Join(s.LayerRootfs(res.Layers[1]), "etc/gone"), &wh); err != nil || wh.Mode&unix.S_IFMT != unix.S_IFCHR {
		t.Fatalf("whiteout in the zstd layer: %v", err)
	}
	// A corrupt zstd layer fails its digest or its decoding, never lands.
	bad := append([]byte(nil), top...)
	bad[len(bad)/2] ^= 0xff
	srv2, _ := fakeRegistry(t, [][]byte{bad}, map[string]any{"config": map[string]any{}})
	s2, _ := NewStore(t.TempDir())
	if _, err := (&Puller{Store: s2, PlainHTTP: true, Platform: "linux/amd64"}).Pull(context.Background(),
		strings.TrimPrefix(srv2.URL, "http://")+"/test/app:v1"); err == nil {
		t.Fatal("corrupt zstd layer imported")
	}
}
