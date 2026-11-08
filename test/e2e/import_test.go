package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// miniRegistry serves test/app:v1, one layer of files (name -> size).
func miniRegistry(t *testing.T, files map[string]int) *httptest.Server {
	t.Helper()
	var lb bytes.Buffer
	gz := gzip.NewWriter(&lb)
	tw := tar.NewWriter(gz)
	for name, size := range files {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(size)})
		tw.Write(bytes.Repeat([]byte("x"), size))
	}
	tw.Close()
	gz.Close()
	dig := func(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
	cfg, _ := json.Marshal(map[string]any{"config": map[string]any{"Env": []string{"FROM_REGISTRY=1"}, "WorkingDir": "/srv"}})
	layer := lb.Bytes()
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": dig(cfg), "size": len(cfg)},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": dig(layer), "size": len(layer)}}})
	blobs := map[string][]byte{dig(cfg): cfg, dig(layer): layer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rest := strings.TrimPrefix(r.URL.Path, "/v2/test/app/"); {
		case rest == "manifests/v1":
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Write(man)
		case strings.HasPrefix(rest, "blobs/") && blobs[strings.TrimPrefix(rest, "blobs/")] != nil:
			w.Write(blobs[strings.TrimPrefix(rest, "blobs/")])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestImportImage (spec §43.3): users have the cluster pull registry
// images into their projects, within the import limit and their project's
// image quota; registries on private networks only when allowed.
func TestImportImage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("unpacking layers needs root")
	}
	small := miniRegistry(t, map[string]int{"srv/app.py": 1000})
	big := miniRegistry(t, map[string]int{"srv/a": 3 << 20, "srv/b": 3 << 20})
	other := miniRegistry(t, map[string]int{"srv/x": 10})
	host := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

	cfg := cluster.SimConfig(1, 2, 16, 64*1024, 100)
	useStore(cfg, t.TempDir())
	cfg.Admission.Projects = map[string]config.ProjectAdmission{"root/u": {MaxImageMB: 5}}
	cfg.ImageImport = config.ImageImport{MaxMB: 100, AllowRegistries: []string{"http://" + host(small), "http://" + host(big)}}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	addr := cfg.APIServers[0].Addr
	admin, _ := client.Dial(addr, l.AdminToken, "root")
	defer admin.Close()
	cx := ctx(t)
	admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "u"})
	pr, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/u", Id: "dev", Kind: "user"})
	if err != nil {
		t.Fatal(err)
	}
	admin.Grant(cx, &pb.GrantRequest{Project: "root/u", Principal: "dev", Perms: []string{"layer.publish", "layer.use", "sandbox.create"}})
	dev, _ := client.Dial(addr, pr.Token, "root/u")
	defer dev.Close()

	imp := func(c *client.Client, image, ref string) (*pb.ImageInfo, error) {
		return c.ImportImage(cx, &pb.ImportImageRequest{Image: image, Ref: ref})
	}
	info, err := imp(dev, "root/u/app:1", host(small)+"/test/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Env["FROM_REGISTRY"] != "1" || info.Workdir != "/srv" || len(info.Layers) != 1 || info.SizeBytes == 0 {
		t.Fatalf("imported: %+v", info)
	}
	// An image made from it in the same project holds its data too (an
	// import overwritten by a pack_diff of itself must not count only the
	// diff); one made from another project's image does not.
	derived, err := dev.ComposeImage(cx, &pb.ComposeImageRequest{Name: "root/u/app:2", Parts: []string{"root/u/app:1"}})
	if err != nil || derived.SizeBytes != info.SizeBytes {
		t.Fatalf("derived in the project: %v %v, want size %d", derived.GetSizeBytes(), err, info.SizeBytes)
	}
	if _, err := admin.ComposeImage(cx, &pb.ComposeImageRequest{Name: "root/base:1", Parts: []string{"root/u/app:1"}}); err != nil {
		t.Fatal(err)
	}
	admin.Grant(cx, &pb.GrantRequest{Project: "root", Principal: "dev", Perms: []string{"layer.use"}})
	if other, err := dev.ComposeImage(cx, &pb.ComposeImageRequest{Name: "root/u/app:3", Parts: []string{"root/base:1"}}); err != nil || other.SizeBytes != 0 {
		t.Fatalf("derived from another project: %v %v", other.GetSizeBytes(), err)
	}
	for _, n := range []string{"root/u/app:2", "root/u/app:3"} {
		dev.DeleteImage(cx, &pb.ImageRef{Name: n})
	}
	if _, err := imp(dev, "root/other:1", host(small)+"/test/app:v1"); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("into a project without layer.publish: %v", err)
	}
	// Not allowed: a registry on a private address.
	if _, err := imp(dev, "root/u/x:1", host(other)+"/test/app:v1"); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("a registry on a private address: %v", err)
	}
	// 6 MB do not fit in the 5 MB of the project's image quota: the limit
	// stops the unpacking.
	if _, err := imp(dev, "root/u/big:1", host(big)+"/test/app:v1"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("past the project's image quota: %v", err)
	}
	if _, err := dev.GetImage(cx, &pb.ImageRef{Name: "root/u/big:1"}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("a refused import left an image: %v", err)
	}
}
