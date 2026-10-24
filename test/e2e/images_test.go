package e2e

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// miniRootfs copies a shell, a few tools and their shared libraries from the
// host into dir: a small, hermetic base layer (no registry access needed).
func miniRootfs(t *testing.T, dir string) {
	t.Helper()
	tools := []string{"bash", "sh", "cat", "ls", "rm", "mkdir", "touch", "test", "env"}
	libs := map[string]bool{}
	os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755)
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("host tool %s: %v", tool, err)
		}
		real, _ := filepath.EvalSymlinks(p)
		copyFile(t, real, filepath.Join(dir, "usr/bin", tool))
		out, _ := exec.Command("ldd", real).Output()
		for _, line := range strings.Split(string(out), "\n") {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "/") {
					libs[f] = true
				}
			}
		}
	}
	for l := range libs {
		real, _ := filepath.EvalSymlinks(l)
		copyFile(t, real, filepath.Join(dir, strings.TrimPrefix(l, "/")))
	}
	os.Symlink("usr/bin", filepath.Join(dir, "bin"))
	for _, d := range []string{"etc", "srv", "opt", "tmp", "root"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(dst), 0o755)
	if _, err := os.Lstat(dst); err == nil {
		return
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func layerID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return "sha256-" + hex.EncodeToString(h[:])
}

func TestStoreImagesAndPackDiff(t *testing.T) {
	if agentDir == "" {
		t.Skip("container runtime unavailable")
	}
	storeRoot := t.TempDir()
	st, _ := images.NewStore(storeRoot)

	// Base layer: a mini rootfs plus files the next layers modify.
	w, _, err := st.BeginLayer(layerID("base"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	os.WriteFile(filepath.Join(w.Rootfs, "etc/base-marker"), []byte("base\n"), 0o644)
	os.WriteFile(filepath.Join(w.Rootfs, "opt/remove-me"), []byte("x"), 0o644)
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	// Workspace layer from an OCI-style tar: adds a file, whites one out.
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "srv/app.txt", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg})
	tw.Write([]byte("app\n"))
	tw.WriteHeader(&tar.Header{Name: "opt/.wh.remove-me", Mode: 0o644, Typeflag: tar.TypeReg})
	tw.Close()
	ws, _, _ := st.BeginLayer(layerID("workspace"))
	if _, err := images.ExtractLayer(&tb, ws.Rootfs); err != nil {
		t.Fatal(err)
	}
	ws.Commit(images.LayerMeta{})

	// Cluster with the store; the static "host" image stays available too.
	state, _ := os.MkdirTemp("", "opendsec")
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(2, 1, 8, 16*1024, 64)
	cfg.ImageStore.Root = storeRoot
	for i := range cfg.Edges {
		cfg.Edges[i].StateDir, cfg.Edges[i].AgentDir = state, agentDir
		// The state dir is on a small tmpfs: sparse 256 MB disks, small reserve.
		cfg.Edges[i].Capacity.DiskMB, cfg.Edges[i].DiskReserveMB = 64*256, 64
		cfg.Edges[i].Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	admin, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root/rl")
	defer admin.Close()
	cx := ctx(t)
	admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "rl"})

	// Register base and workspace images, compose them (no data copied).
	if _, err := admin.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/rl/base:1",
		Layers: []string{layerID("base")}, Env: map[string]string{"GREETING": "hi"}, Workdir: "/srv"}}); err != nil {
		t.Fatal(err)
	}
	admin.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/rl/ws:1", Layers: []string{layerID("workspace")}}})
	app, err := admin.ComposeImage(cx, &pb.ComposeImageRequest{Name: "root/rl/app:1", Parts: []string{"root/rl/base:1", "root/rl/ws:1"}})
	if err != nil || len(app.Layers) != 2 || app.Env["GREETING"] != "hi" {
		t.Fatalf("compose: %v %v", app, err)
	}

	spec := &pb.SandboxSpec{Backend: "container", Image: "root/rl/app:1", Resources: &pb.Resources{CpuCores: 0.5, MemoryMb: 256}}
	sb, err := admin.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Image defaults apply; layers stack; the workspace whiteout hides the base file.
	if r := shell(t, admin, sb.Id, "", `echo "$GREETING $PWD"; cat app.txt /etc/base-marker; test -e /opt/remove-me || echo gone`); string(r.Stdout) != "hi /srv\napp\nbase\ngone\n" {
		t.Fatalf("image contents: %q %q", r.Stdout, r.Stderr)
	}
	// Build an environment, delete a base file, leave residue.
	shell(t, admin, sb.Id, "", `mkdir -p /srv/build && echo built > /srv/build/out.txt && rm /etc/base-marker && echo junk > /tmp/junk && echo history > /root/.bash_history`)

	packed, err := admin.PackDiff(cx, &pb.PackDiffRequest{SandboxId: sb.Id, Image: "root/rl/app:2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(packed.Layers) != 3 || packed.Parent != "root/rl/app:1" || packed.Env["GREETING"] != "hi" {
		t.Fatalf("packed image: %+v", packed)
	}
	// The source sandbox keeps running after the snapshot.
	if r := shell(t, admin, sb.Id, "", "echo still-running"); string(r.Stdout) != "still-running\n" {
		t.Fatal("sandbox not resumed after pack_diff")
	}
	// A sandbox from the packed image has the build output, not the residue,
	// and the deletion made in the source sandbox persists.
	spec2 := &pb.SandboxSpec{Backend: "container", Image: "root/rl/app:2", Resources: &pb.Resources{CpuCores: 0.5, MemoryMb: 256}}
	sb2, err := admin.Create(cx, spec2)
	if err != nil {
		t.Fatal(err)
	}
	r := shell(t, admin, sb2.Id, "", `cat build/out.txt; test -e /etc/base-marker || echo marker-deleted; test -e /tmp/junk || echo no-junk; test -e /root/.bash_history || echo no-history; ls /.opendsec/bin`)
	if want := "built\nmarker-deleted\nno-junk\nno-history\nopendsec-aether\nopendsec-chronus\n"; string(r.Stdout) != want {
		t.Fatalf("packed image contents: %q (stderr %q)", r.Stdout, r.Stderr)
	}
	if _, err := admin.PackDiff(cx, &pb.PackDiffRequest{SandboxId: sb.Id, Image: "root/rl/app:2"}); err == nil {
		t.Fatal("pack_diff overwrote an existing image without overwrite")
	}

	// Permissions: a runtime account with layer.use can run images but not publish.
	pr, _ := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/rl", Id: "runner"})
	admin.Grant(cx, &pb.GrantRequest{Project: "root/rl", Principal: "runner", Perms: []string{"sandbox.create", "sandbox.operate", "layer.use"}})
	runner, _ := client.Dial(cfg.APIServers[0].Addr, pr.Token, "root/rl")
	defer runner.Close()
	rsb, err := runner.Create(cx, spec2)
	if err != nil {
		t.Fatalf("runner create from image: %v", err)
	}
	if _, err := runner.PackDiff(cx, &pb.PackDiffRequest{SandboxId: rsb.Id, Image: "root/rl/sneaky:1"}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("runner published an image: %v", err)
	}
	if _, err := runner.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/rl/sneaky:1", Layers: app.Layers}}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("runner registered an image: %v", err)
	}
	pr2, _ := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/rl", Id: "nouse"})
	admin.Grant(cx, &pb.GrantRequest{Project: "root/rl", Principal: "nouse", Perms: []string{"sandbox.create"}})
	nouse, _ := client.Dial(cfg.APIServers[0].Addr, pr2.Token, "root/rl")
	defer nouse.Close()
	if _, err := nouse.Create(cx, spec2); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("create from an image without layer.use: %v", err)
	}
	// Unknown store images fail fast; listing shows all three.
	if _, err := admin.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "root/rl/nope:1"}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("unknown image: %v", err)
	}
	if list, err := admin.ListImages(cx, &pb.ListImagesRequest{Project: "root/rl"}); err != nil || len(list.Images) != 4 {
		t.Fatalf("list images: %v %v", list, err)
	}
}
