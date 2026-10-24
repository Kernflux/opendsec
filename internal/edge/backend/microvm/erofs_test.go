package microvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/images"
)

// erofsKernel is a guest kernel with EROFS (deploy/guest-kernel), else "".
func erofsKernel() string {
	k := os.Getenv("OPENDSEC_FC_EROFS_KERNEL")
	if k == "" {
		k = "/data/opendsec-vm/vmlinux-6.1.167-opendsec.2"
	}
	if _, err := os.Stat(k); err != nil {
		return ""
	}
	return k
}

// storeImage puts image name in st: the mini image, then a layer with
// /srv/hello and its own /etc/hostname-layer over the mini one's.
func storeImage(t *testing.T, st *images.Store, name string) {
	t.Helper()
	var layers []string
	for _, fill := range []func(dir string) error{
		func(dir string) error { return exec.Command("cp", "-a", imageDir+"/.", dir).Run() },
		func(dir string) error {
			os.MkdirAll(filepath.Join(dir, "srv"), 0o755)
			os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
			if err := os.WriteFile(filepath.Join(dir, "srv/hello"), []byte("from erofs\n"), 0o644); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "etc/layer"), []byte("top\n"), 0o644)
		},
	} {
		id := images.NewDiffLayerID()
		w, _, err := st.BeginLayer(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := fill(w.Rootfs); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Commit(images.LayerMeta{}); err != nil {
			t.Fatal(err)
		}
		layers = append(layers, id)
	}
	if err := st.PutManifest(&images.Manifest{Name: name, Layers: layers}, false); err != nil {
		t.Fatal(err)
	}
}

// TestErofsImages (spec §29.4): with erofs_images a store image runs from an
// EROFS disk built once in the store: the first edge builds it, a second
// edge on the same store copies it; pause and resume, snapshot copies and
// virtio-pmem with DAX work on it.
func TestErofsImages(t *testing.T) {
	k := erofsKernel()
	if k == "" {
		t.Skip("no guest kernel with EROFS (OPENDSEC_FC_EROFS_KERNEL; deploy/guest-kernel/build.sh)")
	}
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skip("no mkfs.erofs")
	}
	erofs := func(pmem bool) func(*Options) {
		return func(o *Options) { o.Kernel, o.ErofsImages, o.ImagePmem = k, true, pmem }
	}
	f := newBackendWith(t, erofs(false))
	const img = "root/erofs:1"
	storeImage(t, f.opt.Store, img)
	ctx := context.Background()
	res := &pb.Resources{MemoryMb: 256}
	a := f.create(t, &pb.SandboxSpec{Image: img, Resources: res})
	if r := sh(t, f.b, a, `cat /srv/hello /etc/layer`); out(r) != "from erofs\ntop" {
		t.Fatalf("first VM: %q %q", r.Stdout, r.Stderr)
	}
	disks, _ := filepath.Glob(filepath.Join(f.opt.Store.Root, "vmdisks", "*.erofs"))
	local, _ := filepath.Glob(filepath.Join(f.b.cacheDir(), "img-*.erofs"))
	if len(disks) != 1 || len(local) != 1 {
		t.Fatalf("store disks %v, local disks %v", disks, local)
	}
	// The VM runs it: its image disk is the EROFS one (the guest reads it,
	// so it mounted it as EROFS).
	s, _ := f.b.get(a.ID)
	for _, p := range []string{disks[0], local[0], filepath.Join(s.root, images.VMImageFile)} {
		if id := diskID(p); !strings.HasPrefix(id, "erofs-") {
			t.Fatalf("%s: %q, not an EROFS disk", p, id)
		}
	}
	built, _ := os.Stat(disks[0])

	// Another edge on the store copies the disk.
	g := newBackendOpt(t, os.Getenv("OPENDSEC_TEST_STATE"), f.opt.Store, erofs(false))
	b := g.create(t, &pb.SandboxSpec{Image: img, Resources: res})
	if r := sh(t, g.b, b, `cat /srv/hello`); out(r) != "from erofs" {
		t.Fatalf("second edge: %q %q", r.Stdout, r.Stderr)
	}
	if now, err := os.Stat(disks[0]); err != nil || !os.SameFile(built, now) || !now.ModTime().Equal(built.ModTime()) {
		t.Fatal("the second edge rebuilt the store's disk")
	}
	if l, _ := filepath.Glob(filepath.Join(g.b.cacheDir(), "img-*.erofs")); len(l) != 1 {
		t.Fatalf("second edge's local disks: %v", l)
	}

	// Pause and resume; a snapshot's copy.
	sh(t, g.b, b, `echo kept > /root/state`)
	if err := g.b.Pause(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := g.b.Resume(ctx, b); err != nil {
		t.Fatal(err)
	}
	if r := sh(t, g.b, b, `cat /root/state /srv/hello`); out(r) != "kept\nfrom erofs" {
		t.Fatalf("after resume: %q %q", r.Stdout, r.Stderr)
	}
	snap, err := f.b.Snapshot(ctx, a, images.NewSnapshotID(), true)
	if err != nil {
		t.Fatal(err)
	}
	c := f.create(t, &pb.SandboxSpec{Snapshot: snap.ID, Resources: res})
	if r := sh(t, f.b, c, `cat /srv/hello`); out(r) != "from erofs" {
		t.Fatalf("snapshot copy: %q %q", r.Stdout, r.Stderr)
	}

	// virtio-pmem with DAX on an EROFS image.
	h := newBackendOpt(t, os.Getenv("OPENDSEC_TEST_STATE"), f.opt.Store, erofs(true))
	d := h.create(t, &pb.SandboxSpec{Image: img, Resources: res})
	if r := sh(t, h.b, d, `cat /srv/hello; test -e /sys/block/pmem0 && echo pmem`); out(r) != "from erofs\npmem" {
		t.Fatalf("pmem: %q %q", r.Stdout, r.Stderr)
	}
}

// TestErofsFirstUse (OPENDSEC_BENCH=1, OPENDSEC_BENCH_STORE, OPENDSEC_BENCH_LOWER:
// a store and the lowerdirs of an image in it, topmost first, ':'-separated;
// spec §29.4): how long a node's first VM of an image takes to create, its
// image flattened to ext4 on the node, or as EROFS built in the store by the
// first edge and copied by the next. The store's files leave the page cache
// before each case.
func TestErofsFirstUse(t *testing.T) {
	root, lower := os.Getenv("OPENDSEC_BENCH_STORE"), os.Getenv("OPENDSEC_BENCH_LOWER")
	k := erofsKernel()
	if os.Getenv("OPENDSEC_BENCH") == "" || root == "" || lower == "" || k == "" {
		t.Skip("set OPENDSEC_BENCH=1, OPENDSEC_BENCH_STORE, OPENDSEC_BENCH_LOWER (and have an EROFS guest kernel)")
	}
	st, err := images.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	layers, ok := st.LayersOf(strings.Split(lower, ":"))
	if !ok {
		t.Fatal("OPENDSEC_BENCH_LOWER is not layers of OPENDSEC_BENCH_STORE")
	}
	img := "bench/img:" + images.NewDiffLayerID()[5:13]
	if err := st.PutManifest(&images.Manifest{Name: img, Layers: layers}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DeleteManifest(img) })
	os.Remove(st.VMDiskPath(images.VMDiskKey(layers))) // the first EROFS edge builds it
	uncache := func() {
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				dropCache(p)
			}
			return nil
		})
	}
	res := &pb.Resources{MemoryMb: 512}
	var b strings.Builder
	for _, c := range []struct {
		name  string
		erofs bool
	}{{"ext4, flattened on the node", false}, {"EROFS, first edge (builds it in the store)", true}, {"EROFS, another edge (copies it)", true}} {
		f := newBackendOpt(t, os.Getenv("OPENDSEC_TEST_STATE"), st, func(o *Options) { o.Kernel, o.ErofsImages = k, c.erofs })
		uncache()
		start := time.Now()
		sb := f.create(t, &pb.SandboxSpec{Image: img, Resources: res})
		took := time.Since(start)
		if r := sh(t, f.b, sb, `python3 -c 'import sys; print(sys.version_info[0])'`); out(r) != "3" {
			t.Fatalf("%s: %q %q", c.name, r.Stdout, r.Stderr)
		}
		start = time.Now()
		f.create(t, &pb.SandboxSpec{Image: img, Resources: res})
		fmt.Fprintf(&b, "%-44s first VM %8v   second VM %8v\n", c.name, took.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	}
	t.Log("\n" + b.String())
}
