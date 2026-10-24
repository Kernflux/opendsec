package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/release"
)

type fakeSD struct {
	root string
	bad  string // release whose units fail
	log  []string
}

func (f *fakeSD) DaemonReload(context.Context) error {
	f.log = append(f.log, "daemon-reload")
	return nil
}
func (f *fakeSD) Run(_ context.Context, verb, unit string) error {
	f.log = append(f.log, verb+" "+unit)
	return nil
}
func (f *fakeSD) ActiveState(context.Context, string) string {
	t, _ := os.Readlink(filepath.Join(f.root, "current"))
	if filepath.Base(t) == f.bad {
		return "failed"
	}
	return "active"
}
func (f *fakeSD) RestartSelf(context.Context) error { return nil }

// fakeFleet serves release tarballs from memory.
type fakeFleet struct {
	pb.FleetClient
	tgz map[string][]byte
}

type chunks struct {
	grpc.ClientStream
	data []byte
	sent bool
}

func (c *chunks) Recv() (*pb.ReleaseChunk, error) {
	if c.sent {
		return nil, io.EOF
	}
	c.sent = true
	return &pb.ReleaseChunk{Data: c.data}, nil
}

func (f *fakeFleet) FetchRelease(_ context.Context, r *pb.FetchReleaseRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ReleaseChunk], error) {
	return &chunks{data: f.tgz[r.Version][r.Offset:]}, nil
}

func packed(t *testing.T, version string) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), version)
	os.MkdirAll(filepath.Join(dir, "bin"), 0o755)
	os.MkdirAll(filepath.Join(dir, "units"), 0o755)
	os.WriteFile(filepath.Join(dir, "bin/opendsec-edge"), []byte(version), 0o755)
	os.WriteFile(filepath.Join(dir, "units/opendsec-edge.service"), []byte("# "+version), 0o644)
	if err := release.WriteSums(dir); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := release.Pack(dir, &b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func setup(t *testing.T) (*Agent, *fakeSD, *fakeFleet, string) {
	t.Helper()
	base := t.TempDir()
	sd := &fakeSD{root: filepath.Join(base, "opt")}
	ff := &fakeFleet{tgz: map[string][]byte{"v1": packed(t, "v1"), "v2": packed(t, "v2")}}
	a := New(Options{Name: "n1", Fleet: ff, Root: sd.root, BinDir: filepath.Join(base, "bin"), Etc: filepath.Join(base, "etc"),
		UnitDir: filepath.Join(base, "units"), StateFile: filepath.Join(base, "state.json"), Systemd: sd,
		Ready: func(context.Context, string) error { return nil }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return a, sd, ff, base
}

func applyOp(ff *fakeFleet, rel, cfg string) *pb.NodeOp {
	sum := sha256.Sum256(ff.tgz[rel])
	return &pb.NodeOp{OpId: rel + cfg, Kind: "apply", Release: rel, Sha256: hex.EncodeToString(sum[:]), Size: int64(len(ff.tgz[rel])),
		Files: []*pb.NodeFile{{Name: "opendsec.json", Content: []byte(cfg)}}, Units: []*pb.NodeUnit{{Unit: "opendsec-edge.service"}},
		TimeoutS: 1}
}

func TestApplyAndRestore(t *testing.T) {
	a, sd, ff, base := setup(t)
	ctx := context.Background()
	if _, err := a.execute(ctx, applyOp(ff, "v1", "one")); err != nil {
		t.Fatal(err)
	}
	if a.current() != "v1" {
		t.Fatalf("current %q", a.current())
	}
	if l, _ := os.Readlink(filepath.Join(base, "bin", "opendsec-edge")); l != filepath.Join(sd.root, "current/bin/opendsec-edge") {
		t.Fatalf("bin link %q", l)
	}
	if b, _ := os.ReadFile(filepath.Join(base, "units", "opendsec-edge.service")); string(b) != "# v1" {
		t.Fatalf("unit file %q", b)
	}
	// v2's units fail: the agent puts v1, its config and its units back.
	sd.bad = "v2"
	_, err := a.execute(ctx, applyOp(ff, "v2", "two"))
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("apply of a failing release: %v", err)
	}
	if a.current() != "v1" {
		t.Fatalf("after the failed apply current is %q, want v1", a.current())
	}
	if b, _ := os.ReadFile(filepath.Join(base, "etc", "opendsec.json")); string(b) != "one" {
		t.Fatalf("config after the failed apply: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(base, "units", "opendsec-edge.service")); string(b) != "# v1" {
		t.Fatalf("unit file after the failed apply: %q", b)
	}
	// v2 stayed staged: a later attempt does not download it again.
	if err := release.VerifyDir(filepath.Join(sd.root, "releases", "v2")); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsForeignUnitsAndFiles(t *testing.T) {
	a, _, ff, _ := setup(t)
	ctx := context.Background()
	op := applyOp(ff, "v1", "x")
	op.Units = []*pb.NodeUnit{{Unit: "sshd.service"}}
	if _, err := a.execute(ctx, op); err == nil {
		t.Fatal("restarted a unit that is not OpenDsec's")
	}
	op = applyOp(ff, "v1", "x")
	op.Files = []*pb.NodeFile{{Name: "../../etc/passwd", Content: []byte("x")}}
	if _, err := a.execute(ctx, op); err == nil {
		t.Fatal("wrote a file outside the allowed set")
	}
	op = applyOp(ff, "v1", "x")
	if _, err := a.execute(ctx, &pb.NodeOp{OpId: "s", Kind: "stage", Release: "v1", Sha256: strings.Repeat("0", 64), Size: op.Size}); err == nil {
		t.Fatal("staged a release whose sha256 does not match")
	}
	if _, err := os.Stat(filepath.Join(a.o.Root, "releases", "v1")); err == nil {
		t.Fatal("a release that failed its check was unpacked")
	}
	if _, err := a.execute(ctx, &pb.NodeOp{OpId: "x", Kind: "exec"}); err == nil {
		t.Fatal("ran an unknown operation")
	}
}

func TestFirecrackerVersion(t *testing.T) {
	if v := FirecrackerVersion("Firecracker v1.17.0\n\nExiting successfully"); v != "1.17.0" {
		t.Fatalf("%q", v)
	}
}
