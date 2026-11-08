package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/e2b"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestProjectLimits (spec §43): users in projects of their own under one
// parent (as a public trial cluster has them) are held to it: their quota,
// the parent's lifetime cap and image limits (admission.projects), no other
// project; WhoAmI tells their project, and E2B's API (e2b.home_projects)
// puts their sandboxes there.
func TestProjectLimits(t *testing.T) {
	cfg := cluster.SimConfig(1, 2, 16, 64*1024, 100)
	cfg.Admission.Projects = map[string]config.ProjectAdmission{"root/try": {MaxTTLMax: 600, DefaultTTLRunningStop: 120},
		"root/try/u": {MaxImages: 2}}
	storeRoot := t.TempDir()
	useStore(cfg, storeRoot)
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	addr := cfg.APIServers[0].Addr
	admin, err := client.Dial(addr, l.AdminToken, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	cx := ctx(t)

	for _, p := range [][2]string{{"root", "try"}, {"root/try", "u"}, {"root/try", "images"}, {"root/try/u", "gh-5"}, {"root/try/u", "gh-3"}} {
		quota := map[string]float64{"sandboxes": 10}
		if p[0] == "root/try/u" {
			quota["sandboxes"] = 2
		}
		if _, err := admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: p[0], Name: p[1], Quota: quota}); err != nil {
			t.Fatal(err)
		}
	}
	keyOf := func(id string) string {
		t.Helper()
		project := "root/try/u/" + id
		pr, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: project, Id: id, Kind: "user", TtlS: 3600})
		if err != nil {
			t.Fatal(err)
		}
		for p, perms := range map[string][]string{project: {"sandbox.create", "sandbox.operate", "layer.use", "layer.publish"},
			"root/try/images": {"layer.use"}} {
			if _, err := admin.Grant(cx, &pb.GrantRequest{Project: p, Principal: id, Perms: perms}); err != nil {
				t.Fatal(err)
			}
		}
		return pr.Token
	}
	key, other := keyOf("gh-5"), keyOf("gh-3")
	user, _ := client.Dial(addr, key, "root/try/u/gh-5")
	defer user.Close()

	me, err := user.WhoAmI(cx, &pb.Empty{})
	if err != nil || me.Id != "gh-5" || me.Project != "root/try/u/gh-5" || me.TokenExpiresAt == 0 {
		t.Fatalf("whoami: %v %v", me, err)
	}
	sp := &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}}
	sb, err := user.Create(cx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Spec.TtlMaxS != 600 || sb.Spec.TtlRunningStopS != 120 {
		t.Fatalf("trial TTLs: max %d idle %d", sb.Spec.TtlMaxS, sb.Spec.TtlRunningStopS)
	}
	long := &pb.SandboxSpec{Backend: "sim", TtlMaxS: 3600}
	if _, err := user.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: "root/try/u/gh-5", Spec: long}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("lifetime above the trial cap: %v", err)
	}
	if got, err := user.SetSandboxTimeout(cx, &pb.SetTimeoutRequest{SandboxId: sb.Id, TimeoutS: 86400}); err != nil || got.Spec.TtlMaxS > 600 {
		t.Fatalf("timeout past the trial cap: %v %v", got.GetSpec().GetTtlMaxS(), err)
	}
	for _, p := range []string{"root", "root/try", "root/try/u/gh-3"} {
		if _, err := user.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: p, Spec: sp}); rpcutil.Reason(err) != rpcutil.Forbidden {
			t.Fatalf("create in %s: %v", p, err)
		}
	}
	if _, err := user.Create(cx, sp); err != nil {
		t.Fatal(err)
	}
	if _, err := user.Create(cx, sp); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("third sandbox past the user's quota: %v", err)
	}
	// Images: users use the shared ones, publish only into their own
	// project, and at most max_images there.
	st, err := images.NewStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := st.BeginLayer(layerID("play-base"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/try/images/base:1",
		Layers: []string{layerID("play-base")}}}); err != nil {
		t.Fatal(err)
	}
	compose := func(name string) error {
		_, err := user.ComposeImage(cx, &pb.ComposeImageRequest{Name: name, Parts: []string{"root/try/images/base:1"}})
		return err
	}
	if err := compose("root/try/images/mine:1"); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("publishing into the shared images: %v", err)
	}
	for _, n := range []string{"a:1", "b:1"} {
		if err := compose("root/try/u/gh-5/" + n); err != nil {
			t.Fatalf("own image %s: %v", n, err)
		}
	}
	if err := compose("root/try/u/gh-5/c:1"); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("third image past max_images: %v", err)
	}
	if _, err := user.DeleteImage(cx, &pb.ImageRef{Name: "root/try/u/gh-5/a:1"}); err != nil {
		t.Fatal(err)
	}
	if err := compose("root/try/u/gh-5/c:1"); err != nil {
		t.Fatalf("after deleting one: %v", err)
	}

	// Admin's sandboxes elsewhere keep the cluster's TTLs.
	asb, err := admin.Create(cx, sp)
	if err != nil || asb.Spec.TtlMaxS != 86400 {
		t.Fatalf("root sandbox: %v %v", asb.GetSpec().GetTtlMaxS(), err)
	}

	// Through E2B's API, bob's sandbox lands in his project. The gateway's
	// client carries each caller's token.
	gwAPI, err := client.Dial(addr, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer gwAPI.Close()
	gw := httptest.NewServer(e2b.New(config.E2B{Project: "root", HomeProjects: []string{"root/try/u"},
		Templates: map[string]config.E2BTemplate{"base": {Image: "host", Backend: "sim", CPU: 1, MemoryMB: 256}}},
		gwAPI, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer gw.Close()
	req, _ := http.NewRequest("POST", gw.URL+"/sandboxes", strings.NewReader(`{"templateID":"base","timeout":300}`))
	req.Header.Set("X-API-KEY", e2b.E2BKey(other))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("e2b create: %d %s", resp.StatusCode, b)
	}
	l2, err := admin.ListSandboxes(cx, &pb.SandboxFilter{Project: "root/try/u/gh-3"})
	if err != nil || len(l2.Sandboxes) != 1 {
		t.Fatalf("bob's project: %v %v", l2, err)
	}
}
