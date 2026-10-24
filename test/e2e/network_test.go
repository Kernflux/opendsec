package e2e

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend/fullvm"
	"github.com/kernflux/opendsec/internal/edge/backend/microvm"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestNetworkPolicy runs sandboxes with networking through the whole stack
// (spec §20): default deny, rule sets and domains, live rule changes, and,
// for microVMs, pause / fork / an edge restart keeping the network. Needs
// root, nftables and internet access; OPENDSEC_NET_TESTS=1 (it enables IPv4
// forwarding on the host).
func TestNetworkPolicy(t *testing.T) {
	if os.Getenv("OPENDSEC_NET_TESTS") == "" || agentDir == "" {
		t.Skip("set OPENDSEC_NET_TESTS=1 (container runtime needed)")
	}
	storeRoot := t.TempDir()
	st, _ := images.NewStore(storeRoot)
	w, _, err := st.BeginLayer(layerID("net-base"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	// HTTPS from inside: the host's CA bundle.
	os.MkdirAll(filepath.Join(w.Rootfs, "etc/ssl/certs"), 0o755)
	if err := copyHostFile("/etc/ssl/certs/ca-certificates.crt", filepath.Join(w.Rootfs, "etc/ssl/certs/ca-certificates.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	state, _ := os.MkdirTemp("", "opendsec")
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(1, 1, 8, 16*1024, 64)
	cfg.ImageStore.Root = storeRoot
	cfg.Network = config.NetworkPolicy{RuleSets: map[string][]string{"pypi": {"pypi.org", "files.pythonhosted.org"}}}
	vmOpt := microvm.Options{Kernel: fcKernel(), Firecracker: "firecracker", Jailer: "jailer"}
	withVM := microvm.Check(&vmOpt) == nil
	qOpt := fullvm.Options{Kernel: opendsecKernel(), QEMU: "qemu-system-x86_64"}
	withQEMU := opendsecKernel() != "" && fullvm.Check(&qOpt) == nil
	for i := range cfg.Edges {
		e := &cfg.Edges[i]
		e.StateDir, e.AgentDir = state, agentDir
		e.Capacity.DiskMB, e.DiskReserveMB = 64*256, 64
		e.Network = config.EdgeNetwork{Enabled: true, Subnet: "10.86.0.0/22", DNSPort: 15398}
		e.Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
		// Warm sandboxes get their network when taken.
		e.Backends["fncall"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256, WarmPool: map[string]int{"root/net:1": 2}}
		if withQEMU {
			e.Backends["fullvm"] = config.Backend{Runtime: "qemu", MaxSandboxes: 64, DefaultDiskMB: 256, Kernel: opendsecKernel()}
		}
		if withVM {
			e.Backends["microvm"] = config.Backend{Runtime: "firecracker", MaxSandboxes: 64, DefaultDiskMB: 256, Kernel: fcKernel()}
		}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer c.Close()
	cx := ctx(t)
	if _, err := c.RegisterImage(cx, &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/net:1", Layers: []string{layerID("net-base")}}}); err != nil {
		t.Fatal(err)
	}
	get := func(id, url string) (int32, error) {
		r, err := c.Http(cx, &pb.HttpRequest{SandboxId: id, Url: url, TimeoutS: 10})
		if err != nil {
			return 0, err
		}
		return r.Status, nil
	}
	const pypi, example = "https://pypi.org/simple/pip/", "https://example.com/"
	expect := func(id, what string, okPypi, okExample bool) {
		t.Helper()
		for url, ok := range map[string]bool{pypi: okPypi, example: okExample} {
			status, err := get(id, url)
			if ok && (err != nil || status != 200) {
				t.Errorf("%s: GET %s: %d %v, want 200", what, url, status, err)
			}
			if !ok && err == nil {
				t.Errorf("%s: GET %s: %d, want refused", what, url, status)
			}
		}
	}
	backends := []string{"container", "fncall"}
	if withQEMU {
		backends = append(backends, "fullvm")
	}
	if withVM {
		backends = append(backends, "microvm")
	} else {
		t.Logf("microvm runtime unavailable: networking tested with containers only")
	}
	for _, be := range backends {
		res := &pb.Resources{CpuCores: 1, MemoryMb: 256}
		start := time.Now()
		sb, err := c.Create(cx, &pb.SandboxSpec{Backend: be, Image: "root/net:1", Resources: res,
			NetworkRules: map[string]bool{"pypi": true}})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s sandbox with a network created in %v", be, time.Since(start).Round(time.Millisecond))
		expect(sb.Id, be+" with pypi", true, false)
		// No sandbox network is a mount on the host (each new mount
		// namespace copies the host's mounts, spec §25).
		if nss, _ := filepath.Glob("/run/netns/opendsec-" + cfg.Edges[0].ID + "-*"); len(nss) != 0 {
			t.Errorf("%s: named network namespaces on the host: %v", be, nss)
		}
		if mi, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(mi), strings.SplitN(sb.Id, ".", 2)[1]) {
			t.Errorf("%s: sandbox mounts on the host", be)
		}
		// No rules: nothing.
		closed, err := c.Create(cx, &pb.SandboxSpec{Backend: be, Image: "root/net:1", Resources: res})
		if err != nil {
			t.Fatal(err)
		}
		expect(closed.Id, be+" without rules", false, false)
		// Live changes.
		if _, err := c.UpdateNetwork(cx, &pb.UpdateNetworkRequest{SandboxId: sb.Id, Rules: map[string]bool{"example.com": true}}); err != nil {
			t.Fatal(err)
		}
		expect(sb.Id, be+" plus example.com", true, true)
		upd, err := c.UpdateNetwork(cx, &pb.UpdateNetworkRequest{SandboxId: sb.Id, Rules: map[string]bool{"example.com": true}, Replace: true})
		if err != nil || len(upd.Spec.NetworkRules) != 1 {
			t.Fatalf("replace rules: %v %v", upd, err)
		}
		expect(sb.Id, be+" with example.com only", false, true)
		if _, err := c.UpdateNetwork(cx, &pb.UpdateNetworkRequest{SandboxId: sb.Id, Rules: map[string]bool{"no-such-set": true}}); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Errorf("unknown rule: %v", err)
		}
		if be == "microvm" {
			// Pause (the VM process ends) and resume; fork copies share the
			// guest's network config, each in its own namespace.
			if _, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil {
				t.Fatal(err)
			}
			expect(sb.Id, "microvm after resume", false, true)
			forks, err := c.Fork(cx, &pb.ForkSandboxRequest{SandboxId: sb.Id, Count: 2})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range forks {
				if r.ErrorReason != "" {
					t.Fatalf("fork: %s %s", r.ErrorReason, r.ErrorMessage)
				}
				expect(r.Sandbox.Id, "fork copy", false, true)
				c.Stop(cx, r.Sandbox.Id)
			}
			// The network outlives an edge restart.
			ec, _ := l.Cfg.Edge(sb.EdgeId)
			ec.KeepSandboxesOnExit = true
			if err := l.RestartEdge(sb.EdgeId, nil); err != nil {
				t.Fatal(err)
			}
			ec.KeepSandboxesOnExit = false
			var last string
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
				l.Settle()
				s, err := c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id})
				if err == nil && s.State == pb.SandboxState_RUNNING {
					break
				}
				last = fmt.Sprint(s.GetState(), " ", s.GetMessage(), " ", err)
				if time.Now().After(deadline) {
					t.Fatalf("after an edge restart: %s", last)
				}
			}
			expect(sb.Id, "microvm after an edge restart", false, true)
			if _, err := c.UpdateNetwork(cx, &pb.UpdateNetworkRequest{SandboxId: sb.Id, Rules: map[string]bool{"pypi": true}}); err != nil {
				t.Fatal(err)
			}
			expect(sb.Id, "microvm after an edge restart, plus pypi", true, true)
		}
		c.Stop(cx, sb.Id)
		c.Stop(cx, closed.Id)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == 0 })
	if nss, _ := filepath.Glob("/run/netns/opendsec-" + cfg.Edges[0].ID + "-*"); len(nss) != 0 {
		t.Errorf("namespaces left: %v", nss)
	}
}

func copyHostFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}
