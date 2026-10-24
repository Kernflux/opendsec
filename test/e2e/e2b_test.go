package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/e2b"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestE2BSDK (spec §37): E2B's own SDKs against the E2B gateway, in front
// of a cluster running real containers. OPENDSEC_E2B_PYTHON is a python
// with the e2b package (pip install e2b); OPENDSEC_E2B_JS is a directory
// where `npm install e2b` was run, with node on PATH.
func TestE2BSDK(t *testing.T) {
	py, js := os.Getenv("OPENDSEC_E2B_PYTHON"), os.Getenv("OPENDSEC_E2B_JS")
	if py == "" && js == "" {
		t.Skip("set OPENDSEC_E2B_PYTHON to a python with the e2b package, or OPENDSEC_E2B_JS to a directory with it installed by npm")
	}
	l, _ := startContainers(t)
	api, err := client.Dial(l.Cfg.APIServers[0].Addr, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	cfg := config.E2B{Project: "root", Templates: map[string]config.E2BTemplate{
		"base": {Image: "host", Backend: "container", CPU: 1, MemoryMB: 256}}}
	srv := httptest.NewUnstartedServer(e2b.New(cfg, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	defer srv.Close()

	run := func(t *testing.T, name string, args ...string) {
		cx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(cx, name, args...)
		cmd.Env = append(os.Environ(), "E2B_API_URL="+srv.URL, "E2B_SANDBOX_URL="+srv.URL, "E2B_API_KEY="+l.AdminToken)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "OK ") {
			t.Fatalf("e2b SDK check: %v\n%s", err, out)
		}
		t.Log(strings.TrimSpace(string(out)))
	}
	if py != "" {
		t.Run("python", func(t *testing.T) { run(t, py, "testdata/e2b_sdk_check.py") })
		t.Run("lifecycle", func(t *testing.T) { run(t, py, "testdata/e2b_lifecycle_check.py") })
	}
	if js != "" {
		t.Run("js", func(t *testing.T) {
			// ES modules resolve packages from the script's directory.
			dir := t.TempDir()
			script, err := os.ReadFile("testdata/e2b_js_check.mjs")
			if err == nil {
				err = os.WriteFile(dir+"/check.mjs", script, 0o644)
			}
			if err == nil {
				err = os.Symlink(js+"/node_modules", dir+"/node_modules")
			}
			if err != nil {
				t.Fatal(err)
			}
			run(t, "node", dir+"/check.mjs")
		})
	}
}

// portServer runs in the sandbox (python3 of the host image): on 8124 a
// streamed (chunked) response, ticks 0.3 s apart, or, for "Upgrade: echo",
// an echoed connection after 101.
const portServer = `
import socket, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8124)); s.listen()
def serve(c):
    req = b""
    while b"\r\n\r\n" not in req:
        req += c.recv(4096)
    if b"upgrade: echo" in req.lower():
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
        while True:
            b = c.recv(4096)
            if not b: break
            c.sendall(b)
    else:
        seen = b"x-access-token" in req.lower() or b"e2b-sandbox-id" in req.lower()
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        for i in range(3):
            line = ("tick %d leaked=%s\n" % (i, seen)).encode()
            c.sendall(b"%x\r\n%s\r\n" % (len(line), line)); time.sleep(0.3)
        c.sendall(b"0\r\n\r\n")
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,)).start()
`

// TestE2BPorts (spec §37.8): a sandbox's other ports through the gateway:
// a streamed response arrives as it is written, an upgraded connection
// echoes both ways, a closed port is 502, no token is 401, and the
// gateway's headers (tokens) never reach the sandbox.
func TestE2BPorts(t *testing.T) {
	l, c := startContainers(t)
	api, err := client.Dial(l.Cfg.APIServers[0].Addr, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	srv := httptest.NewServer(e2b.New(config.E2B{Project: "root"}, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer srv.Close()
	cx := ctx(t)
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "host", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteFile(cx, &pb.WriteFileRequest{SandboxId: sb.Id, Path: "/tmp/portserver.py", Data: []byte(portServer)}); err != nil {
		t.Fatal(err)
	}
	pst, err := c.StartProcess(cx, &pb.StartProcessRequest{SandboxId: sb.Id, Cmd: "python3", Args: []string{"/tmp/portserver.py"}})
	if err != nil {
		t.Fatal(err)
	}
	pst.Recv()
	e2bID := strings.Replace(sb.Id, ".", "-", 1)
	req := func(port, token string) *http.Request {
		r, _ := http.NewRequest("GET", srv.URL+"/stream", nil)
		r.Header.Set("E2b-Sandbox-Id", e2bID)
		r.Header.Set("E2b-Sandbox-Port", port)
		if token != "" {
			r.Header.Set("E2B-Traffic-Access-Token", token)
		}
		return r
	}
	var resp *http.Response
	for i := 0; i < 50; i++ { // the server starting
		if resp, err = http.DefaultClient.Do(req("8124", l.AdminToken)); err == nil && resp.StatusCode == 200 {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %v %v", resp, err)
	}
	t0 := time.Now()
	buf := make([]byte, 100)
	n, _ := resp.Body.Read(buf)
	first := time.Since(t0)
	rest, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(buf[:n]) + string(rest)
	if body != "tick 0 leaked=False\ntick 1 leaked=False\ntick 2 leaked=False\n" || first > 250*time.Millisecond {
		t.Fatalf("streamed %q, first chunk after %v", body, first)
	}

	// An upgraded connection, raw.
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /echo HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\nE2b-Sandbox-Id: %s\r\nE2b-Sandbox-Port: 8124\r\nE2B-Traffic-Access-Token: %s\r\n\r\n", e2bID, l.AdminToken)
	br := bufio.NewReader(conn)
	if st, err := br.ReadString('\n'); err != nil || !strings.Contains(st, "101") {
		t.Fatalf("upgrade: %q %v", st, err)
	}
	for {
		if line, _ := br.ReadString('\n'); line == "\r\n" || line == "" {
			break
		}
	}
	for _, msg := range []string{"ping", "pong-" + strings.Repeat("x", 100000)} {
		go conn.Write([]byte(msg))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(br, got); err != nil || string(got) != msg {
			t.Fatalf("echo of %d bytes: %v", len(msg), err)
		}
	}

	if r, err := http.DefaultClient.Do(req("8125", l.AdminToken)); err != nil || r.StatusCode != http.StatusBadGateway {
		t.Fatalf("closed port: %v %v", r, err)
	}
	if r, err := http.DefaultClient.Do(req("8124", "")); err != nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %v %v", r, err)
	}
}

// TestE2BSnapshots (spec §37.10): E2B's fork and snapshots through the
// gateway with E2B's Python SDK (OPENDSEC_E2B_PYTHON), on containers from a
// store image: forks, snapshots by id and by name, Sandbox.create from a
// snapshot, listing and deleting. Memory is checked on microVMs in
// production (MEMORY=1).
func TestE2BSnapshots(t *testing.T) {
	py := os.Getenv("OPENDSEC_E2B_PYTHON")
	if py == "" || agentDir == "" {
		t.Skip("needs OPENDSEC_E2B_PYTHON and the container runtime")
	}
	storeRoot := ownFilesystem(t)
	st, _ := images.NewStore(storeRoot)
	w, _, err := st.BeginLayer(layerID("e2b-snap"))
	if err != nil {
		t.Fatal(err)
	}
	miniRootfs(t, w.Rootfs)
	if _, err := w.Commit(images.LayerMeta{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	state, _ := os.MkdirTemp("", "opendsec")
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(2, 1, 8, 16*1024, 64)
	cfg.ImageStore.Root = storeRoot
	for i := range cfg.Edges {
		cfg.Edges[i].StateDir, cfg.Edges[i].AgentDir = state, agentDir
		cfg.Edges[i].Capacity.DiskMB, cfg.Edges[i].DiskReserveMB = 64*256, 64
		cfg.Edges[i].Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	api, err := client.Dial(cfg.APIServers[0].Addr, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	admin, _ := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	defer admin.Close()
	if _, err := admin.RegisterImage(ctx(t), &pb.RegisterImageRequest{Image: &pb.ImageInfo{Name: "root/env:1",
		Layers: []string{layerID("e2b-snap")}}}); err != nil {
		t.Fatal(err)
	}
	ct := config.E2BTemplate{Backend: "container", CPU: 0.5, MemoryMB: 256}
	base := ct
	base.Image = "root/env:1"
	gw := config.E2B{Project: "root", DefaultTemplate: ct, Templates: map[string]config.E2BTemplate{"base": base}}
	srv := httptest.NewServer(e2b.New(gw, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer srv.Close()

	cx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cx, py, "testdata/e2b_snapshot_check.py")
	cmd.Env = append(os.Environ(), "E2B_API_URL="+srv.URL, "E2B_SANDBOX_URL="+srv.URL, "E2B_API_KEY="+l.AdminToken)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK ") {
		t.Fatalf("e2b snapshot check: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
