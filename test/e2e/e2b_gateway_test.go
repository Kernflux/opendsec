package e2e

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/e2b"
	"github.com/kernflux/opendsec/pkg/client"
)

// TestE2BGateway (spec §37): the gateway's envd routes and connect,
// without an SDK: the env vars need the caller's token every time, a
// multi-file upload keeps each file's directories, gzip uploads are
// stored decompressed, file operations run as the user named, connect
// never shortens a sandbox's life, and /health tells a gone sandbox.
func TestE2BGateway(t *testing.T) {
	l, _ := startContainers(t)
	api, err := client.Dial(l.Cfg.APIServers[0].Addr, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	cfg := config.E2B{Project: "root", Templates: map[string]config.E2BTemplate{
		"base": {Image: "host", Backend: "container", CPU: 1, MemoryMB: 256}}}
	srv := httptest.NewServer(e2b.New(cfg, api, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer srv.Close()

	do := func(method, path, token string, body io.Reader, hdr ...string) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, srv.URL+path, body)
		if token != "" {
			r.Header.Set("X-Access-Token", token)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	var sb struct {
		SandboxID string `json:"sandboxID"`
	}
	code, b := do("POST", "/sandboxes", l.AdminToken,
		strings.NewReader(`{"templateID":"base","timeout":300,"envVars":{"SECRET":"s3cr3t"}}`), "Content-Type", "application/json")
	if code != http.StatusCreated || json.Unmarshal(b, &sb) != nil {
		t.Fatalf("create: %d %s", code, b)
	}
	envd := func(method, path, token string, body io.Reader, hdr ...string) (int, []byte) {
		t.Helper()
		return do(method, path, token, body, append(hdr, "E2b-Sandbox-Id", sb.SandboxID, "E2b-Sandbox-Port", strconv.Itoa(e2b.EnvdPort))...)
	}

	// The env vars, once cached, were served to any token.
	if code, b := envd("GET", "/envs", l.AdminToken, nil); code != 200 || !strings.Contains(string(b), "s3cr3t") {
		t.Fatalf("envs: %d %s", code, b)
	}
	if code, b := envd("GET", "/envs", "dsk.nobody.x", nil); code != http.StatusUnauthorized {
		t.Fatalf("envs with a bad token: %d %s", code, b)
	}

	// Two files of one name in different directories.
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	for _, f := range [][2]string{{"/tmp/up/a/x", "A"}, {"/tmp/up/b/x", "B"}} {
		w, _ := mw.CreateFormFile("file", f[0])
		w.Write([]byte(f[1]))
	}
	mw.Close()
	if code, b := envd("POST", "/files", l.AdminToken, &form, "Content-Type", mw.FormDataContentType()); code != 200 {
		t.Fatalf("multi-file upload: %d %s", code, b)
	}
	for p, want := range map[string]string{"/tmp/up/a/x": "A", "/tmp/up/b/x": "B"} {
		if code, b := envd("GET", "/files?path="+p, l.AdminToken, nil); code != 200 || string(b) != want {
			t.Fatalf("%s: %d %q", p, code, b)
		}
	}

	// A gzip upload is stored as what was compressed.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("hello"))
	zw.Close()
	if code, b := envd("POST", "/files?path=/tmp/up/z", l.AdminToken, &gz, "Content-Type", "application/octet-stream",
		"Content-Encoding", "gzip"); code != 200 {
		t.Fatalf("gzip upload: %d %s", code, b)
	}
	if code, b := envd("GET", "/files?path=/tmp/up/z", l.AdminToken, nil); code != 200 || string(b) != "hello" {
		t.Fatalf("gzip upload stored %d %q", code, b)
	}

	// File operations as the user the SDK names: nobody cannot read
	// /etc/shadow, and what it writes is its own.
	if code, _ := envd("GET", "/files?path=/etc/shadow", l.AdminToken, nil); code != 200 {
		t.Fatalf("shadow as root: %d", code)
	}
	if code, _ := envd("GET", "/files?path=/etc/shadow&username=65534", l.AdminToken, nil); code == 200 {
		t.Fatalf("nobody read /etc/shadow")
	}
	if code, b := envd("POST", "/files?path=/tmp/nobody-mine&username=65534", l.AdminToken, strings.NewReader("m"),
		"Content-Type", "application/octet-stream"); code != 200 {
		t.Fatalf("write as nobody: %d %s", code, b)
	}
	if code, b := envd("POST", "/files?path=/tmp/up/a/y&username=65534", l.AdminToken, strings.NewReader("m"),
		"Content-Type", "application/octet-stream"); code == 200 {
		t.Fatalf("write into root's directory as nobody: %d %s", code, b)
	}

	// connect with a shorter timeout keeps the current end.
	endAt := func() string {
		var d struct {
			EndAt string `json:"endAt"`
		}
		if code, b := do("GET", "/sandboxes/"+sb.SandboxID, l.AdminToken, nil); code != 200 || json.Unmarshal(b, &d) != nil {
			t.Fatalf("get: %d %s", code, b)
		}
		return d.EndAt
	}
	before := endAt()
	if code, b := do("POST", "/sandboxes/"+sb.SandboxID+"/connect", l.AdminToken, strings.NewReader(`{"timeout":10}`),
		"Content-Type", "application/json"); code != 200 {
		t.Fatalf("connect: %d %s", code, b)
	}
	if after := endAt(); after != before {
		t.Fatalf("connect with timeout 10 moved the end from %s to %s", before, after)
	}

	// /health: the sandbox's, not the gateway's.
	if code, b := envd("GET", "/health", l.AdminToken, nil); code != http.StatusNoContent {
		t.Fatalf("health while running: %d %s", code, b)
	}
	if code, b := do("DELETE", "/sandboxes/"+sb.SandboxID, l.AdminToken, nil); code != http.StatusNoContent {
		t.Fatalf("kill: %d %s", code, b)
	}
	if code, b := envd("GET", "/health", l.AdminToken, nil); code != http.StatusBadGateway {
		t.Fatalf("health after kill: %d %s", code, b)
	}
}
