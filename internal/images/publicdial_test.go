package images

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	for addr, want := range map[string]bool{"1.1.1.1": true, "8.8.8.8": true, "2606:4700::1111": true,
		"10.1.2.3": false, "192.168.1.10": false, "172.20.0.1": false, "127.0.0.1": false, "169.254.169.254": false,
		"100.100.100.200": false, "0.0.0.0": false, "::1": false, "fd00::1": false, "fe80::1": false,
		"::ffff:192.168.0.1": false, "::ffff:1.1.1.1": true} {
		if got := IsPublicIP(net.ParseIP(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

// A pull for an untrusted user cannot reach the local network, even by a
// redirect; an allowed mirror can be.
func TestPublicClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := PublicClient(5*time.Second, nil)
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("reached a loopback registry: %v", err)
	}
	c = PublicClient(5*time.Second, []string{host})
	req, _ = http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("allowed mirror: %v", err)
	}
	resp.Body.Close()
	req, _ = http.NewRequestWithContext(ctx, "GET", srv.URL+"/redirect", nil)
	if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("followed a redirect inside: %v", err)
	}
}

// Untrusted extraction stops at its byte and entry limits.
func TestExtractLimits(t *testing.T) {
	mk := func(files int, size int) *bytes.Buffer {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for i := 0; i < files; i++ {
			tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d", i), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(size)})
			tw.Write(make([]byte, size))
		}
		tw.Close()
		return &b
	}
	if _, err := extractLayer(mk(2, 1<<20), t.TempDir(), &budget{maxBytes: 3 << 20}); err != nil {
		t.Fatalf("within the limit: %v", err)
	}
	if _, err := extractLayer(mk(4, 1<<20), t.TempDir(), &budget{maxBytes: 3 << 20}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("past the byte limit: %v", err)
	}
	if _, err := extractLayer(mk(11, 1), t.TempDir(), &budget{maxEntries: 10}); err == nil || !strings.Contains(err.Error(), "more than 10 files") {
		t.Fatalf("past the entry limit: %v", err)
	}
	// A budget carries over layers.
	b := &budget{maxBytes: 3 << 20}
	extractLayer(mk(2, 1<<20), t.TempDir(), b)
	if _, err := extractLayer(mk(2, 1<<20), t.TempDir(), b); err == nil {
		t.Fatal("the second layer passed the image's limit")
	}
}
