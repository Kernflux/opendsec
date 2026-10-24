package metrics

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReadiness(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close()
	Serve(addr, nil)
	get := func(path string) (int, string) {
		t.Helper()
		var r *http.Response
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if r, err = http.Get("http://" + addr + path); err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}

	var broken error
	SetReady("a", func() error { return nil })
	SetReady("b", func() error { return broken })
	t.Cleanup(func() { SetReady("a", nil); SetReady("b", nil) })
	if code, _ := get("/readyz"); code != 200 {
		t.Fatalf("ready: %d", code)
	}
	broken = errors.New("no leader")
	if code, body := get("/readyz"); code != 503 || !strings.Contains(body, "b: no leader") {
		t.Fatalf("not ready: %d %q", code, body)
	}
	if !strings.Contains(Text(), "opendsec_ready 0") {
		t.Error("opendsec_ready should be 0")
	}
	SetReady("b", nil)
	if code, _ := get("/readyz"); code != 200 {
		t.Fatalf("check removed: %d", code)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
	if !strings.Contains(Text(), `opendsec_build_info{version="`) {
		t.Error("no build info")
	}

	Drain()
	t.Cleanup(func() { draining.Store(false) })
	if code, body := get("/readyz"); code != 503 || !strings.Contains(body, "shutting down") {
		t.Fatalf("draining: %d %q", code, body)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz while draining: %d", code)
	}
}
