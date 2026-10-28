package microvm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/edge/backend"
)

// fcAPI talks to one Firecracker process over its API socket.
type fcAPI struct {
	c *http.Client
}

func newFCAPI(sock string) *fcAPI {
	return &fcAPI{c: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return backend.DialUnix(ctx, sock)
		},
	}}}
}

func (a *fcAPI) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("firecracker %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// setState pauses ("Paused") or resumes ("Resumed") the VM's vCPUs.
func (a *fcAPI) setState(ctx context.Context, state string) error {
	return a.call(ctx, http.MethodPatch, "/vm", map[string]string{"state": state}, nil)
}

// state returns the VM state ("Running", "Paused", "Not started").
func (a *fcAPI) state(ctx context.Context) (string, error) {
	var info struct {
		State string `json:"state"`
	}
	err := a.call(ctx, http.MethodGet, "/", nil, &info)
	return info.State, err
}

// dialVsock connects to guest port through Firecracker's vsock Unix socket
// (host-initiated connections: "CONNECT <port>\n", answered "OK <n>\n").
func dialVsock(ctx context.Context, uds string, port uint32) (net.Conn, error) {
	c, err := backend.DialUnix(ctx, uds)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		c.Close()
		return nil, err
	}
	// Read the reply byte by byte: anything after it belongs to the stream.
	var line []byte
	b := make([]byte, 1)
	for len(line) < 64 {
		if _, err := c.Read(b); err != nil {
			c.Close()
			return nil, fmt.Errorf("vsock handshake: %w", err)
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	if !strings.HasPrefix(string(line), "OK ") {
		c.Close()
		return nil, fmt.Errorf("vsock handshake: %q", line)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
