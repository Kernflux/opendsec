package rpcutil

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// blackhole forwards TCP to target until frozen, then drops everything in
// both directions without closing: a peer frozen (SIGSTOP) or cut off by a
// network partition.
type blackhole struct {
	ln     net.Listener
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func newBlackhole(t *testing.T, target string) *blackhole {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{ln: ln}
	t.Cleanup(func() {
		ln.Close()
		b.mu.Lock()
		for _, c := range b.conns {
			c.Close()
		}
		b.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			b.mu.Lock()
			b.conns = append(b.conns, c, u)
			b.mu.Unlock()
			go b.pipe(c, u)
			go b.pipe(u, c)
		}
	}()
	return b
}

func (b *blackhole) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				dst.Close()
			}
			return
		}
		if !b.frozen.Load() {
			dst.Write(buf[:n])
		}
	}
}

// TestDialDetectsSilentPeer: a call in flight to a peer that stops
// answering without closing the connection fails within ~15 s (keepalive),
// so callers retry elsewhere instead of waiting for their deadline.
func TestDialDetectsSilentPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(ServerOptions()...)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(ln)
	defer srv.Stop()
	bh := newBlackhole(t, ln.Addr().String())

	conn, err := Dial(bh.ln.Addr().String(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	w, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Recv(); err != nil { // the current status; then the stream waits
		t.Fatal(err)
	}
	bh.frozen.Store(true)
	t0 := time.Now()
	_, err = w.Recv()
	took := time.Since(t0)
	if err == nil || Reason(err) != Unavailable {
		t.Fatalf("Recv after the peer went silent: %v (reason %q)", err, Reason(err))
	}
	if took > 20*time.Second {
		t.Fatalf("silent peer noticed after %v", took)
	}
	t.Logf("silent peer noticed after %v: %v", took.Round(100*time.Millisecond), err)
}
