package apiserver

import (
	"context"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(10, 3)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if l.allow("a") {
		t.Fatal("allowed past the burst")
	}
	if !l.allow("b") {
		t.Fatal("keys must not share a bucket")
	}
	now = now.Add(100 * time.Millisecond) // 10/s: one token back
	if !l.allow("a") || l.allow("a") {
		t.Fatal("refill is not rate-proportional")
	}
	now = now.Add(time.Hour)
	if l.exhausted("a") {
		t.Fatal("bucket did not refill")
	}
	for i := 0; i < 3; i++ {
		l.charge("a")
	}
	if !l.exhausted("a") {
		t.Fatal("charge did not take tokens")
	}
	if newLimiter(-1, 5) != nil || newLimiter(0, 5) != nil {
		t.Fatal("a non-positive rate must disable the limiter")
	}
}

func TestLimiterWaitPaces(t *testing.T) {
	l := newLimiter(100, 1) // 10 ms per token after the first
	start := time.Now()
	for i := 0; i < 11; i++ {
		if err := l.wait(context.Background(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 90*time.Millisecond {
		t.Fatalf("11 waits at 100/s took only %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 5; i++ {
		l.wait(ctx, "b") // the first is free; the others are cancelled and refunded
	}
	l.mu.Lock()
	tokens := l.bucketLocked("b").tokens
	l.mu.Unlock()
	if tokens < -0.1 {
		t.Fatalf("cancelled waits kept their tokens: %v", tokens)
	}
}

func TestApplyTTLs(t *testing.T) {
	s := &Server{}
	sp := &pb.SandboxSpec{}
	if s.applyTTLs(sp, "root"); sp.TtlMaxS != 0 || sp.TtlRunningStopS != 0 {
		t.Fatal("no policy must leave TTLs alone")
	}
	c := config.Cluster{}
	c.Defaults()
	s.SetAdmission(c.Admission)
	sp = &pb.SandboxSpec{}
	if err := s.applyTTLs(sp, "root"); err != nil || sp.TtlRunningStopS != 3600 || sp.TtlMaxS != 86400 {
		t.Fatalf("defaults: %v %+v", err, sp)
	}
	sp = &pb.SandboxSpec{TtlRunningStopS: 60, TtlMaxS: 120}
	if s.applyTTLs(sp, "root"); sp.TtlRunningStopS != 60 || sp.TtlMaxS != 120 {
		t.Fatalf("explicit TTLs overridden: %+v", sp)
	}
	if err := s.applyTTLs(&pb.SandboxSpec{TtlMaxS: 8 * 86400}, "root"); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("ttl_max above the cap: %v", err)
	}
	// A cap below the default lifetime bounds the default too; with no
	// default lifetime the cap applies.
	s.SetAdmission(config.Admission{DefaultTTLMax: 86400, MaxTTLMax: 600})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp, "root") != nil || sp.TtlMaxS != 600 {
		t.Fatalf("default above the cap: %+v", sp)
	}
	s.SetAdmission(config.Admission{DefaultTTLMax: -1, MaxTTLMax: 600})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp, "root") != nil || sp.TtlMaxS != 600 {
		t.Fatalf("no default, capped: %+v", sp)
	}
	s.SetAdmission(config.Admission{DefaultTTLRunningStop: -1, DefaultTTLMax: -1, MaxTTLMax: -1})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp, "root") != nil || sp.TtlMaxS != 0 || sp.TtlRunningStopS != 0 {
		t.Fatalf("-1 must disable defaults and cap: %+v", sp)
	}
}

// A project's TTLs apply to it and its subprojects; entries along the path
// combine, the longer path's winning; a cap only ever lowers.
func TestProjectTTLs(t *testing.T) {
	s := &Server{}
	c := config.Cluster{}
	c.Defaults()
	c.Admission.Projects = map[string]config.ProjectAdmission{
		"root/try":       {DefaultTTLRunningStop: 300, MaxTTLMax: 3600},
		"root/try/long":  {MaxTTLMax: 30 * 86400},
		"root/try/short": {DefaultTTLMax: 600},
		"root/try/u":     {MaxImages: 5, ImageTTL: 86400},
		"root/try/u/big": {MaxImages: 50, MaxImageMB: 1024},
	}
	s.SetAdmission(c.Admission)
	for _, tc := range []struct {
		project   string
		ask       int64
		stop, max int64
		refused   bool
	}{
		{"root", 0, 3600, 86400, false},
		{"root/tryx", 0, 3600, 86400, false}, // not a subproject
		{"root/try", 0, 300, 3600, false},
		{"root/try/u/gh-1", 0, 300, 3600, false},
		{"root/try/u/gh-1", 7200, 0, 0, true},
		{"root/try/u/gh-1", 1800, 300, 1800, false},
		{"root/try/long", 0, 300, 3600, false}, // its cap cannot raise root/try's
		{"root/try/long", 7200, 0, 0, true},
		{"root/try/short", 0, 300, 600, false},
	} {
		sp := &pb.SandboxSpec{TtlMaxS: tc.ask}
		err := s.applyTTLs(sp, tc.project)
		if tc.refused {
			if rpcutil.Reason(err) != rpcutil.Invalid {
				t.Errorf("%s asking %d: want refused, got %v", tc.project, tc.ask, err)
			}
			continue
		}
		if err != nil || sp.TtlRunningStopS != tc.stop || sp.TtlMaxS != tc.max {
			t.Errorf("%s asking %d: %v stop=%d max=%d, want %d %d", tc.project, tc.ask, err, sp.TtlRunningStopS, sp.TtlMaxS, tc.stop, tc.max)
		}
	}
	// Image limits combine the same way.
	for p, want := range map[string]config.ProjectAdmission{
		"root":             {},
		"root/try":         {},
		"root/try/u/gh-1":  {MaxImages: 5, ImageTTL: 86400},
		"root/try/u/big":   {MaxImages: 50, MaxImageMB: 1024, ImageTTL: 86400},
		"root/try/u/big/x": {MaxImages: 50, MaxImageMB: 1024, ImageTTL: 86400},
	} {
		if got := c.Admission.For(p).Image; got != want {
			t.Errorf("%s: image limits %+v, want %+v", p, got, want)
		}
	}
}

func TestValidateSpecNonFinite(t *testing.T) {
	for _, cpu := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		sp := &pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: cpu}}
		if err := validateSpec(sp); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Fatalf("cpu %g: %v", cpu, err)
		}
	}
	if err := validateSpec(&pb.SandboxSpec{Backend: "sim", Resources: &pb.Resources{CpuCores: 0.5}}); err != nil {
		t.Fatal(err)
	}
}

// Behind trusted proxies, limits per client address use the caller's
// address from X-Forwarded-For; a client cannot pass as another by sending
// the header itself.
func TestClientAddr(t *testing.T) {
	s := &Server{}
	s.SetAdmission(config.Admission{TrustedProxies: []string{"10.20.0.5", "10.0.0.0/8"}})
	call := func(peerIP string, xff ...string) string {
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(peerIP), Port: 5000}})
		if len(xff) > 0 {
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", strings.Join(xff, ", ")))
		}
		return s.clientAddr(ctx)
	}
	for _, tc := range []struct {
		got, want string
	}{
		{call("203.0.113.9"), "203.0.113.9"},
		{call("203.0.113.9", "198.51.100.1"), "203.0.113.9"},                       // not a proxy: its header is ignored
		{call("10.20.0.5", "198.51.100.1"), "198.51.100.1"},                        // TLS proxy
		{call("10.1.2.3", "6.6.6.6", "198.51.100.1", "10.20.0.5"), "198.51.100.1"}, // proxy, gateway; the first entry is the client's own claim
		{call("10.20.0.5"), "10.20.0.5"},                                           // a proxy's own call
	} {
		if tc.got != tc.want {
			t.Errorf("got %s, want %s", tc.got, tc.want)
		}
	}
}
