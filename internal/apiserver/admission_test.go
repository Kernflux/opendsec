package apiserver

import (
	"context"
	"math"
	"testing"
	"time"

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
	if s.applyTTLs(sp); sp.TtlMaxS != 0 || sp.TtlRunningStopS != 0 {
		t.Fatal("no policy must leave TTLs alone")
	}
	c := config.Cluster{}
	c.Defaults()
	s.SetAdmission(c.Admission)
	sp = &pb.SandboxSpec{}
	if err := s.applyTTLs(sp); err != nil || sp.TtlRunningStopS != 3600 || sp.TtlMaxS != 86400 {
		t.Fatalf("defaults: %v %+v", err, sp)
	}
	sp = &pb.SandboxSpec{TtlRunningStopS: 60, TtlMaxS: 120}
	if s.applyTTLs(sp); sp.TtlRunningStopS != 60 || sp.TtlMaxS != 120 {
		t.Fatalf("explicit TTLs overridden: %+v", sp)
	}
	if err := s.applyTTLs(&pb.SandboxSpec{TtlMaxS: 8 * 86400}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("ttl_max above the cap: %v", err)
	}
	// A cap below the default lifetime bounds the default too; with no
	// default lifetime the cap applies.
	s.SetAdmission(config.Admission{DefaultTTLMax: 86400, MaxTTLMax: 600})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp) != nil || sp.TtlMaxS != 600 {
		t.Fatalf("default above the cap: %+v", sp)
	}
	s.SetAdmission(config.Admission{DefaultTTLMax: -1, MaxTTLMax: 600})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp) != nil || sp.TtlMaxS != 600 {
		t.Fatalf("no default, capped: %+v", sp)
	}
	s.SetAdmission(config.Admission{DefaultTTLRunningStop: -1, DefaultTTLMax: -1, MaxTTLMax: -1})
	if sp = (&pb.SandboxSpec{}); s.applyTTLs(sp) != nil || sp.TtlMaxS != 0 || sp.TtlRunningStopS != 0 {
		t.Fatalf("-1 must disable defaults and cap: %+v", sp)
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
