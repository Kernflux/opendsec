package apiserver

import (
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// ---- admission policy (spec §18) -----------------------------------------------------

// SetAdmission installs the cluster's admission policy: TTL defaults and
// caps, per-principal rate limits and the in-flight creation cap. Without it
// the server applies none of them.
func (s *Server) SetAdmission(a config.Admission) {
	s.adm = a
	s.reqLimit = newLimiter(a.RequestRate, a.RequestBurst)
	s.createLimit = newLimiter(a.CreateRate, a.CreateBurst)
	s.authFailLimit = newLimiter(a.AuthFailRate, 2*a.AuthFailRate)
	if a.MaxInflightCreates > 0 {
		s.inflight = make(chan struct{}, a.MaxInflightCreates)
	}
}

// applyTTLs fills in default TTLs and enforces the lifetime cap, so every
// sandbox is eventually reclaimed even when its creator forgets it.
func (s *Server) applyTTLs(sp *pb.SandboxSpec) error {
	a := s.adm
	capMax := int64(a.MaxTTLMax)
	if capMax > 0 && sp.TtlMaxS > capMax {
		return rpcutil.Err(rpcutil.Invalid, "ttl_max_s %d exceeds the maximum %d", sp.TtlMaxS, capMax)
	}
	if sp.TtlPausedS < 0 {
		return rpcutil.Err(rpcutil.Invalid, "ttl_paused_s must be >= 0")
	}
	if capMax > 0 && sp.TtlPausedS > capMax { // kept paused at most the cap on lifetimes
		sp.TtlPausedS = capMax
	}
	if sp.TtlRunningStopS == 0 && a.DefaultTTLRunningStop > 0 {
		sp.TtlRunningStopS = int64(a.DefaultTTLRunningStop)
	}
	if sp.TtlMaxS == 0 {
		if a.DefaultTTLMax > 0 {
			sp.TtlMaxS = int64(a.DefaultTTLMax)
		}
		if capMax > 0 && (sp.TtlMaxS == 0 || sp.TtlMaxS > capMax) {
			sp.TtlMaxS = capMax
		}
	}
	return nil
}

// acquireCreate waits for an in-flight creation slot (bounding the load one
// apiserver puts on IAM and the edges); release with releaseCreate.
func (s *Server) acquireCreate(ctx context.Context) error {
	if s.inflight == nil {
		return nil
	}
	select {
	case s.inflight <- struct{}{}:
		return nil
	case <-ctx.Done():
		return rpcutil.Err(rpcutil.Timeout, "waiting for a creation slot: %v", ctx.Err())
	}
}

func (s *Server) releaseCreate() {
	if s.inflight != nil {
		<-s.inflight
	}
}

// limitCreate charges one creation to the principal's creation rate. Single
// creations are rejected when over the rate; batch creations wait, which
// paces a large batch instead of failing part of it.
func (s *Server) limitCreate(ctx context.Context, principal string, wait bool) error {
	if s.createLimit == nil {
		return nil
	}
	if wait {
		if err := s.createLimit.wait(ctx, principal); err != nil {
			return rpcutil.Err(rpcutil.Timeout, "creation rate limit: %v", err)
		}
		return nil
	}
	if !s.createLimit.allow(principal) {
		return rpcutil.Err(rpcutil.RateLimited, "creation rate limit (%g/s) exceeded for %s", s.adm.CreateRate, principal)
	}
	return nil
}

// admitCall authenticates a public call and charges it to the caller's
// request rate. Failed authentications are limited per client address, so
// guessing tokens cannot load IAM.
func (s *Server) admitCall(ctx context.Context) error {
	if s.reqLimit == nil && s.authFailLimit == nil {
		return nil
	}
	tok := rpcutil.BearerToken(ctx)
	if tok == "" {
		return nil // the handler reports unauthenticated
	}
	// Tokens already authenticated are served from the cache and never hit
	// IAM, so only uncached ones count against the client address.
	addr := peerHost(ctx)
	if s.authFailLimit != nil && !s.authCached(tok) && s.authFailLimit.exhausted(addr) {
		return rpcutil.Err(rpcutil.RateLimited, "too many failed authentications from %s", addr)
	}
	p, err := s.principal(ctx)
	if err != nil {
		if s.authFailLimit != nil && rpcutil.Reason(err) == rpcutil.Unauthenticated {
			s.authFailLimit.charge(addr)
		}
		return err
	}
	if s.reqLimit != nil && !s.reqLimit.allow(p) {
		return rpcutil.Err(rpcutil.RateLimited, "request rate limit (%g/s) exceeded for %s", s.adm.RequestRate, p)
	}
	return nil
}

func (s *Server) authCached(tok string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	e, ok := s.authn[tok]
	return ok && time.Now().Before(e.exp)
}

func peerHost(ctx context.Context) string {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.Addr == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(pr.Addr.String())
	if err != nil {
		return pr.Addr.String()
	}
	return h
}

// ServerOptions returns the interceptors enforcing admitCall on every
// public call. Place them after the audit interceptors so rejections are
// audited too.
func (s *Server) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := s.admitCall(ctx); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := s.admitCall(ss.Context()); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	}
}

// ---- token buckets -------------------------------------------------------------------

const limiterMaxKeys = 100000

// limiter is a set of token buckets, one per key (principal or address).
type limiter struct {
	rate, burst float64
	now         func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter returns nil (no limit) for a non-positive rate.
func newLimiter(rate, burst float64) *limiter {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &limiter{rate: rate, burst: burst, now: time.Now, buckets: map[string]*bucket{}}
}

// bucketLocked returns key's bucket, refilled to now.
func (l *limiter) bucketLocked(key string) *bucket {
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= limiterMaxKeys {
			l.gcLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
		return b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	return b
}

// gcLocked drops buckets that have refilled completely (indistinguishable
// from new ones), or everything if all keys are active.
func (l *limiter) gcLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= limiterMaxKeys {
		l.buckets = map[string]*bucket{}
	}
}

// allow takes a token if one is available.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketLocked(key)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// wait takes a token, sleeping until it is due.
func (l *limiter) wait(ctx context.Context, key string) error {
	l.mu.Lock()
	b := l.bucketLocked(key)
	b.tokens--
	delay := time.Duration(-b.tokens / l.rate * float64(time.Second))
	l.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		l.mu.Lock()
		b := l.bucketLocked(key)
		b.tokens = min(l.burst, b.tokens+1) // not used: give it back
		l.mu.Unlock()
		return ctx.Err()
	}
}

// exhausted reports whether key has no token left, without taking one.
func (l *limiter) exhausted(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bucketLocked(key).tokens < 1
}

// charge takes a token, if any is left.
func (l *limiter) charge(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.bucketLocked(key); b.tokens >= 1 {
		b.tokens--
	}
}
