package edge

import (
	"context"
	"sort"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
)

// Memory squeezing under node pressure (spec §24). Running sandboxes of
// backends with a balloon give memory back: best-effort ones first, then
// the longest idle, a quarter of their memory per pass up to half; once
// the node has room again the balloons deflate. Guests reclaim what the
// balloon takes from their caches and swap (and take it back on OOM).

const (
	squeezeBelow  = 1.5 // x mem_reserve_mb: squeeze
	releaseAbove  = 3.0 // x mem_reserve_mb: release
	squeezeStep   = 0.25
	squeezeMaxPct = 0.5
)

// balance runs one pass for the node's available memory and reserve (MB).
func (e *Edge) balance(ctx context.Context, avail, reserve int64) {
	type cand struct {
		r  *record
		sq backend.Squeezer
		be backend.Backend
	}
	e.mu.Lock()
	var cands []cand
	for _, r := range e.sbs {
		if r.sb.State != pb.SandboxState_RUNNING {
			continue
		}
		be := e.backends[r.sb.Spec.Backend]
		if sq, ok := be.(backend.Squeezer); ok {
			cands = append(cands, cand{r, sq, be})
		}
	}
	e.mu.Unlock()
	switch {
	case float64(avail) < squeezeBelow*float64(reserve):
		sort.Slice(cands, func(i, j int) bool {
			a, b := cands[i].r, cands[j].r
			if (a.sb.Spec.Qos == "BE") != (b.sb.Spec.Qos == "BE") {
				return a.sb.Spec.Qos == "BE"
			}
			return a.lastActive.Before(b.lastActive)
		})
		need := int64(squeezeBelow*float64(reserve)) - avail
		for _, c := range cands {
			if need <= 0 {
				break
			}
			mem := c.r.sb.Spec.Resources.GetMemoryMb()
			cur := c.r.squeezedMB
			next := min(int64(float64(mem)*squeezeMaxPct), cur+max(1, int64(float64(mem)*squeezeStep)))
			if next <= cur {
				continue
			}
			if err := c.sq.Squeeze(ctx, e.bsb(c.r), next); err != nil {
				continue
			}
			e.mu.Lock()
			c.r.squeezedMB = next
			e.mu.Unlock()
			need -= next - cur
		}
	case float64(avail) > releaseAbove*float64(reserve):
		for _, c := range cands {
			if c.r.squeezedMB == 0 {
				continue
			}
			if c.sq.Squeeze(ctx, e.bsb(c.r), 0) == nil {
				e.mu.Lock()
				c.r.squeezedMB = 0
				e.mu.Unlock()
			}
		}
	}
}
