package fleet

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
)

// TestGates: a gate over its max pauses a rollout, and so does one that
// cannot be read; no samples read as 0, but only while Prometheus scrapes
// OpenDsec at all. Rollbacks, and a rollout resumed after a gate paused
// it, are not stopped.
func TestGates(t *testing.T) {
	var body, up, upQuery string
	var status int
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if q := r.URL.Query().Get("query"); q != "x" {
			upQuery = q
			io.WriteString(w, up)
			return
		}
		io.WriteString(w, body)
	}))
	defer prom.Close()
	sample := func(v string) string {
		return `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"` + v + `"]}]}}`
	}
	const empty = `{"status":"success","data":{"resultType":"vector","result":[]}}`
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), opt: Options{Now: time.Now,
		Cfg: config.Fleet{PrometheusURL: prom.URL, Gates: []config.FleetGate{{Name: "errors", Query: "x", Max: 1}}}}}
	for _, c := range []struct {
		name, body, up string
		status         int
		ro             *pb.FleetRollout
		paused         string // "" = not paused
	}{
		{"under max", sample("0.5"), sample("1"), 200, &pb.FleetRollout{}, ""},
		{"over max", sample("3"), sample("1"), 200, &pb.FleetRollout{}, "paused: gate errors: 3 > 1"},
		{"NaN", sample("NaN"), sample("1"), 200, &pb.FleetRollout{}, "paused: gate errors: NaN > 1"},
		{"no samples", empty, sample("1"), 200, &pb.FleetRollout{}, ""},
		{"nothing scraped", empty, empty, 200, &pb.FleetRollout{}, "paused: gate data unavailable"},
		{"every target down", empty, sample("0"), 200, &pb.FleetRollout{}, "paused: gate data unavailable"},
		{"prometheus failing", "oops", "oops", 503, &pb.FleetRollout{}, "paused: gate data unreadable"},
		{"rollback", sample("3"), empty, 200, &pb.FleetRollout{Rollback: true}, ""},
		{"waived", sample("3"), empty, 200, &pb.FleetRollout{GatesWaived: true}, ""},
	} {
		body, up, status = c.body, c.up, c.status
		c.ro.State = rsRunning
		got := s.gatePaused(context.Background(), c.ro)
		if got != (c.paused != "") || (got && (c.ro.State != rsPaused || !strings.HasPrefix(c.ro.Message, c.paused))) {
			t.Errorf("%s: paused=%v state=%s message=%q; want %q", c.name, got, c.ro.State, c.ro.Message, c.paused)
		}
	}
	if upQuery != defaultGatesUp {
		t.Errorf("scrape check %q, want %q", upQuery, defaultGatesUp)
	}
	s.opt.Cfg.GatesUp = `up{job="sandbox"}`
	body, up, status = empty, sample("1"), 200
	if ro := (&pb.FleetRollout{State: rsRunning}); s.gatePaused(context.Background(), ro) || upQuery != s.opt.Cfg.GatesUp {
		t.Errorf("gates_up %q: paused=%v, queried %q", s.opt.Cfg.GatesUp, ro.State == rsPaused, upQuery)
	}
	prom.Close()
	if ro := (&pb.FleetRollout{State: rsRunning}); !s.gatePaused(context.Background(), ro) {
		t.Error("prometheus down: the rollout went on")
	}
}
