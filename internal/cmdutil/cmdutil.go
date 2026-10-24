// Package cmdutil holds helpers shared by the cmd/ binaries.
package cmdutil

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/metrics"
)

// Logger returns a text logger at the given level (debug|info|warn|error).
func Logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// WaitSignal blocks until SIGINT or SIGTERM.
func WaitSignal() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

// Drain is the shutdown sequence of a service behind a load balancer (spec
// §27.1): /readyz fails at once, then the process keeps serving for delay so
// the balancer's health checks take it out before its listener closes.
func Drain(log *slog.Logger, delay time.Duration) {
	metrics.Drain()
	if delay > 0 {
		log.Info("draining before shutdown", "delay", delay)
		time.Sleep(delay)
	}
}

func Fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "err", err)
	os.Exit(1)
}

// maxProcs caps the services' GOMAXPROCS unless GOMAXPROCS is set: on a
// 384-thread node an edge with thousands of sandboxes (tens of thousands of
// goroutines) spent ~40% of its CPU in garbage collection, its workers
// contending for shared work queues; it needs nowhere near that many.
const maxProcs = 32

func init() {
	if os.Getenv("GOMAXPROCS") == "" && runtime.GOMAXPROCS(0) > maxProcs {
		runtime.GOMAXPROCS(maxProcs)
	}
}
