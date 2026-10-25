// Package cmdutil holds helpers shared by the cmd/ binaries.
package cmdutil

import (
	"context"
	"fmt"
	"io"
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
	opts := &slog.HandlerOptions{Level: l}
	if !toJournal() {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	var h journalHandler
	for i, p := range []string{"<3>", "<4>", "<6>", "<7>"} {
		h[i] = slog.NewTextHandler(prefixWriter{p, os.Stderr}, opts)
	}
	return slog.New(h)
}

// toJournal reports whether stderr is a stream to journald: systemd sets
// JOURNAL_STREAM to its device and inode.
func toJournal() bool {
	js := os.Getenv("JOURNAL_STREAM")
	fi, err := os.Stderr.Stat()
	if js == "" || err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && js == fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

// journalHandler starts each record with its syslog priority ("<4>" for a
// warning), which journald takes off the line as the entry's priority
// (SyslogLevelPrefix=, on by default), so that `journalctl -p warning`
// finds the warnings and errors. Its handlers are for error, warning,
// info and debug.
type journalHandler [4]slog.Handler

func (h journalHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h[0].Enabled(ctx, l)
}

func (h journalHandler) Handle(ctx context.Context, r slog.Record) error {
	i := 3
	switch {
	case r.Level >= slog.LevelError:
		i = 0
	case r.Level >= slog.LevelWarn:
		i = 1
	case r.Level >= slog.LevelInfo:
		i = 2
	}
	return h[i].Handle(ctx, r)
}

func (h journalHandler) WithAttrs(as []slog.Attr) slog.Handler {
	for i := range h {
		h[i] = h[i].WithAttrs(as)
	}
	return h
}

func (h journalHandler) WithGroup(name string) slog.Handler {
	for i := range h {
		h[i] = h[i].WithGroup(name)
	}
	return h
}

// prefixWriter writes each record (a text handler writes one per Write)
// after prefix, in one write.
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func (p prefixWriter) Write(b []byte) (int, error) {
	if _, err := p.w.Write(append([]byte(p.prefix), b...)); err != nil {
		return 0, err
	}
	return len(b), nil
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
