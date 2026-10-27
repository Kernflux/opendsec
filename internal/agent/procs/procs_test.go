package procs

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// events collects a process stream.
type events struct {
	mu     sync.Mutex
	pid    uint32
	out    strings.Builder
	errb   strings.Builder
	exit   *pb.ProcessExit
	notify chan struct{}
}

func newEvents() *events { return &events{notify: make(chan struct{}, 1)} }

func (e *events) send(ev *pb.ProcessEvent) error {
	e.mu.Lock()
	switch x := ev.Event.(type) {
	case *pb.ProcessEvent_Started:
		e.pid = x.Started
	case *pb.ProcessEvent_Stdout:
		e.out.Write(x.Stdout)
	case *pb.ProcessEvent_Pty:
		e.out.Write(x.Pty)
	case *pb.ProcessEvent_Stderr:
		e.errb.Write(x.Stderr)
	case *pb.ProcessEvent_Exit:
		e.exit = x.Exit
	}
	e.mu.Unlock()
	select {
	case e.notify <- struct{}{}:
	default:
	}
	return nil
}

func (e *events) stdout() string { e.mu.Lock(); defer e.mu.Unlock(); return e.out.String() }

// waitFor waits until f holds.
func (e *events) waitFor(t *testing.T, what string, f func(*events) bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		e.mu.Lock()
		ok := f(e)
		e.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-e.notify:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("timed out waiting for %s (stdout %q)", what, e.stdout())
		}
	}
}

func start(t *testing.T, m *Manager, r *pb.StartProcessRequest) (*events, chan error, context.CancelFunc) {
	t.Helper()
	ev := newEvents()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx, r, ev.send) }()
	ev.waitFor(t, "start", func(e *events) bool { return e.pid != 0 })
	return ev, done, cancel
}

func newManager(t *testing.T) *Manager {
	return New(Config{Workdir: t.TempDir(), Env: map[string]string{"BASE": "base"}})
}

func TestRunAndExit(t *testing.T) {
	m := newManager(t)
	ev := newEvents()
	err := m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "sh",
		Args: []string{"-c", `echo "$BASE $X $(pwd)"; echo oops >&2; exit 3`}, Env: map[string]string{"X": "x"}, Cwd: "/tmp"}, ev.send)
	if err != nil {
		t.Fatal(err)
	}
	if got := ev.stdout(); got != "base x /tmp\n" || ev.errb.String() != "oops\n" {
		t.Fatalf("stdout %q stderr %q", got, ev.errb.String())
	}
	if !ev.exit.Exited || ev.exit.ExitCode != 3 || ev.exit.Status != "exit status 3" {
		t.Fatalf("exit %+v", ev.exit)
	}
	if n := len(m.List().Processes); n != 0 {
		t.Fatalf("%d processes left", n)
	}
	err = m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "no-such-command"}, ev.send)
	if rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("missing command: %v", err)
	}
}

func TestStdinSignalAndTag(t *testing.T) {
	m := newManager(t)
	ev, done, cancel := start(t, m, &pb.StartProcessRequest{Cmd: "cat", Stdin: true, Tag: "echo"})
	defer cancel()
	if err := m.Input(&pb.ProcessInput{Tag: "echo", Data: []byte("hello\n")}); err != nil {
		t.Fatal(err)
	}
	ev.waitFor(t, "echo", func(e *events) bool { return e.out.String() == "hello\n" })
	_, _, cancelOther := start(t, m, &pb.StartProcessRequest{Cmd: "sleep", Args: []string{"30"}, Tag: "other"})
	defer cancelOther()
	if err := m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "true", Tag: "echo"}, ev.send); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("duplicate tag: %v", err)
	}
	l := m.List().Processes
	if len(l) != 2 || l[0].Pid == 0 {
		t.Fatalf("list %v", l)
	}
	if err := m.CloseStdin(&pb.ProcessRef{Pid: ev.pid}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !ev.exit.Exited || ev.exit.ExitCode != 0 {
		t.Fatalf("cat after closing stdin: %+v", ev.exit)
	}
	// SIGKILL to the other one (and its group).
	other, _ := m.get(0, "other")
	if err := m.Signal(&pb.ProcessSignal{Tag: "other", Signal: 9}); err != nil {
		t.Fatal(err)
	}
	<-other.done
	if other.exit.Exited || other.exit.ExitCode != -1 || other.exit.Status != "signal: killed" {
		t.Fatalf("killed: %+v", other.exit)
	}
	if err := m.Input(&pb.ProcessInput{Pid: other.info.Pid, Data: []byte("x")}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("input to an ended process: %v", err)
	}
}

// TestDetachAndConnect: a stream going away leaves its process running; a
// later Connect gets its output from then on, and its exit.
func TestDetachAndConnect(t *testing.T) {
	m := newManager(t)
	_, done, cancel := start(t, m, &pb.StartProcessRequest{Cmd: "sh", Args: []string{"-c", "read x; echo got $x"}, Stdin: true})
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("detached stream: %v", err)
	}
	l := m.List().Processes
	if len(l) != 1 {
		t.Fatalf("process gone with its stream: %v", l)
	}
	ev := newEvents()
	cdone := make(chan error, 1)
	go func() { cdone <- m.Connect(context.Background(), &pb.ProcessRef{Pid: l[0].Pid}, ev.send) }()
	ev.waitFor(t, "connect", func(e *events) bool { return e.pid == l[0].Pid })
	m.Input(&pb.ProcessInput{Pid: l[0].Pid, Data: []byte("it\n")})
	if err := <-cdone; err != nil {
		t.Fatal(err)
	}
	if ev.stdout() != "got it\n" || ev.exit.ExitCode != 0 {
		t.Fatalf("stdout %q exit %+v", ev.stdout(), ev.exit)
	}
}

func TestPty(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	m := newManager(t)
	ev, done, cancel := start(t, m, &pb.StartProcessRequest{Cmd: "sh", Pty: &pb.PtySize{Cols: 100, Rows: 30},
		Args: []string{"-c", `tty; stty size; echo "term=$TERM"; read x; stty size`}})
	defer cancel()
	ev.waitFor(t, "first size", func(e *events) bool { return strings.Contains(e.out.String(), "term=") })
	out := ev.stdout()
	if !strings.Contains(out, "/dev/pts/") || !strings.Contains(out, "30 100") || !strings.Contains(out, "term=xterm-256color") {
		t.Fatalf("pty output %q", out)
	}
	if err := m.Resize(&pb.ProcessResize{Pid: ev.pid, Size: &pb.PtySize{Cols: 120, Rows: 40}}); err != nil {
		t.Fatal(err)
	}
	m.Input(&pb.ProcessInput{Pid: ev.pid, Data: []byte("go\r")})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev.stdout(), "40 120") || ev.exit.ExitCode != 0 {
		t.Fatalf("after resize: %q %+v", ev.stdout(), ev.exit)
	}
}

// TestLeftBehind: a background child holding the output pipes does not
// keep the exit from being reported.
func TestLeftBehind(t *testing.T) {
	m := newManager(t)
	ev := newEvents()
	t0 := time.Now()
	if err := m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "sh", Args: []string{"-c", "sleep 30 & echo started"}}, ev.send); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > drainGrace+3*time.Second || ev.stdout() != "started\n" || ev.exit.ExitCode != 0 {
		t.Fatalf("took %v, stdout %q, exit %+v", d, ev.stdout(), ev.exit)
	}
}

func TestUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	m := newManager(t)
	ev := newEvents()
	if err := m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "sh", Args: []string{"-c", "id -u; echo $HOME"},
		User: "65534:65534", Cwd: "/tmp"}, ev.send); err != nil {
		t.Fatal(err)
	}
	if ev.stdout() != "65534\n/tmp/home-65534\n" {
		t.Fatalf("as 65534: %q", ev.stdout())
	}
}

// TestRelativePath: a relative PATH entry is relative to the process's
// cwd, not to the agent's.
func TestRelativePath(t *testing.T) {
	m := newManager(t)
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/prog", []byte("#!/bin/sh\necho from-cwd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ev := newEvents()
	err := m.Start(context.Background(), &pb.StartProcessRequest{Cmd: "prog", Cwd: dir,
		Env: map[string]string{"PATH": ".:/usr/bin:/bin"}}, ev.send)
	if err != nil || ev.stdout() != "from-cwd\n" {
		t.Fatalf("got %q, %v", ev.stdout(), err)
	}
}
