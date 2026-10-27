// Package procs runs the processes of the process API (spec §37): commands
// started as processes of their own, outside shell sessions, the way E2B's
// envd runs them. A process is addressed by pid or by an optional tag, can
// take stdin and signals, and can run on a PTY. Streams attach to it: the
// one that started it, and any number of later ones (Connect); a stream
// ending never ends its process.
package procs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/chronus"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// MaxProcs bounds the processes running at once in a sandbox.
const MaxProcs = 1024

// drainGrace is how long a process's output is still read after it exited:
// a child it left behind may hold the pipes or the terminal open forever.
const drainGrace = 2 * time.Second

type Config struct {
	Workdir string            // cwd when the request has none
	User    string            // user when the request has none ("" = root)
	Env     map[string]string // the sandbox's environment
}

type Manager struct {
	cfg Config

	mu    sync.Mutex
	procs map[uint32]*proc
	tags  map[string]uint32
}

func New(cfg Config) *Manager {
	return &Manager{cfg: cfg, procs: map[uint32]*proc{}, tags: map[string]uint32{}}
}

type proc struct {
	info  *pb.ProcessInfo
	cmd   *exec.Cmd
	pty   *os.File       // the terminal's master side, for PTY processes
	stdin io.WriteCloser // pipe, or pty; nil without stdin

	mu   sync.Mutex
	subs map[*sub]bool
	exit *pb.ProcessExit
	done chan struct{} // closed once exit is set and all output was published
}

// sub is one attached stream.
type sub struct {
	ch   chan *pb.ProcessEvent
	gone chan struct{}
}

// publish hands ev to every attached stream, waiting for slow ones (the
// process then waits on its pipe: backpressure) but not for gone ones.
func (p *proc) publish(ev *pb.ProcessEvent) {
	p.mu.Lock()
	subs := make([]*sub, 0, len(p.subs))
	for s := range p.subs {
		subs = append(subs, s)
	}
	p.mu.Unlock()
	for _, s := range subs {
		select {
		case s.ch <- ev:
		case <-s.gone:
		}
	}
}

func (p *proc) attach() *sub {
	s := &sub{ch: make(chan *pb.ProcessEvent, 64), gone: make(chan struct{})}
	p.mu.Lock()
	p.subs[s] = true
	p.mu.Unlock()
	return s
}

func (p *proc) detach(s *sub) {
	p.mu.Lock()
	delete(p.subs, s)
	p.mu.Unlock()
	close(s.gone)
}

// stream sends p's events to send until it exits (the exit event last) or
// ctx ends; s was attached before p could produce output.
func (p *proc) stream(ctx context.Context, s *sub, send func(*pb.ProcessEvent) error) error {
	defer p.detach(s)
	if err := send(&pb.ProcessEvent{Event: &pb.ProcessEvent_Started{Started: p.info.Pid}}); err != nil {
		return err
	}
	for {
		select {
		case ev := <-s.ch:
			if err := send(ev); err != nil {
				return err
			}
		case <-p.done:
			for { // all output was published before done: drain it, then the exit
				select {
				case ev := <-s.ch:
					if err := send(ev); err != nil {
						return err
					}
				default:
					return send(&pb.ProcessEvent{Event: &pb.ProcessEvent_Exit{Exit: p.exit}})
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Start starts a process and streams its events to send until it exits or
// ctx ends (the process keeps running then).
func (m *Manager) Start(ctx context.Context, r *pb.StartProcessRequest, send func(*pb.ProcessEvent) error) error {
	if r.Cmd == "" {
		return rpcutil.Err(rpcutil.Invalid, "cmd required")
	}
	user := r.User
	if user == "" {
		user = m.cfg.User
	}
	env := map[string]string{}
	for k, v := range m.cfg.Env {
		env[k] = v
	}
	if r.Pty != nil {
		env["TERM"] = "xterm-256color"
	}
	for k, v := range r.Env {
		env[k] = v
	}
	environ, cred, err := chronus.Environ(user, env)
	if err != nil {
		return rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	cwd := r.Cwd
	if cwd == "" {
		cwd = m.cfg.Workdir
		if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
			cwd = "/"
		}
	} else if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
		return rpcutil.Err(rpcutil.Invalid, "cwd %s is not a directory", cwd)
	}
	path, err := lookPath(r.Cmd, environ, cwd)
	if err != nil {
		return rpcutil.Err(rpcutil.NotFound, "%v", err)
	}
	cmd := exec.Command(path, r.Args...)
	cmd.Args[0] = r.Cmd
	cmd.Env, cmd.Dir = environ, cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setpgid: true}
	p := &proc{info: &pb.ProcessInfo{Tag: r.Tag, Cmd: r.Cmd, Args: r.Args, Env: r.Env, Cwd: cwd}, cmd: cmd,
		subs: map[*sub]bool{}, done: make(chan struct{})}

	var outputs []io.ReadCloser // read until EOF, or drainGrace after the exit
	var closeAfterStart []io.Closer
	if r.Pty != nil {
		master, slave, err := openPty(r.Pty, cred)
		if err != nil {
			return rpcutil.Err(rpcutil.Internal, "pty: %v", err)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr.Setpgid = false
		cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty = true, true // a session of its own, the PTY its terminal
		p.pty, p.stdin = master, master
		outputs = append(outputs, master)
		closeAfterStart = append(closeAfterStart, slave)
	} else {
		if r.Stdin {
			pr, pw, err := os.Pipe()
			if err != nil {
				return rpcutil.Err(rpcutil.Internal, "%v", err)
			}
			cmd.Stdin, p.stdin = pr, pw
			closeAfterStart = append(closeAfterStart, pr)
		}
		for _, w := range []*io.Writer{&cmd.Stdout, &cmd.Stderr} {
			pr, pw, err := os.Pipe()
			if err != nil {
				return rpcutil.Err(rpcutil.Internal, "%v", err)
			}
			*w = pw
			outputs = append(outputs, pr)
			closeAfterStart = append(closeAfterStart, pw)
		}
	}
	closeAll := func(cs []io.Closer) {
		for _, c := range cs {
			c.Close()
		}
	}

	m.mu.Lock()
	if len(m.procs) >= MaxProcs {
		m.mu.Unlock()
		closeAll(closeAfterStart)
		for _, o := range outputs {
			o.Close()
		}
		return rpcutil.Err(rpcutil.NoCapacity, "%d processes are running", MaxProcs)
	}
	if r.Tag != "" {
		if _, taken := m.tags[r.Tag]; taken {
			m.mu.Unlock()
			closeAll(closeAfterStart)
			for _, o := range outputs {
				o.Close()
			}
			return rpcutil.Err(rpcutil.Invalid, "a process tagged %q is running", r.Tag)
		}
	}
	s := p.attach() // before any output exists
	err = cmd.Start()
	closeAll(closeAfterStart)
	if err != nil {
		m.mu.Unlock()
		for _, o := range outputs {
			o.Close()
		}
		if p.stdin != nil && p.pty == nil {
			p.stdin.Close()
		}
		return rpcutil.Err(rpcutil.Invalid, "start %s: %v", r.Cmd, err)
	}
	p.info.Pid = uint32(cmd.Process.Pid)
	m.procs[p.info.Pid] = p
	if r.Tag != "" {
		m.tags[r.Tag] = p.info.Pid
	}
	m.mu.Unlock()
	// aether is protected from the OOM killer; what it runs is not.
	os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", cmd.Process.Pid), []byte("0"), 0)
	go m.run(p, outputs)
	return p.stream(ctx, s, send)
}

// run publishes p's output, waits for it to exit and records how.
func (m *Manager) run(p *proc, outputs []io.ReadCloser) {
	var wg sync.WaitGroup
	for i, o := range outputs {
		wrap := func(b []byte) *pb.ProcessEvent { return &pb.ProcessEvent{Event: &pb.ProcessEvent_Stdout{Stdout: b}} }
		switch {
		case p.pty != nil:
			wrap = func(b []byte) *pb.ProcessEvent { return &pb.ProcessEvent{Event: &pb.ProcessEvent_Pty{Pty: b}} }
		case i == 1:
			wrap = func(b []byte) *pb.ProcessEvent { return &pb.ProcessEvent{Event: &pb.ProcessEvent_Stderr{Stderr: b}} }
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32<<10)
			for {
				n, err := o.Read(buf)
				if n > 0 {
					p.publish(wrap(append([]byte(nil), buf[:n]...)))
				}
				if err != nil { // EOF; EIO on a terminal whose processes are gone
					return
				}
			}
		}()
	}
	werr := p.cmd.Wait()
	drained := make(chan struct{})
	go func() { wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainGrace):
		for _, o := range outputs { // something it started still holds them
			o.Close()
		}
		<-drained
	}
	for _, o := range outputs {
		o.Close()
	}
	if p.stdin != nil && p.pty == nil {
		p.stdin.Close()
	}
	exit := &pb.ProcessExit{ExitCode: -1}
	if st := p.cmd.ProcessState; st != nil {
		exit.Status = st.String()
		if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Exited() {
			exit.Exited, exit.ExitCode = true, int32(ws.ExitStatus())
		}
	} else if werr != nil {
		exit.Error = werr.Error()
	}
	m.mu.Lock()
	delete(m.procs, p.info.Pid)
	if p.info.Tag != "" && m.tags[p.info.Tag] == p.info.Pid {
		delete(m.tags, p.info.Tag)
	}
	m.mu.Unlock()
	p.mu.Lock()
	p.exit = exit
	p.mu.Unlock()
	close(p.done)
}

func (m *Manager) get(pid uint32, tag string) (*proc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pid == 0 && tag != "" {
		var ok bool
		if pid, ok = m.tags[tag]; !ok {
			return nil, rpcutil.Err(rpcutil.NotFound, "no process tagged %q", tag)
		}
	}
	p := m.procs[pid]
	if p == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "no process %d", pid)
	}
	return p, nil
}

// Connect streams a running process's events from now on.
func (m *Manager) Connect(ctx context.Context, r *pb.ProcessRef, send func(*pb.ProcessEvent) error) error {
	p, err := m.get(r.Pid, r.Tag)
	if err != nil {
		return err
	}
	return p.stream(ctx, p.attach(), send)
}

func (m *Manager) List() *pb.ProcessList {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &pb.ProcessList{}
	for _, p := range m.procs {
		out.Processes = append(out.Processes, p.info)
	}
	sort.Slice(out.Processes, func(i, j int) bool { return out.Processes[i].Pid < out.Processes[j].Pid })
	return out
}

func (m *Manager) Input(r *pb.ProcessInput) error {
	p, err := m.get(r.Pid, r.Tag)
	if err != nil {
		return err
	}
	if p.stdin == nil {
		return rpcutil.Err(rpcutil.Invalid, "process %d was started without stdin", p.info.Pid)
	}
	if _, err := p.stdin.Write(r.Data); err != nil {
		return rpcutil.Err(rpcutil.Invalid, "stdin of process %d: %v", p.info.Pid, err)
	}
	return nil
}

func (m *Manager) CloseStdin(r *pb.ProcessRef) error {
	p, err := m.get(r.Pid, r.Tag)
	if err != nil {
		return err
	}
	switch {
	case p.pty != nil:
		_, err = p.pty.Write([]byte{4}) // ^D: end of input for the terminal's reader
	case p.stdin != nil:
		err = p.stdin.Close()
	default:
		return rpcutil.Err(rpcutil.Invalid, "process %d was started without stdin", p.info.Pid)
	}
	if err != nil && !errors.Is(err, os.ErrClosed) {
		return rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	return nil
}

// Signal signals the process's group: what it started goes too.
func (m *Manager) Signal(r *pb.ProcessSignal) error {
	p, err := m.get(r.Pid, r.Tag)
	if err != nil {
		return err
	}
	if r.Signal <= 0 || r.Signal > 64 {
		return rpcutil.Err(rpcutil.Invalid, "bad signal %d", r.Signal)
	}
	if err := syscall.Kill(-int(p.info.Pid), syscall.Signal(r.Signal)); err != nil && err != syscall.ESRCH {
		return rpcutil.Err(rpcutil.Internal, "signal %d: %v", p.info.Pid, err)
	}
	return nil
}

func (m *Manager) Resize(r *pb.ProcessResize) error {
	p, err := m.get(r.Pid, r.Tag)
	if err != nil {
		return err
	}
	if p.pty == nil {
		return rpcutil.Err(rpcutil.Invalid, "process %d has no terminal", p.info.Pid)
	}
	if r.Size == nil {
		return rpcutil.Err(rpcutil.Invalid, "size required")
	}
	return setSize(p.pty, r.Size)
}

// lookPath finds cmd in the PATH of env (the process's, not aether's).
// lookPath finds cmd in env's PATH; relative entries ("." or empty, as in
// a shell) are relative to cwd, where the process runs.
func lookPath(cmd string, env []string, cwd string) (string, error) {
	if filepath.IsAbs(cmd) || filepath.Base(cmd) != cmd {
		return cmd, nil
	}
	path := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		p := filepath.Join(dir, cmd)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", cmd)
}
