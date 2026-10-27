// Package aether implements the per-sandbox proxy (paper §3, spec §11.3).
// The edge talks only to aether; aether routes each call by session id to
// the chronus process owning that shell session, spawning it on first use,
// and kills the session's whole process tree when it is closed.
package aether

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/procs"
	"github.com/kernflux/opendsec/internal/agent/proctree"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

var sessionRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`) // not "." or "..": names a directory

const DefaultSession = "default"

type Config struct {
	RunDir     string            // sockets + output records (/.opendsec/run)
	ChronusBin string            // path to opendsec-chronus
	Workdir    string            // initial cwd of new sessions
	User       string            // init_user
	Env        map[string]string // base environment of every session
}

type session struct {
	name   string
	user   string // as the session runs ("root" for the default)
	proc   *exec.Cmd
	conn   *grpc.ClientConn
	client pb.RuntimeClient
	exited chan struct{}
}

type Aether struct {
	pb.UnimplementedRuntimeServer
	cfg   Config
	procs *procs.Manager // the process API (spec §37), outside sessions

	mu       sync.Mutex
	sessions map[string]*session
	spawning map[string]chan struct{}
}

func New(cfg Config) *Aether {
	return &Aether{cfg: cfg, sessions: map[string]*session{}, spawning: map[string]chan struct{}{},
		procs: procs.New(procs.Config{Workdir: cfg.Workdir, User: cfg.User, Env: cfg.Env})}
}

func (a *Aether) session(ctx context.Context, name string) (*session, error) {
	return a.sessionAs(ctx, name, "")
}

// userRe: a user name, or uid[:gid].
var userRe = regexp.MustCompile(`^([a-z_][a-z0-9_.-]{0,31}|[0-9]{1,10}(:[0-9]{1,10})?)$`)

// sessionAs returns session name, starting it as user ("" = the init
// user) if it does not run; a running session must run as user, if given.
func (a *Aether) sessionAs(ctx context.Context, name, user string) (*session, error) {
	if name == "" {
		name = DefaultSession
	}
	if !sessionRe.MatchString(name) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad session id %q", name)
	}
	if user != "" && !userRe.MatchString(user) {
		return nil, rpcutil.Err(rpcutil.Invalid, "bad user %q (a name, or uid[:gid])", user)
	}
	want := cmp.Or(user, a.cfg.User, "root")
	for {
		a.mu.Lock()
		if s := a.sessions[name]; s != nil {
			select {
			case <-s.exited: // chronus died; replace it
				delete(a.sessions, name)
			default:
				a.mu.Unlock()
				if user != "" && s.user != want {
					return nil, rpcutil.Err(rpcutil.Invalid, "session %s runs as %s, not %s", name, s.user, want)
				}
				return s, nil
			}
		}
		if wait, ok := a.spawning[name]; ok {
			a.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, rpcutil.Err(rpcutil.Timeout, "waiting for session %s", name)
			}
		}
		done := make(chan struct{})
		a.spawning[name] = done
		a.mu.Unlock()

		s, err := a.spawn(name, want)
		a.mu.Lock()
		delete(a.spawning, name)
		if err == nil {
			a.sessions[name] = s
		}
		a.mu.Unlock()
		close(done)
		return s, err
	}
}

func (a *Aether) spawn(name, user string) (*session, error) {
	sock := filepath.Join(a.cfg.RunDir, "chronus-"+name+".sock")
	os.Remove(sock)
	env, _ := json.Marshal(a.cfg.Env)
	cmd := exec.Command(a.cfg.ChronusBin,
		"--socket", sock, "--session", name, "--workdir", a.cfg.Workdir,
		"--user", user, "--env", string(env),
		"--records", filepath.Join(a.cfg.RunDir, "sessions", name))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "start chronus: %v", err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		// The socket file appears at bind(), before listen(); only a
		// successful connect means chronus is serving.
		if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
			c.Close()
			break
		}
		select {
		case <-exited:
			return nil, rpcutil.Err(rpcutil.Unavailable, "chronus for session %s exited during startup", name)
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			proctree.Signal(cmd.Process.Pid, syscall.SIGKILL, true)
			return nil, rpcutil.Err(rpcutil.Unavailable, "chronus for session %s did not start", name)
		}
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(80<<20), grpc.MaxCallSendMsgSize(80<<20)))
	if err != nil {
		proctree.Signal(cmd.Process.Pid, syscall.SIGKILL, true)
		return nil, err
	}
	return &session{name: name, user: user, proc: cmd, conn: conn, client: pb.NewRuntimeClient(conn), exited: exited}, nil
}

// kill tears down a session's chronus and everything it started.
func (s *session) kill() {
	s.conn.Close()
	proctree.Signal(s.proc.Process.Pid, syscall.SIGKILL, true)
	select {
	case <-s.exited:
	case <-time.After(5 * time.Second):
	}
}

// CloseAll kills every session (aether shutdown).
func (a *Aether) CloseAll() {
	a.mu.Lock()
	ss := a.sessions
	a.sessions = map[string]*session{}
	a.mu.Unlock()
	for _, s := range ss {
		s.kill()
	}
}

// ---- Runtime: forwarded calls -----------------------------------------------------

func (a *Aether) Exec(ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
	s, err := a.sessionAs(ctx, r.Session, r.User)
	if err != nil {
		return nil, err
	}
	return s.client.Exec(ctx, r)
}

func (a *Aether) GetOutput(ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.GetOutput(ctx, r)
}

func (a *Aether) ReadFile(ctx context.Context, r *pb.FileRequest) (*pb.FileData, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.ReadFile(ctx, r)
}

func (a *Aether) WriteFile(ctx context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.WriteFile(ctx, r)
}

func (a *Aether) ListDir(ctx context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.ListDir(ctx, r)
}

func (a *Aether) Stat(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.Stat(ctx, r)
}

func (a *Aether) Remove(ctx context.Context, r *pb.FileRequest) (*pb.Empty, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.Remove(ctx, r)
}

func (a *Aether) Http(ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.Http(ctx, r)
}

func (a *Aether) ExecStream(r *pb.ExecRequest, st pb.Runtime_ExecStreamServer) error {
	s, err := a.sessionAs(st.Context(), r.Session, r.User)
	if err != nil {
		return err
	}
	up, err := s.client.ExecStream(st.Context(), r)
	if err != nil {
		return err
	}
	return rpcutil.PipeEvents(up, st)
}

func (a *Aether) MakeDir(ctx context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.MakeDir(ctx, r)
}

func (a *Aether) Move(ctx context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
	s, err := a.session(ctx, r.Session)
	if err != nil {
		return nil, err
	}
	return s.client.Move(ctx, r)
}

// ---- Runtime: processes (spec §37) -------------------------------------------------

func (a *Aether) StartProcess(r *pb.StartProcessRequest, st pb.Runtime_StartProcessServer) error {
	if r.User != "" && !userRe.MatchString(r.User) {
		return rpcutil.Err(rpcutil.Invalid, "bad user %q (a name, or uid[:gid])", r.User)
	}
	return a.procs.Start(st.Context(), r, st.Send)
}

func (a *Aether) ConnectProcess(r *pb.ProcessRef, st pb.Runtime_ConnectProcessServer) error {
	return a.procs.Connect(st.Context(), r, st.Send)
}

func (a *Aether) ListProcesses(context.Context, *pb.ProcessRef) (*pb.ProcessList, error) {
	return a.procs.List(), nil
}

func (a *Aether) SendProcessInput(_ context.Context, r *pb.ProcessInput) (*pb.Empty, error) {
	return &pb.Empty{}, a.procs.Input(r)
}

func (a *Aether) CloseProcessStdin(_ context.Context, r *pb.ProcessRef) (*pb.Empty, error) {
	return &pb.Empty{}, a.procs.CloseStdin(r)
}

func (a *Aether) SignalProcess(_ context.Context, r *pb.ProcessSignal) (*pb.Empty, error) {
	return &pb.Empty{}, a.procs.Signal(r)
}

func (a *Aether) ResizeProcess(_ context.Context, r *pb.ProcessResize) (*pb.Empty, error) {
	return &pb.Empty{}, a.procs.Resize(r)
}

// ConnectPort connects to a port on the sandbox's loopback (IPv4, else
// IPv6) and relays the connection over the stream (spec §37.8). An empty
// message acknowledges the connection, so the caller learns at once
// whether the port is open.
func (a *Aether) ConnectPort(st pb.Runtime_ConnectPortServer) error {
	first, err := st.Recv()
	if err != nil {
		return err
	}
	if first.Port == 0 || first.Port > 65535 {
		return rpcutil.Err(rpcutil.Invalid, "bad port %d", first.Port)
	}
	port := strconv.Itoa(int(first.Port))
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		var err6 error
		if c, err6 = net.DialTimeout("tcp", net.JoinHostPort("::1", port), 5*time.Second); err6 != nil {
			return rpcutil.Err(rpcutil.Unavailable, "nothing listens on port %d in the sandbox: %v", first.Port, err)
		}
	}
	if len(first.Data) > 0 {
		if _, err := c.Write(first.Data); err != nil {
			c.Close()
			return rpcutil.Err(rpcutil.Unavailable, "port %d: %v", first.Port, err)
		}
	}
	if err := st.Send(&pb.PortData{}); err != nil {
		c.Close()
		return err
	}
	return rpcutil.PipePort(st, c)
}

// ---- Runtime: session management and health -------------------------------------

func (a *Aether) ListSessions(context.Context, *pb.SessionRef) (*pb.SessionList, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := &pb.SessionList{}
	for name := range a.sessions {
		out.Sessions = append(out.Sessions, name)
	}
	sort.Strings(out.Sessions)
	return out, nil
}

func (a *Aether) CloseSession(_ context.Context, r *pb.SessionRef) (*pb.Empty, error) {
	name := r.Session
	if name == "" {
		name = DefaultSession
	}
	a.mu.Lock()
	s := a.sessions[name]
	delete(a.sessions, name)
	a.mu.Unlock()
	if s == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "session %s", name)
	}
	s.kill()
	return &pb.Empty{}, nil
}

// heartbeatInterval: the edge tells a lost sandbox by its stream ending, not
// by missing heartbeats; at thousands of sandboxes per edge, receiving one
// a second from each cost the edge real CPU (allocation, GC).
const heartbeatInterval = 15 * time.Second

func (a *Aether) Watch(_ *pb.Empty, st pb.Runtime_WatchServer) error {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		a.mu.Lock()
		n := len(a.sessions)
		a.mu.Unlock()
		if err := st.Send(&pb.Heartbeat{At: rpcutil.Now(), Sessions: int32(n)}); err != nil {
			return err
		}
		select {
		case <-st.Context().Done():
			return nil
		case <-t.C:
		}
	}
}

// ---- PID 1 -------------------------------------------------------------------------------

// RunInit is the sandbox's PID 1: it starts the aether server (this binary
// without --init), forwards termination signals to it, reaps orphans, and
// exits with the server's status so the sandbox ends when aether does.
func RunInit(args []string) int {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "aether init:", err)
		return 1
	}
	server := cmd.Process.Pid
	sigs := make(chan os.Signal, 8)
	signalNotify(sigs)
	go func() {
		for s := range sigs {
			if s == syscall.SIGCHLD {
				continue
			}
			cmd.Process.Signal(s)
		}
	}()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 1
		}
		if pid == server {
			if ws.Exited() {
				return ws.ExitStatus()
			}
			return 128 + int(ws.Signal())
		}
	}
}
