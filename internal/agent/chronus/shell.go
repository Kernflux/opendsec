// Package chronus implements one shell session inside a sandbox (paper §3,
// spec §11.3). A chronus process owns one persistent shell, so cd, exported
// variables and functions persist across commands. Command output is
// recorded to files so callers may detach and fetch it later.
package chronus

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kernflux/opendsec/internal/agent/proctree"
)

const doneMarker = "__OPENDSEC_DONE__"

// Command is one submitted command line.
type Command struct {
	ID       int64
	Cmd      string
	OutPath  string
	ErrPath  string
	Started  time.Time
	done     chan struct{}
	mu       sync.Mutex
	exitCode int
	timedOut bool
	ended    time.Time
	out, err *recorder // the output streams' recorders
}

func (c *Command) Done() <-chan struct{} { return c.done }

// Dropped is how much output went past the record limit (spec §29.3).
func (c *Command) Dropped() int64 {
	if c.out == nil {
		return 0
	}
	return c.out.dropped.Load() + c.err.dropped.Load()
}

func (c *Command) IsDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Status returns the exit code, timeout flag and duration (so far).
func (c *Command) Status() (exit int, timedOut bool, dur time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	end := c.ended
	if end.IsZero() {
		end = time.Now()
	}
	return c.exitCode, c.timedOut, end.Sub(c.Started)
}

func (c *Command) finish(code int) {
	// Let the output reach the records before callers read them: the
	// streams end with the command, unless a background process it started
	// keeps one open, which is not waited for long.
	if c.out != nil {
		deadline := time.Now().Add(100 * time.Millisecond)
		for _, r := range []*recorder{c.out, c.err} {
			r.release()
			r.wait(time.Until(deadline))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return
	default:
	}
	c.exitCode = code
	c.ended = time.Now()
	close(c.done)
}

// Shell is a persistent shell process plus its command records.
type Shell struct {
	Workdir string
	User    string
	Env     map[string]string
	Dir     string // where scripts and output records live
	// MaxRecord caps each output stream of a command, SessionRecords the
	// records the session keeps (spec §29.3).
	MaxRecord, SessionRecords int64

	run chan struct{} // one foreground command at a time

	credOnce sync.Once
	cred     *syscall.Credential
	credErr  error

	mu    sync.Mutex
	proc  *exec.Cmd
	stdin io.WriteCloser
	alive chan struct{} // closed when the current shell process exits
	cmds  map[int64]*Command
	byReq map[string]*Command // by client request id (idempotent resubmission)
	next  int64
	cur   *Command
	// Finished commands' records, oldest first, and their total size.
	kept     []*Command
	recorded int64
}

func NewShell(workdir, user string, env map[string]string, dir string) (*Shell, error) {
	// The session dir is the shell user's (chowned at start); its parents
	// only need to be traversable by it.
	if err := os.MkdirAll(filepath.Dir(dir), 0o711); err != nil {
		return nil, err
	}
	for p := filepath.Dir(dir); p != "/" && p != "."; p = filepath.Dir(p) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o011 != 0o011 {
			os.Chmod(p, fi.Mode().Perm()|0o011)
		}
		if filepath.Base(p) == "run" {
			break // up to the agents' run dir
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return &Shell{Workdir: workdir, User: user, Env: env, Dir: dir,
		MaxRecord: DefaultMaxRecord, SessionRecords: DefaultSessionRecords,
		run: make(chan struct{}, 1), cmds: map[int64]*Command{}, byReq: map[string]*Command{}}, nil
}

func shellPath() string {
	for _, p := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sh"
}

// numericUser parses "uid" or "uid:gid" (gid defaults to uid); uid 0 is
// root, not a numeric user.
func numericUser(u string) (uid, gid int, ok bool) {
	us, gs, hasGID := strings.Cut(u, ":")
	uid, err := strconv.Atoi(us)
	if err != nil || uid <= 0 {
		return 0, 0, false
	}
	gid = uid
	if hasGID {
		if gid, err = strconv.Atoi(gs); err != nil || gid < 0 {
			return 0, 0, false
		}
	}
	return uid, gid, true
}

func (s *Shell) environ() ([]string, *syscall.Credential, error) {
	return Environ(s.User, s.Env)
}

// fsCred is the identity the session's file calls run as (nil: root).
func (s *Shell) fsCred() (*syscall.Credential, error) {
	s.credOnce.Do(func() {
		_, s.cred, s.credErr = Environ(s.User, nil)
	})
	return s.cred, s.credErr
}

// Environ is the environment and credentials of a command run as user
// ("" or "root": root; a name; or uid[:gid], which needs no /etc/passwd
// entry): HOME, USER and a base PATH, overridden by extra.
func Environ(user string, extra map[string]string) ([]string, *syscall.Credential, error) {
	env := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": "/root", "TERM": "dumb", "LANG": "C.UTF-8", "USER": "root",
	}
	var cred *syscall.Credential
	if uid, gid, ok := numericUser(user); ok {
		// No /etc/passwd entry needed: a home of its own under /tmp.
		home := fmt.Sprintf("/tmp/home-%d", uid)
		if err := os.MkdirAll(home, 0o700); err == nil {
			os.Chown(home, uid, gid)
		}
		cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		env["HOME"], env["USER"] = home, strconv.Itoa(uid)
	} else if user != "" && user != "root" {
		u, err := osuser.Lookup(user)
		if err != nil {
			return nil, nil, fmt.Errorf("user %q: %w", user, err)
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		env["HOME"], env["USER"] = u.HomeDir, u.Username
	}
	for k, v := range extra {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, cred, nil
}

// startLocked launches a fresh shell process; the caller holds s.mu.
func (s *Shell) startLocked() error {
	env, cred, err := s.environ()
	if err != nil {
		return err
	}
	sh := shellPath()
	args := []string{}
	if strings.HasSuffix(sh, "bash") {
		args = []string{"--noprofile", "--norc"}
	}
	cmd := exec.Command(sh, args...)
	cmd.Env = env
	cmd.Dir = s.Workdir
	if st, err := os.Stat(s.Workdir); err != nil || !st.IsDir() {
		cmd.Dir = "/"
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: cred}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// chronus inherited aether's OOM protection; the user's commands do not.
	os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", cmd.Process.Pid), []byte("0"), 0)
	if cred != nil {
		os.Chown(s.Dir, int(cred.Uid), int(cred.Gid))
	}
	alive := make(chan struct{})
	s.proc, s.stdin, s.alive = cmd, stdin, alive
	go s.readMarkers(cmd, stdout, alive)
	return nil
}

func (s *Shell) readMarkers(cmd *exec.Cmd, stdout io.Reader, alive chan struct{}) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || f[0] != doneMarker {
			continue
		}
		id, err1 := strconv.ParseInt(f[1], 10, 64)
		code, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		s.mu.Lock()
		c := s.cmds[id]
		s.mu.Unlock()
		if c != nil {
			c.finish(code)
		}
	}
	err := cmd.Wait()
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		code = ee.ExitCode()
	} else if err == nil {
		code = 0
	}
	s.mu.Lock()
	cur := s.cur
	if s.proc == cmd {
		s.proc, s.stdin = nil, nil
	}
	s.mu.Unlock()
	if cur != nil {
		cur.finish(code) // e.g. the command ran `exit 3`
	}
	close(alive)
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Submit queues cmd and returns once it has started. Commands in a session
// run one at a time; Submit waits for the previous one (bounded by ctx).
// Submit starts cmdline once the session is free. A non-empty reqID makes it
// idempotent: a command already submitted with that id is returned instead.
func (s *Shell) Submit(ctx context.Context, cmdline string, timeout time.Duration, env map[string]string, cwd, reqID string) (*Command, error) {
	if c := s.byRequest(reqID); c != nil {
		return c, nil
	}
	select {
	case s.run <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c := s.byRequest(reqID); c != nil { // submitted while this one waited
		<-s.run
		return c, nil
	}
	c, err := s.submit(cmdline, env, cwd, reqID)
	if err != nil {
		<-s.run
		return nil, err
	}
	go s.supervise(c, timeout)
	return c, nil
}

func (s *Shell) byRequest(reqID string) *Command {
	if reqID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byReq[reqID]
}

func (s *Shell) submit(cmdline string, env map[string]string, cwd, reqID string) (*Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil {
		if err := s.startLocked(); err != nil {
			return nil, err
		}
	}
	s.next++
	id := s.next
	c := &Command{
		ID: id, Cmd: cmdline, Started: time.Now(), done: make(chan struct{}),
		OutPath: filepath.Join(s.Dir, fmt.Sprintf("%d.out", id)),
		ErrPath: filepath.Join(s.Dir, fmt.Sprintf("%d.err", id)),
	}
	script := filepath.Join(s.Dir, fmt.Sprintf("%d.sh", id))
	// The shell writes the output into pipes; chronus records it, within
	// limits (spec §29.3). The records are chronus's only.
	outPipe, errPipe := c.OutPath+".pipe", c.ErrPath+".pipe"
	for _, p := range []string{c.OutPath, c.ErrPath} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return nil, err
		}
	}
	for _, p := range []string{outPipe, errPipe} {
		os.Remove(p)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			return nil, fmt.Errorf("output pipe: %w", err)
		}
	}
	if err := os.WriteFile(script, []byte(cmdline+"\n"), 0o600); err != nil {
		return nil, err
	}
	if s.proc.SysProcAttr.Credential != nil {
		cr := s.proc.SysProcAttr.Credential
		for _, p := range []string{outPipe, errPipe, script} {
			os.Chown(p, int(cr.Uid), int(cr.Gid))
		}
	}
	c.out, c.err = startRecorder(outPipe, c.OutPath, s.MaxRecord), startRecorder(errPipe, c.ErrPath, s.MaxRecord)
	var line string
	if len(env) == 0 && cwd == "" {
		// Runs in the session shell itself: state changes persist.
		line = fmt.Sprintf("{ . %s ; } </dev/null >%s 2>%s; printf '\\n%s %d %%d\\n' $?\n",
			quote(script), quote(outPipe), quote(errPipe), doneMarker, id)
	} else {
		// Per-command cwd/env: run in a subshell so the session is unchanged.
		var pre []string
		if cwd != "" {
			pre = append(pre, "cd "+quote(cwd))
		}
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !validEnvName(k) {
				return nil, fmt.Errorf("invalid environment variable name %q", k)
			}
			pre = append(pre, "export "+k+"="+quote(env[k]))
		}
		line = fmt.Sprintf("( %s && . %s ) </dev/null >%s 2>%s; printf '\\n%s %d %%d\\n' $?\n",
			strings.Join(pre, " && "), quote(script), quote(outPipe), quote(errPipe), doneMarker, id)
	}
	s.cmds[id] = c
	s.cur = c
	if _, err := io.WriteString(s.stdin, line); err != nil {
		delete(s.cmds, id)
		s.cur = nil
		c.out.release()
		c.err.release()
		return nil, fmt.Errorf("shell write: %w", err)
	}
	if reqID != "" {
		s.byReq[reqID] = c
	}
	go func() {
		<-c.done
		s.keep(c)
	}()
	return c, nil
}

// keep counts finished command c's records against the session's budget,
// removing the oldest finished commands' records (never c's) while over it.
func (s *Shell) keep(c *Command) {
	size := func(c *Command) (n int64) {
		for _, p := range []string{c.OutPath, c.ErrPath} {
			if st, err := os.Stat(p); err == nil {
				n += st.Size()
			}
		}
		return n
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kept = append(s.kept, c)
	s.recorded += size(c)
	for s.recorded > s.SessionRecords && len(s.kept) > 1 {
		old := s.kept[0]
		s.kept = s.kept[1:]
		s.recorded -= size(old)
		for _, p := range []string{old.OutPath, old.ErrPath, strings.TrimSuffix(old.OutPath, ".out") + ".sh"} {
			os.Remove(p)
		}
		delete(s.cmds, old.ID)
		for k, v := range s.byReq {
			if v == old {
				delete(s.byReq, k)
			}
		}
	}
}

func validEnvName(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// supervise enforces the timeout and releases the session when c finishes.
func (s *Shell) supervise(c *Command, timeout time.Duration) {
	defer func() {
		s.mu.Lock()
		if s.cur == c {
			s.cur = nil
		}
		s.mu.Unlock()
		<-s.run
	}()
	var expired <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-c.done:
		return
	case <-expired:
	}
	c.mu.Lock()
	c.timedOut = true
	c.mu.Unlock()
	pid := s.pid()
	// Kill what the command started; the shell (and its state) survives.
	proctree.Signal(pid, syscall.SIGTERM, false)
	if waitDone(c, 3*time.Second) {
		return
	}
	proctree.Signal(pid, syscall.SIGKILL, false)
	if waitDone(c, 2*time.Second) {
		return
	}
	// A shell builtin loop (e.g. `while :; do :; done`): only killing the
	// shell stops it. The session restarts on the next command.
	c.finish(137)
	s.Close()
}

func waitDone(c *Command, d time.Duration) bool {
	select {
	case <-c.done:
		return true
	case <-time.After(d):
		return false
	}
}

func (s *Shell) pid() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil || s.proc.Process == nil {
		return 0
	}
	return s.proc.Process.Pid
}

// IsShell reports whether pid is the session's shell process (reaped by
// os/exec, not by the orphan reaper).
func (s *Shell) IsShell(pid int) bool { return pid != 0 && pid == s.pid() }

// Get returns a command by id.
func (s *Shell) Get(id int64) *Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmds[id]
}

// Close kills the shell and everything it started.
func (s *Shell) Close() {
	s.mu.Lock()
	proc, alive := s.proc, s.alive
	s.mu.Unlock()
	if proc == nil || proc.Process == nil {
		return
	}
	proctree.Signal(proc.Process.Pid, syscall.SIGKILL, true)
	select {
	case <-alive:
	case <-time.After(5 * time.Second):
	}
}

// ReadRange reads up to limit bytes of path starting at off.
func ReadRange(path string, off, limit int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	if off >= size {
		return nil, size, nil
	}
	n := min(size-off, limit)
	buf := make([]byte, n)
	m, err := f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, size, err
	}
	return buf[:m], size, nil
}
