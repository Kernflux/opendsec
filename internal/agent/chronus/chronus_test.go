package chronus

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// client starts a chronus server on a unix socket and returns a client.
func client(t *testing.T) (pb.RuntimeClient, string) {
	t.Helper()
	c, work, _ := clientWith(t, nil)
	return c, work
}

// clientWith is client with the shell adjusted by edit; it also returns
// the shell.
func clientWith(t *testing.T, edit func(*Shell)) (pb.RuntimeClient, string, *Shell) {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	os.Mkdir(work, 0o755)
	sh, err := NewShell(work, "", map[string]string{"GREETING": "hi"}, filepath.Join(dir, "rec"))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(sh)
	}
	sock := filepath.Join(dir, "c.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterRuntimeServer(srv, &Server{Session: "default", Shell: sh})
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Stop(); sh.Close() })
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewRuntimeClient(conn), work, sh
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func run(t *testing.T, c pb.RuntimeClient, cmd string) *pb.ExecResult {
	t.Helper()
	r, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: cmd})
	if err != nil {
		t.Fatalf("%q: %v", cmd, err)
	}
	return r
}

func TestPersistentState(t *testing.T) {
	c, work := client(t)
	r := run(t, c, "echo $GREETING; echo oops >&2; exit_code_test() { return 3; }; exit_code_test")
	if string(r.Stdout) != "hi\n" || string(r.Stderr) != "oops\n" || r.ExitCode != 3 || !r.Done {
		t.Fatalf("result = %+v", r)
	}
	run(t, c, "mkdir -p sub && cd sub && export X=42")
	r = run(t, c, `pwd; echo "x=$X"`)
	if want := filepath.Join(work, "sub") + "\nx=42\n"; string(r.Stdout) != want {
		t.Fatalf("state not kept: %q want %q", r.Stdout, want)
	}
	// Per-command env/cwd do not leak into the session.
	r2, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: `pwd; echo "y=$Y"`, Cwd: "/", Env: map[string]string{"Y": "1"}})
	if err != nil || string(r2.Stdout) != "/\ny=1\n" {
		t.Fatalf("per-command: %q %v", r2.GetStdout(), err)
	}
	r = run(t, c, `pwd; echo "y=$Y"`)
	if !strings.HasSuffix(strings.Split(string(r.Stdout), "\n")[0], "/sub") || !strings.Contains(string(r.Stdout), "y=\n") {
		t.Fatalf("per-command leaked: %q", r.Stdout)
	}
	if _, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "true", Env: map[string]string{"BAD-NAME": "x"}}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("bad env name: %v", err)
	}
}

func TestBackgroundAndOutput(t *testing.T) {
	c, _ := client(t)
	r, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "echo start; sleep 0.3; echo end", Background: true})
	if err != nil || r.Done {
		t.Fatalf("background: %+v %v", r, err)
	}
	o, err := c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: r.CmdId, WaitS: 5})
	if err != nil || !o.Done || string(o.Stdout) != "start\nend\n" {
		t.Fatalf("output: %+v %v", o, err)
	}
	// Offsets let callers fetch incrementally.
	o, _ = c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: r.CmdId, StdoutOffset: 6})
	if string(o.Stdout) != "end\n" || o.StdoutSize != 10 {
		t.Fatalf("offset: %q size=%d", o.Stdout, o.StdoutSize)
	}
	if _, err := c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: 999}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("unknown cmd: %v", err)
	}
}

func TestIdempotentResubmit(t *testing.T) {
	c, work := client(t)
	// A retry while the first submission still runs, one after it ended
	// (foreground and stream), and one waiting behind another command: the
	// command runs once and every call sees its result.
	first, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "echo x >> runs; sleep 0.5; echo done", RequestId: "r1", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "echo x >> runs; sleep 0.5; echo done", RequestId: "r1"})
	if err != nil || again.CmdId != first.CmdId || string(again.Stdout) != "done\n" {
		t.Fatalf("retry: %+v %v (first %d)", again, err, first.CmdId)
	}
	for off, want := range map[int64]string{0: "done\n", 2: "ne\n"} { // a resumed stream skips what was received
		st, err := c.ExecStream(ctx(t), &pb.ExecRequest{Cmd: "echo x >> runs", RequestId: "r1", StdoutOffset: off})
		if err != nil {
			t.Fatal(err)
		}
		var out string
		for {
			ev, err := st.Recv()
			if err != nil {
				break
			}
			if ev.GetStarted() != 0 && ev.GetStarted() != first.CmdId {
				t.Fatalf("stream retry started %d", ev.GetStarted())
			}
			out += string(ev.GetStdout())
		}
		if out != want {
			t.Fatalf("stream retry from %d: %q", off, out)
		}
	}
	if r := run(t, c, "cat runs"); string(r.Stdout) != "x\n" {
		t.Fatalf("ran %q times", r.Stdout)
	}
	if _, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "sleep 0.5", Background: true}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *pb.ExecResult, 2)
	for range 2 {
		go func() {
			r, _ := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "echo y >> runs2", RequestId: "r2"})
			done <- r
		}()
	}
	a, b := <-done, <-done
	if a == nil || b == nil || a.CmdId != b.CmdId {
		t.Fatalf("concurrent retries: %+v %+v", a, b)
	}
	if got, _ := os.ReadFile(filepath.Join(work, "runs2")); string(got) != "y\n" {
		t.Fatalf("ran %q", got)
	}
}

func TestTimeoutKeepsSession(t *testing.T) {
	c, _ := client(t)
	run(t, c, "export KEEP=yes")
	start := time.Now()
	r, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "sleep 30", TimeoutS: 0.3})
	if err != nil || !r.TimedOut || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %+v %v after %v", r, err, time.Since(start))
	}
	if r := run(t, c, "echo $KEEP"); string(r.Stdout) != "yes\n" {
		t.Fatalf("session lost after timeout: %q", r.Stdout)
	}
	// A builtin busy loop can only be stopped by killing the shell; the
	// session restarts (state is lost, but it keeps working).
	r, err = c.Exec(ctx(t), &pb.ExecRequest{Cmd: "while :; do :; done", TimeoutS: 0.3})
	if err != nil || !r.TimedOut {
		t.Fatalf("busy loop: %+v %v", r, err)
	}
	if r := run(t, c, "echo alive"); string(r.Stdout) != "alive\n" {
		t.Fatalf("after restart: %q", r.Stdout)
	}
}

func TestShellExit(t *testing.T) {
	c, _ := client(t)
	r := run(t, c, "exit 7")
	if r.ExitCode != 7 || !r.Done {
		t.Fatalf("exit: %+v", r)
	}
	if r := run(t, c, "echo back"); string(r.Stdout) != "back\n" {
		t.Fatalf("shell not restarted: %q", r.Stdout)
	}
}

func TestStream(t *testing.T) {
	c, _ := client(t)
	st, err := c.ExecStream(ctx(t), &pb.ExecRequest{Cmd: "for i in 1 2 3; do echo $i; sleep 0.1; done; echo err >&2; exit 2"})
	if err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	chunks := 0
	var exit *pb.ExecResult
	for {
		ev, err := st.Recv()
		if err != nil {
			break
		}
		switch e := ev.Event.(type) {
		case *pb.ExecEvent_Stdout:
			out.Write(e.Stdout)
			chunks++
		case *pb.ExecEvent_Stderr:
			errb.Write(e.Stderr)
		case *pb.ExecEvent_Exit:
			exit = e.Exit
		}
	}
	if out.String() != "1\n2\n3\n" || errb.String() != "err\n" || exit == nil || exit.ExitCode != 2 {
		t.Fatalf("stream: out=%q err=%q exit=%v", out.String(), errb.String(), exit)
	}
	if chunks < 2 {
		t.Fatalf("output was not streamed incrementally (%d chunks)", chunks)
	}
}

func TestFiles(t *testing.T) {
	c, work := client(t)
	cx := ctx(t)
	if _, err := c.WriteFile(cx, &pb.WriteFileRequest{Path: "a/b.txt", Data: []byte("hello"), Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	c.WriteFile(cx, &pb.WriteFileRequest{Path: "a/b.txt", Data: []byte(" world"), Append: true})
	d, err := c.ReadFile(cx, &pb.FileRequest{Path: filepath.Join(work, "a/b.txt"), Offset: 6})
	if err != nil || string(d.Data) != "world" || d.Size != 11 {
		t.Fatalf("read: %q %v", d.GetData(), err)
	}
	st, _ := c.Stat(cx, &pb.FileRequest{Path: "a/b.txt"})
	if st.Type != "file" || st.Mode != 0o600 || st.Size != 11 {
		t.Fatalf("stat: %+v", st)
	}
	l, _ := c.ListDir(cx, &pb.FileRequest{Path: "a"})
	if len(l.Entries) != 1 || l.Entries[0].Name != "b.txt" {
		t.Fatalf("list: %+v", l)
	}
	// The shell sees the same files.
	if r := run(t, c, "cat a/b.txt"); string(r.Stdout) != "hello world" {
		t.Fatalf("shell view: %q", r.Stdout)
	}
	if _, err := c.Remove(cx, &pb.FileRequest{Path: "a"}); err == nil {
		t.Fatal("non-recursive remove of non-empty dir should fail")
	}
	if _, err := c.Remove(cx, &pb.FileRequest{Path: "a", Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadFile(cx, &pb.FileRequest{Path: "a/b.txt"}); rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("after remove: %v", err)
	}
}

func TestHTTP(t *testing.T) {
	c, _ := client(t)
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	defer lis.Close()
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		conn.Read(buf)
		conn.Write([]byte("HTTP/1.1 201 Created\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok"))
		conn.Close()
	}()
	r, err := c.Http(ctx(t), &pb.HttpRequest{Url: "http://" + lis.Addr().String() + "/x", Method: "POST", Body: []byte("b")})
	if err != nil || r.Status != 201 || string(r.Body) != "ok" || r.Headers["X-Test"] != "yes" {
		t.Fatalf("http: %+v %v", r, err)
	}
}

// recordsSize is the disk the session's records take.
func recordsSize(t *testing.T, sh *Shell) (n int64) {
	t.Helper()
	ents, _ := os.ReadDir(sh.Dir)
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
	}
	return n
}

// TestOutputLimit (spec §29.3): past the per-stream limit output is read and
// dropped, so the command neither blocks nor fills the disk.
func TestOutputLimit(t *testing.T) {
	c, _, sh := clientWith(t, func(s *Shell) { s.MaxRecord = 64 << 10 })
	r := run(t, c, "head -c 1000000 /dev/zero | tr '\\0' x; echo done >&2")
	if !r.Done || r.ExitCode != 0 || r.StdoutSize != 64<<10 || r.DroppedBytes != 1000000-64<<10 || string(r.Stderr) != "done\n" {
		t.Fatalf("exit %d stdout %d dropped %d stderr %q", r.ExitCode, r.StdoutSize, r.DroppedBytes, r.Stderr)
	}
	// A command that never stops writing: the timeout ends it, the records
	// stay within the limit.
	start := time.Now()
	r, err := c.Exec(ctx(t), &pb.ExecRequest{Cmd: "yes", TimeoutS: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TimedOut || r.StdoutSize != 64<<10 || r.DroppedBytes < 1<<20 || time.Since(start) > 10*time.Second {
		t.Fatalf("yes: timed out %v, stdout %d, dropped %d, took %v", r.TimedOut, r.StdoutSize, r.DroppedBytes, time.Since(start))
	}
	if n := recordsSize(t, sh); n > 3*64<<10 {
		t.Fatalf("records take %d bytes", n)
	}
	if r := run(t, c, "echo still here"); string(r.Stdout) != "still here\n" {
		t.Fatalf("session after the limit: %q", r.Stdout)
	}
}

// TestSessionRecords (spec §29.3): past the session's budget the oldest
// finished commands' records go; the latest stay.
func TestSessionRecords(t *testing.T) {
	c, _, sh := clientWith(t, func(s *Shell) { s.SessionRecords = 300 << 10 })
	var ids []int64
	for i := 0; i < 6; i++ {
		r := run(t, c, "head -c 100000 /dev/zero")
		ids = append(ids, r.CmdId)
	}
	time.Sleep(100 * time.Millisecond) // the last one is counted
	if n := recordsSize(t, sh); n > 400<<10 {
		t.Fatalf("records take %d bytes, budget %d", n, 300<<10)
	}
	if _, err := c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: ids[0]}); err == nil {
		t.Error("the oldest command's output survived the budget")
	}
	r, err := c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: ids[5]})
	if err != nil || r.StdoutSize != 100000 {
		t.Fatalf("latest command: %v %v", r, err)
	}
}

// TestOutputAfterCommand: a background process the command started keeps
// writing to the command's output after it ends; Exec does not wait for it,
// GetOutput sees what it wrote later.
func TestOutputAfterCommand(t *testing.T) {
	c, _ := client(t)
	start := time.Now()
	r := run(t, c, "(sleep 1; echo late) & echo now")
	if string(r.Stdout) != "now\n" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("got %q after %v", r.Stdout, time.Since(start))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		o, err := c.GetOutput(ctx(t), &pb.OutputRequest{CmdId: r.CmdId})
		if err == nil && string(o.Stdout) == "now\nlate\n" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("later output: %v %v", o, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestFilesAsUser: a session's file calls run as its user, as its shell
// does: they see its permissions and create files it owns, while chronus
// itself keeps running as root on every other thread.
func TestFilesAsUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	c, work, _ := clientWith(t, func(sh *Shell) { sh.User = "65534:65534" })
	for p := work; p != "/"; p = filepath.Dir(p) {
		if fi, err := os.Stat(p); err == nil {
			os.Chmod(p, fi.Mode().Perm()|0o011)
		}
	}
	os.Chmod(work, 0o777)
	if err := os.WriteFile(filepath.Join(work, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cx := ctx(t)
	if r := run(t, c, "id -u"); strings.TrimSpace(string(r.Stdout)) != "65534" {
		t.Fatalf("shell runs as %q", r.Stdout)
	}
	for i := 0; i < 20; i++ {
		_, err := c.ReadFile(cx, &pb.FileRequest{Path: "secret"})
		if rpcutil.Reason(err) != rpcutil.Forbidden {
			t.Fatalf("reading a root-only file: %v, want forbidden", err)
		}
		if _, err := c.WriteFile(cx, &pb.WriteFileRequest{Path: "mine.txt", Data: []byte("hi")}); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(work, "mine.txt"), &st); err != nil || st.Uid != 65534 || st.Gid != 65534 {
		t.Fatalf("mine.txt owned by %d:%d (%v), want 65534:65534", st.Uid, st.Gid, err)
	}
	if _, err := c.Remove(cx, &pb.FileRequest{Path: "secret"}); err != nil {
		t.Fatalf("removing from a dir it may write: %v", err) // as for its shell
	}
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	for _, f := range tasks {
		b, err := os.ReadFile(f)
		if err != nil {
			continue // the thread ended
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Uid:") && strings.Fields(l)[4] != "0" {
				t.Fatalf("a thread kept the session's identity: %s: %s", f, l)
			}
		}
	}
}

// TestRecordsDirAsUser: a session's user cannot add to the records dir,
// and a link at a name chronus writes next (planted before, or left from
// before a restart) is replaced, never written through as root.
func TestRecordsDirAsUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	c, work, sh := clientWith(t, func(sh *Shell) { sh.User = "65534:65534" })
	for p := work; p != "/"; p = filepath.Dir(p) {
		if fi, err := os.Stat(p); err == nil {
			os.Chmod(p, fi.Mode().Perm()|0o011)
		}
	}
	if r := run(t, c, "echo hi"); string(r.Stdout) != "hi\n" {
		t.Fatalf("first command: %q", r.Stdout)
	}
	if r := run(t, c, "touch "+filepath.Join(sh.Dir, "x")+" 2>&1; echo $?"); strings.TrimSpace(string(r.Stdout)) == "0" {
		t.Fatal("the session's user could create a file in the records dir")
	}
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	next := sh.next + 1
	for _, n := range []string{"%d.out", "%d.err", "%d.sh"} {
		os.Symlink(victim, filepath.Join(sh.Dir, fmt.Sprintf(n, next)))
	}
	if r := run(t, c, "echo again"); string(r.Stdout) != "again\n" {
		t.Fatalf("command after the links: %q", r.Stdout)
	}
	var st syscall.Stat_t
	if b, _ := os.ReadFile(victim); string(b) != "keep" || syscall.Stat(victim, &st) != nil || st.Uid != 0 {
		t.Fatalf("written through a link: %q, owner %d", b, st.Uid)
	}
}
