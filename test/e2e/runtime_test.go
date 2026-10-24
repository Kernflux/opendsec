package e2e

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend/container"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

var agentDir string // built by TestMain when the container runtime is usable

func TestMain(m *testing.M) {
	if container.Check() == nil {
		dir, err := os.MkdirTemp("", "opendsec-agents")
		if err != nil {
			panic(err)
		}
		cmd := exec.Command("go", "build", "-o", dir, "github.com/kernflux/opendsec/cmd/opendsec-aether", "github.com/kernflux/opendsec/cmd/opendsec-chronus")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			panic("build agents: " + err.Error() + "\n" + string(out))
		}
		agentDir = dir
		defer os.RemoveAll(dir)
	}
	code := m.Run()
	if agentDir != "" {
		os.RemoveAll(agentDir)
	}
	os.Exit(code)
}

// startContainers starts a cluster of 2 edges with the real container runtime.
func startContainers(t *testing.T) (*cluster.Local, *client.Client) {
	t.Helper()
	if agentDir == "" {
		t.Skipf("container runtime unavailable: %v", container.Check())
	}
	state, err := os.MkdirTemp("", "opendsec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := cluster.SimConfig(2, 1, 8, 16*1024, 64)
	for i := range cfg.Edges {
		cfg.Edges[i].StateDir, cfg.Edges[i].AgentDir = state, agentDir
		// The state dir is on a small tmpfs: sparse 256 MB disks, small reserve.
		cfg.Edges[i].Capacity.DiskMB, cfg.Edges[i].DiskReserveMB = 64*256, 64
		cfg.Edges[i].Images = map[string][]string{"host": {"/"}}
		if i == 0 {
			cfg.Edges[i].Images["py"] = []string{"/"} // only e000 has image "py"
		}
		cfg.Edges[i].Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 64, DefaultDiskMB: 256}
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return l, c
}

var ctrSpec = &pb.SandboxSpec{Backend: "container", Image: "host",
	Resources: &pb.Resources{CpuCores: 1, MemoryMb: 512}, TaskId: "job-rt"}

func shell(t *testing.T, c *client.Client, id, session, cmd string) *pb.ExecResult {
	t.Helper()
	r, err := c.Exec(ctx(t), &pb.ExecRequest{SandboxId: id, Session: session, Cmd: cmd})
	if err != nil {
		t.Fatalf("%q: %v", cmd, err)
	}
	return r
}

func TestRuntimeEndToEnd(t *testing.T) {
	_, c := startContainers(t)
	cx := ctx(t)
	sb, err := c.Create(cx, ctrSpec)
	if err != nil {
		t.Fatal(err)
	}
	id := sb.Id

	// The paper's example: run_shell("echo hello world").
	if r := shell(t, c, id, "", "echo hello world"); string(r.Stdout) != "hello world\n" || r.ExitCode != 0 {
		t.Fatalf("exec: %+v", r)
	}
	shell(t, c, id, "", "cd /tmp && export STEP=1")
	if r := shell(t, c, id, "", "echo $PWD $STEP"); string(r.Stdout) != "/tmp 1\n" {
		t.Fatalf("session state: %q", r.Stdout)
	}

	// Files written through the API are visible to the shell and vice versa.
	if _, err := c.WriteFile(cx, &pb.WriteFileRequest{SandboxId: id, Path: "/work/main.py", Data: []byte("print(6*7)\n")}); err != nil {
		t.Fatal(err)
	}
	if r := shell(t, c, id, "", "python3 /work/main.py > /work/out.txt; cat /work/out.txt"); string(r.Stdout) != "42\n" {
		t.Fatalf("python: %q %q", r.Stdout, r.Stderr)
	}
	d, err := c.ReadFile(cx, &pb.FileRequest{SandboxId: id, Path: "/work/out.txt"})
	if err != nil || string(d.Data) != "42\n" {
		t.Fatalf("read: %v %v", d, err)
	}

	// Past gRPC's 4 MB default, through apiserver and edge: a 20 MB write
	// and read, and 10 MB of command output.
	big := make([]byte, 20<<20)
	for i := range big {
		big[i] = byte(i * 7)
	}
	if _, err := c.WriteFile(cx, &pb.WriteFileRequest{SandboxId: id, Path: "/work/big", Data: big}); err != nil {
		t.Fatalf("20 MB write: %v", err)
	}
	if d, err := c.ReadFile(cx, &pb.FileRequest{SandboxId: id, Path: "/work/big"}); err != nil || string(d.Data) != string(big) {
		t.Fatalf("20 MB read: %v (%d bytes)", err, len(d.GetData()))
	}
	if r := shell(t, c, id, "", "head -c 10485760 /work/big"); len(r.Stdout) != 10<<20 {
		t.Fatalf("10 MB of output: got %d bytes", len(r.Stdout))
	}

	// Streaming output.
	st, err := c.ExecStream(cx, &pb.ExecRequest{SandboxId: id, Cmd: "for i in 1 2 3; do echo $i; sleep 0.1; done"})
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	var exit *pb.ExecResult
	for {
		ev, err := st.Recv()
		if err != nil {
			break
		}
		if o := ev.GetStdout(); o != nil {
			got.Write(o)
		}
		if e := ev.GetExit(); e != nil {
			exit = e
		}
	}
	if got.String() != "1\n2\n3\n" || exit == nil || exit.ExitCode != 0 {
		t.Fatalf("stream: %q %v", got.String(), exit)
	}

	// Background command + asynchronous output retrieval.
	bg, err := c.Exec(cx, &pb.ExecRequest{SandboxId: id, Session: "bg", Cmd: "sleep 0.2; echo done", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.GetOutput(cx, &pb.OutputRequest{SandboxId: id, Session: "bg", CmdId: bg.CmdId, WaitS: 5})
	if err != nil || !o.Done || string(o.Stdout) != "done\n" {
		t.Fatalf("output: %v %v", o, err)
	}

	// HTTP to a server running inside the sandbox (its netns only has lo).
	shell(t, c, id, "web", "cd /work && (python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 &)")
	shell(t, c, id, "", `for i in $(seq 100); do python3 -c 'import urllib.request as u; u.urlopen("http://127.0.0.1:8000/", timeout=1)' 2>/dev/null && break; sleep 0.05; done`)
	h, err := c.Http(cx, &pb.HttpRequest{SandboxId: id, Url: "http://127.0.0.1:8000/out.txt"})
	if err != nil || h.Status != 200 || string(h.Body) != "42\n" {
		t.Fatalf("http: %v %v", h, err)
	}
	// ...and the sandbox has no route to the outside world.
	if r := shell(t, c, id, "", "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 80), 2)' 2>&1; echo rc=$?"); !strings.Contains(string(r.Stdout), "rc=1") {
		t.Fatalf("external network reachable: %q", r.Stdout)
	}

	// Sessions run concurrently; closing one kills its process tree.
	start := time.Now()
	var wg sync.WaitGroup
	for _, s := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func(s string) { defer wg.Done(); shell(t, c, id, s, "sleep 0.5") }(s)
	}
	wg.Wait()
	if el := time.Since(start); el > 1400*time.Millisecond {
		t.Errorf("sessions did not run concurrently: %v", el)
	}
	if _, err := c.CloseSession(cx, &pb.SessionRef{SandboxId: id, Session: "web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Http(cx, &pb.HttpRequest{SandboxId: id, Url: "http://127.0.0.1:8000/", TimeoutS: 2}); err == nil {
		t.Error("server started by a closed session is still running")
	}

	if _, err := c.Stop(cx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(cx, &pb.ExecRequest{SandboxId: id, Cmd: "true"}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("exec on stopped sandbox: %v", err)
	}
}

func TestRuntimePauseTTLAndLoss(t *testing.T) {
	_, c := startContainers(t)
	cx := ctx(t)

	// Transparent resume: any runtime call to a paused sandbox resumes it.
	sb, err := c.Create(cx, ctrSpec)
	if err != nil {
		t.Fatal(err)
	}
	shell(t, c, sb.Id, "", "export KEEP=state")
	if s, err := c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id}); err != nil || s.State != pb.SandboxState_PAUSED {
		t.Fatalf("pause: %v %v", s, err)
	}
	if r := shell(t, c, sb.Id, "", "echo $KEEP"); string(r.Stdout) != "state\n" {
		t.Fatalf("after transparent resume: %q", r.Stdout)
	}
	if s, _ := c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id}); s.State != pb.SandboxState_RUNNING {
		t.Fatalf("state = %v", s.State)
	}

	// A command longer than the idle TTL keeps the sandbox alive.
	spec := proto.Clone(ctrSpec).(*pb.SandboxSpec)
	spec.TtlRunningStopS = 1
	short, err := c.Create(cx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if r := shell(t, c, short.Id, "", "sleep 2.5; echo survived"); string(r.Stdout) != "survived\n" {
		t.Fatalf("long command: %q", r.Stdout)
	}
	// ...but once idle it is reaped.
	eventuallyFor(t, 5*time.Second, func() bool {
		s, _ := c.GetSandbox(cx, &pb.SandboxRef{Id: short.Id})
		return s.GetState() == pb.SandboxState_STOPPED
	})

	// Killing aether marks the sandbox FAILED and returns its quota.
	victim, err := c.Create(cx, ctrSpec)
	if err != nil {
		t.Fatal(err)
	}
	before := usage(t, c, "root")["sandboxes"]
	c.Exec(cx, &pb.ExecRequest{SandboxId: victim.Id, Background: true, Cmd: `for p in /proc/[0-9]*; do
	  if tr '\0' ' ' <$p/cmdline 2>/dev/null | grep -q '^/.opendsec/bin/opendsec-aether --socket'; then kill -9 ${p#/proc/}; fi
	done`})
	eventuallyFor(t, 5*time.Second, func() bool {
		s, _ := c.GetSandbox(cx, &pb.SandboxRef{Id: victim.Id})
		return s.GetState() == pb.SandboxState_FAILED
	})
	s, _ := c.GetSandbox(cx, &pb.SandboxRef{Id: victim.Id})
	t.Logf("failed sandbox: %s", s.Message)
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == before-1 })

	// Runtime calls on sim sandboxes are rejected cleanly.
	simSb, _ := c.Create(cx, &pb.SandboxSpec{Backend: "sim"})
	if _, err := c.Exec(cx, &pb.ExecRequest{SandboxId: simSb.Id, Cmd: "true"}); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("exec on sim: %v", err)
	}
}

func eventuallyFor(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestEdgeRestartKeepsSandboxes(t *testing.T) {
	l, c := startContainers(t)
	cx := ctx(t)
	sb, err := c.Create(cx, ctrSpec)
	if err != nil {
		t.Fatal(err)
	}
	shell(t, c, sb.Id, "", "export X=survives && cd /tmp && echo before > /tmp/f")
	bg, err := c.Exec(cx, &pb.ExecRequest{SandboxId: sb.Id, Session: "job", Cmd: "sleep 1.5; echo finished", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	usageBefore := usage(t, c, "root")

	ec, _ := l.Cfg.Edge(sb.EdgeId)
	ec.KeepSandboxesOnExit = true
	t.Cleanup(func() { ec.KeepSandboxesOnExit = false }) // let the final Stop clean up
	err = l.RestartEdge(sb.EdgeId, func() {
		// While the edge is down the sandbox is unreachable, not lost.
		if _, err := c.Exec(cx, &pb.ExecRequest{SandboxId: sb.Id, Cmd: "true"}); rpcutil.Reason(err) != rpcutil.Unavailable {
			t.Errorf("exec while edge down: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	// The apiserver's connection to the edge recovers within its (capped)
	// reconnect backoff, or immediately once the watcher reports it healthy.
	start := time.Now()
	var s *pb.Sandbox
	eventuallyFor(t, 5*time.Second, func() bool {
		l.Settle()
		s, err = c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id})
		return err == nil
	})
	t.Logf("sandbox reachable again %v after edge restart", time.Since(start).Round(time.Millisecond))
	if s.State != pb.SandboxState_RUNNING {
		t.Fatalf("after restart: %v", s.State)
	}
	if r := shell(t, c, sb.Id, "", "echo $X $PWD; cat /tmp/f"); string(r.Stdout) != "survives /tmp\nbefore\n" {
		t.Fatalf("session after edge restart: %q", r.Stdout)
	}
	o, err := c.GetOutput(cx, &pb.OutputRequest{SandboxId: sb.Id, Session: "job", CmdId: bg.CmdId, WaitS: 5})
	if err != nil || !o.Done || string(o.Stdout) != "finished\n" {
		t.Fatalf("command running across the restart: %v %v", o, err)
	}
	if u := usage(t, c, "root"); u["sandboxes"] != usageBefore["sandboxes"] {
		t.Fatalf("quota changed across restart: %v -> %v", usageBefore, u)
	}
	// Lifecycle and task operations work on the adopted sandbox.
	if r, err := c.ApplyTaskAction(cx, &pb.TaskActionRequest{Project: "root", TaskId: "job-rt", Action: pb.TaskAction_TASK_PAUSE}); err != nil || r.Affected != 1 {
		t.Fatalf("task pause after restart: %v %v", r, err)
	}
	if r := shell(t, c, sb.Id, "", "echo $X"); string(r.Stdout) != "survives\n" {
		t.Fatalf("transparent resume after restart: %q", r.Stdout)
	}
	// Restarting again with a paused sandbox keeps it paused.
	c.PauseSandbox(cx, &pb.SandboxRef{Id: sb.Id})
	if err := l.RestartEdge(sb.EdgeId, nil); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 5*time.Second, func() bool {
		l.Settle()
		s, err = c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id})
		return err == nil
	})
	if s.State != pb.SandboxState_PAUSED {
		t.Fatalf("paused sandbox after restart: %v", s.State)
	}
	if _, err := c.Stop(cx, sb.Id); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return usage(t, c, "root")["sandboxes"] == usageBefore["sandboxes"]-1 })
}

func TestImageAwareScheduling(t *testing.T) {
	l, c := startContainers(t)
	// e000 has "host" and "py"; e001 only "host" (images differ per node).
	_ = l
	cx := ctx(t)
	for i := 0; i < 6; i++ {
		sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "py", Resources: &pb.Resources{CpuCores: 0.2, MemoryMb: 128}})
		if err != nil {
			t.Fatal(err)
		}
		if sb.EdgeId != "e000" {
			t.Fatalf("image py placed on %s, which does not have it", sb.EdgeId)
		}
		c.Stop(cx, sb.Id)
	}
	_, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "nope:1", Resources: &pb.Resources{MemoryMb: 128}})
	if rpcutil.Reason(err) != rpcutil.NotFound {
		t.Fatalf("unknown image: want not_found, got %v", err)
	}
}

// TestProcessesEndToEnd (spec §37): the process API through apiserver, edge
// and aether in a real container: output, stdin, exit codes, a terminal,
// reconnecting, signals, and the new file calls.
func TestProcessesEndToEnd(t *testing.T) {
	_, c := startContainers(t)
	cx := ctx(t)
	sb, err := c.Create(cx, &pb.SandboxSpec{Backend: "container", Image: "host", Resources: &pb.Resources{CpuCores: 1, MemoryMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	collect := func(st interface {
		Recv() (*pb.ProcessEvent, error)
	}) (pid uint32, out string, exit *pb.ProcessExit) {
		t.Helper()
		var b strings.Builder
		for {
			ev, err := st.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch x := ev.Event.(type) {
			case *pb.ProcessEvent_Started:
				pid = x.Started
			case *pb.ProcessEvent_Stdout:
				b.Write(x.Stdout)
			case *pb.ProcessEvent_Stderr:
				b.WriteString("E:" + string(x.Stderr))
			case *pb.ProcessEvent_Pty:
				b.Write(x.Pty)
			case *pb.ProcessEvent_Exit:
				exit = x.Exit
			}
			out = b.String()
		}
	}

	st, err := c.StartProcess(cx, &pb.StartProcessRequest{SandboxId: sb.Id, Cmd: "/bin/bash",
		Args: []string{"-l", "-c", "echo out; echo err >&2; exit 7"}})
	if err != nil {
		t.Fatal(err)
	}
	if pid, out, exit := collect(st); pid == 0 || out != "out\nE:err\n" && out != "E:err\nout\n" || exit.ExitCode != 7 {
		t.Fatalf("pid %d out %q exit %+v", pid, out, exit)
	}

	// stdin, detached and reconnected by tag.
	scx, cancel := context.WithCancel(cx)
	st, err = c.StartProcess(scx, &pb.StartProcessRequest{SandboxId: sb.Id, Cmd: "sh", Args: []string{"-c", "read a; echo got $a"},
		Stdin: true, Tag: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil || first.GetStarted() == 0 {
		t.Fatalf("start: %v %v", first, err)
	}
	cancel()
	if l, err := c.ListProcesses(cx, &pb.ProcessRef{SandboxId: sb.Id}); err != nil || len(l.Processes) != 1 || l.Processes[0].Tag != "reader" {
		t.Fatalf("list: %v %v", l, err)
	}
	cst, err := c.ConnectProcess(cx, &pb.ProcessRef{SandboxId: sb.Id, Tag: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		c.SendProcessInput(cx, &pb.ProcessInput{SandboxId: sb.Id, Tag: "reader", Data: []byte("it\n")})
	}()
	if _, out, exit := collect(cst); out != "got it\n" || exit.ExitCode != 0 {
		t.Fatalf("reconnected: %q %+v", out, exit)
	}

	// A terminal, killed by a signal.
	st, err = c.StartProcess(cx, &pb.StartProcessRequest{SandboxId: sb.Id, Cmd: "sh", Args: []string{"-c", "stty size; sleep 60"},
		Pty: &pb.PtySize{Cols: 90, Rows: 20}})
	if err != nil {
		t.Fatal(err)
	}
	first, _ = st.Recv()
	go func() {
		time.Sleep(300 * time.Millisecond)
		c.SignalProcess(cx, &pb.ProcessSignal{SandboxId: sb.Id, Pid: first.GetStarted(), Signal: 9})
	}()
	if _, out, exit := collect(st); !strings.Contains(out, "20 90") || exit.Exited {
		t.Fatalf("pty: %q %+v", out, exit)
	}

	if _, err := c.MakeDir(cx, &pb.FileRequest{SandboxId: sb.Id, Path: "/tmp/a/b"}); err != nil {
		t.Fatal(err)
	}
	c.WriteFile(cx, &pb.WriteFileRequest{SandboxId: sb.Id, Path: "/tmp/a/b/f", Data: []byte("x")})
	if fi, err := c.Move(cx, &pb.MoveRequest{SandboxId: sb.Id, Source: "/tmp/a/b/f", Destination: "/tmp/c/g"}); err != nil || fi.Name != "g" {
		t.Fatalf("move: %v %v", fi, err)
	}
	if d, err := c.ReadFile(cx, &pb.FileRequest{SandboxId: sb.Id, Path: "/tmp/c/g"}); err != nil || string(d.Data) != "x" {
		t.Fatalf("moved file: %v %v", d, err)
	}
}
