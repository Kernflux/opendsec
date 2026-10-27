package e2b

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kernflux/opendsec/gen/go/e2b/envd/filesystem"
	"github.com/kernflux/opendsec/gen/go/e2b/envd/filesystem/filesystemconnect"
	"github.com/kernflux/opendsec/gen/go/e2b/envd/process"
	"github.com/kernflux/opendsec/gen/go/e2b/envd/process/processconnect"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// envd: E2B's in-sandbox API, served by the gateway on the sandbox's behalf
// (spec §37): Process and Filesystem over Connect, and the HTTP routes for
// files.

type userKey struct{}

func (g *Gateway) envdHandler() http.Handler {
	mux := http.NewServeMux()
	p, h := processconnect.NewProcessHandler(&processService{g})
	mux.Handle(p, h)
	p, h = filesystemconnect.NewFilesystemHandler(&filesystemService{g})
	mux.Handle(p, h)
	mux.HandleFunc("GET /files", g.download)
	mux.HandleFunc("POST /files", g.upload)
	mux.HandleFunc("GET /envs", func(w http.ResponseWriter, r *http.Request) {
		sb, err := g.api.GetSandbox(r.Context(), &pb.SandboxRef{Id: sandboxOf(r.Context())})
		if err != nil {
			writeAPIErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envOf(sb))
	})
	mux.HandleFunc("POST /init", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"cpu_count": 0, "cpu_used_pct": 0, "mem_total": 0, "mem_used": 0, "ts": time.Now().Unix()})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := apiKey(r)
		if r.URL.Path == "/health" {
			g.health(w, r, key)
			return
		}
		if key == "" {
			writeErr(w, http.StatusUnauthorized, "missing access token (X-Access-Token): an OpenDsec token")
			return
		}
		ctx := client.WithToken(r.Context(), key)
		if u := cmpOr(basicUser(r.Header.Get("Authorization")), r.URL.Query().Get("username")); u != "" {
			ctx = context.WithValue(ctx, userKey{}, u)
		}
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// health answers envd's /health for the sandbox: 204 while it runs, 502
// (what E2B's proxy answers, and the SDKs' is_running reads as false) once
// it is gone or paused. Without a token there is nothing to ask: 204.
func (g *Gateway) health(w http.ResponseWriter, r *http.Request, key string) {
	if key != "" {
		sb, err := g.api.GetSandbox(client.WithToken(r.Context(), key), &pb.SandboxRef{Id: sandboxOf(r.Context())})
		switch {
		case rpcutil.Reason(err) == rpcutil.NotFound:
			writeErr(w, http.StatusBadGateway, "sandbox not found")
			return
		case err != nil:
			writeAPIErr(w, err)
			return
		case sb.State != pb.SandboxState_RUNNING && sb.State != pb.SandboxState_CREATING:
			writeErr(w, http.StatusBadGateway, "sandbox is "+strings.ToLower(sb.State.String()))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func sandboxOf(ctx context.Context) string { s, _ := ctx.Value(sandboxKey{}).(string); return s }
func userOf(ctx context.Context) string    { u, _ := ctx.Value(userKey{}).(string); return u }

// fileSession is the agent session file operations run in: one per user
// the SDK names, started as that user, so files are read and written with
// its identity (a session keeps its user; "" = the default session).
func fileSession(ctx context.Context) string {
	if u := userOf(ctx); u != "" {
		return "e2b-user-" + strings.ReplaceAll(u, ":", "_")
	}
	return ""
}

// basicUser is the user of envd's "Authorization: Basic base64(user:)".
func basicUser(h string) string {
	enc, ok := strings.CutPrefix(h, "Basic ")
	if !ok {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	u, _, _ := strings.Cut(string(b), ":")
	return u
}

// ---- Process -------------------------------------------------------------------------

type processService struct{ g *Gateway }

func selector(id string, s *process.ProcessSelector) *pb.ProcessRef {
	return &pb.ProcessRef{SandboxId: id, Pid: s.GetPid(), Tag: s.GetTag()}
}

func (s *processService) List(ctx context.Context, _ *connect.Request[process.ListRequest]) (*connect.Response[process.ListResponse], error) {
	l, err := s.g.api.ListProcesses(ctx, &pb.ProcessRef{SandboxId: sandboxOf(ctx)})
	if err != nil {
		return nil, connectErr(err)
	}
	out := &process.ListResponse{}
	for _, p := range l.Processes {
		info := &process.ProcessInfo{Pid: p.Pid,
			Config: &process.ProcessConfig{Cmd: p.Cmd, Args: p.Args, Envs: p.Env, Cwd: &p.Cwd}}
		if p.Tag != "" {
			info.Tag = &p.Tag
		}
		out.Processes = append(out.Processes, info)
	}
	return connect.NewResponse(out), nil
}

func (s *processService) Start(ctx context.Context, req *connect.Request[process.StartRequest], st *connect.ServerStream[process.StartResponse]) error {
	id, m := sandboxOf(ctx), req.Msg
	cfg := m.GetProcess()
	env, err := s.g.sandboxEnv(ctx, id)
	if err != nil {
		return connectErr(err)
	}
	merged := map[string]string{}
	for k, v := range env {
		merged[k] = v
	}
	for k, v := range cfg.GetEnvs() {
		merged[k] = v
	}
	r := &pb.StartProcessRequest{SandboxId: id, Cmd: cfg.GetCmd(), Args: cfg.GetArgs(), Env: merged, Cwd: cfg.GetCwd(),
		User: userOf(ctx), Tag: m.GetTag(), Stdin: m.Stdin == nil || *m.Stdin} // unset: stdin on, as old envds
	if m.Pty != nil {
		r.Pty = &pb.PtySize{Cols: m.Pty.GetSize().GetCols(), Rows: m.Pty.GetSize().GetRows()}
	}
	up, err := s.g.api.StartProcess(ctx, r)
	if err != nil {
		return connectErr(err)
	}
	return relay(ctx, up, keepalive(req.Header()), func(ev *process.ProcessEvent) error {
		return st.Send(&process.StartResponse{Event: ev})
	})
}

func (s *processService) Connect(ctx context.Context, req *connect.Request[process.ConnectRequest], st *connect.ServerStream[process.ConnectResponse]) error {
	up, err := s.g.api.ConnectProcess(ctx, selector(sandboxOf(ctx), req.Msg.GetProcess()))
	if err != nil {
		return connectErr(err)
	}
	return relay(ctx, up, keepalive(req.Header()), func(ev *process.ProcessEvent) error {
		return st.Send(&process.ConnectResponse{Event: ev})
	})
}

// keepalive is the interval of the keepalive events a stream's caller asks
// for (Keepalive-Ping-Interval, seconds), so idle streams survive proxies.
func keepalive(h http.Header) time.Duration {
	if s, err := strconv.Atoi(h.Get("Keepalive-Ping-Interval")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 0
}

type processEvents interface {
	Recv() (*pb.ProcessEvent, error)
}

// relay converts a process's events to envd's and sends them, with
// keepalive events every interval.
func relay(ctx context.Context, up processEvents, interval time.Duration, send func(*process.ProcessEvent) error) error {
	var mu sync.Mutex
	locked := func(ev *process.ProcessEvent) error { mu.Lock(); defer mu.Unlock(); return send(ev) }
	if interval > 0 {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if locked(&process.ProcessEvent{Event: &process.ProcessEvent_Keepalive{Keepalive: &process.ProcessEvent_KeepAlive{}}}) != nil {
						return
					}
				}
			}
		}()
	}
	for {
		ev, err := up.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return connectErr(err)
		}
		if out := envdEvent(ev); out != nil {
			if err := locked(out); err != nil {
				return err
			}
		}
	}
}

func envdEvent(ev *pb.ProcessEvent) *process.ProcessEvent {
	data := func(o any) *process.ProcessEvent {
		d := &process.ProcessEvent_DataEvent{}
		switch o := o.(type) {
		case *process.ProcessEvent_DataEvent_Stdout:
			d.Output = o
		case *process.ProcessEvent_DataEvent_Stderr:
			d.Output = o
		case *process.ProcessEvent_DataEvent_Pty:
			d.Output = o
		}
		return &process.ProcessEvent{Event: &process.ProcessEvent_Data{Data: d}}
	}
	switch x := ev.Event.(type) {
	case *pb.ProcessEvent_Started:
		return &process.ProcessEvent{Event: &process.ProcessEvent_Start{Start: &process.ProcessEvent_StartEvent{Pid: x.Started}}}
	case *pb.ProcessEvent_Stdout:
		return data(&process.ProcessEvent_DataEvent_Stdout{Stdout: x.Stdout})
	case *pb.ProcessEvent_Stderr:
		return data(&process.ProcessEvent_DataEvent_Stderr{Stderr: x.Stderr})
	case *pb.ProcessEvent_Pty:
		return data(&process.ProcessEvent_DataEvent_Pty{Pty: x.Pty})
	case *pb.ProcessEvent_Exit:
		end := &process.ProcessEvent_EndEvent{ExitCode: x.Exit.ExitCode, Exited: x.Exit.Exited, Status: x.Exit.Status}
		if x.Exit.Error != "" {
			end.Error = &x.Exit.Error
		}
		return &process.ProcessEvent{Event: &process.ProcessEvent_End{End: end}}
	}
	return nil
}

func (s *processService) Update(ctx context.Context, req *connect.Request[process.UpdateRequest]) (*connect.Response[process.UpdateResponse], error) {
	if req.Msg.Pty == nil {
		return connect.NewResponse(&process.UpdateResponse{}), nil
	}
	ref := selector(sandboxOf(ctx), req.Msg.GetProcess())
	_, err := s.g.api.ResizeProcess(ctx, &pb.ProcessResize{SandboxId: ref.SandboxId, Pid: ref.Pid, Tag: ref.Tag,
		Size: &pb.PtySize{Cols: req.Msg.Pty.GetSize().GetCols(), Rows: req.Msg.Pty.GetSize().GetRows()}})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&process.UpdateResponse{}), nil
}

func inputData(in *process.ProcessInput) []byte {
	if b := in.GetStdin(); b != nil {
		return b
	}
	return in.GetPty()
}

func (s *processService) SendInput(ctx context.Context, req *connect.Request[process.SendInputRequest]) (*connect.Response[process.SendInputResponse], error) {
	ref := selector(sandboxOf(ctx), req.Msg.GetProcess())
	if _, err := s.g.api.SendProcessInput(ctx, &pb.ProcessInput{SandboxId: ref.SandboxId, Pid: ref.Pid, Tag: ref.Tag,
		Data: inputData(req.Msg.GetInput())}); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&process.SendInputResponse{}), nil
}

// StreamInput sends each input of the stream in order, as SendInput does.
func (s *processService) StreamInput(ctx context.Context, st *connect.ClientStream[process.StreamInputRequest]) (*connect.Response[process.StreamInputResponse], error) {
	var ref *pb.ProcessRef
	for st.Receive() {
		switch x := st.Msg().Event.(type) {
		case *process.StreamInputRequest_Start:
			ref = selector(sandboxOf(ctx), x.Start.GetProcess())
		case *process.StreamInputRequest_Data:
			if ref == nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("input before the start event"))
			}
			if _, err := s.g.api.SendProcessInput(ctx, &pb.ProcessInput{SandboxId: ref.SandboxId, Pid: ref.Pid, Tag: ref.Tag,
				Data: inputData(x.Data.GetInput())}); err != nil {
				return nil, connectErr(err)
			}
		}
	}
	if err := st.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&process.StreamInputResponse{}), nil
}

func (s *processService) SendSignal(ctx context.Context, req *connect.Request[process.SendSignalRequest]) (*connect.Response[process.SendSignalResponse], error) {
	ref := selector(sandboxOf(ctx), req.Msg.GetProcess())
	if _, err := s.g.api.SignalProcess(ctx, &pb.ProcessSignal{SandboxId: ref.SandboxId, Pid: ref.Pid, Tag: ref.Tag,
		Signal: int32(req.Msg.GetSignal())}); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&process.SendSignalResponse{}), nil
}

func (s *processService) CloseStdin(ctx context.Context, req *connect.Request[process.CloseStdinRequest]) (*connect.Response[process.CloseStdinResponse], error) {
	if _, err := s.g.api.CloseProcessStdin(ctx, selector(sandboxOf(ctx), req.Msg.GetProcess())); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&process.CloseStdinResponse{}), nil
}

// ---- Filesystem ----------------------------------------------------------------------

type filesystemService struct{ g *Gateway }

func entry(p string, fi *pb.FileInfo) *filesystem.EntryInfo {
	mode := os.FileMode(fi.Mode).Perm()
	t := filesystem.FileType_FILE_TYPE_FILE
	switch fi.Type {
	case "dir":
		t, mode = filesystem.FileType_FILE_TYPE_DIRECTORY, mode|os.ModeDir
	case "symlink":
		t, mode = filesystem.FileType_FILE_TYPE_SYMLINK, mode|os.ModeSymlink
	}
	return &filesystem.EntryInfo{Name: fi.Name, Type: t, Path: p, Size: fi.Size, Mode: uint32(mode.Perm()),
		Permissions: mode.String(), IsSymlink: fi.Type == "symlink",
		ModifiedTime: timestamppb.New(time.Unix(0, int64(fi.Mtime*1e9)))}
}

func (s *filesystemService) Stat(ctx context.Context, req *connect.Request[filesystem.StatRequest]) (*connect.Response[filesystem.StatResponse], error) {
	fi, err := s.g.api.Stat(ctx, &pb.FileRequest{SandboxId: sandboxOf(ctx), Session: fileSession(ctx), User: userOf(ctx), Path: req.Msg.Path})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&filesystem.StatResponse{Entry: entry(req.Msg.Path, fi)}), nil
}

func (s *filesystemService) MakeDir(ctx context.Context, req *connect.Request[filesystem.MakeDirRequest]) (*connect.Response[filesystem.MakeDirResponse], error) {
	id := sandboxOf(ctx)
	if _, err := s.g.api.Stat(ctx, &pb.FileRequest{SandboxId: id, Session: fileSession(ctx), User: userOf(ctx), Path: req.Msg.Path}); err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New(req.Msg.Path+" already exists"))
	}
	fi, err := s.g.api.MakeDir(ctx, &pb.FileRequest{SandboxId: id, Session: fileSession(ctx), User: userOf(ctx), Path: req.Msg.Path})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&filesystem.MakeDirResponse{Entry: entry(req.Msg.Path, fi)}), nil
}

func (s *filesystemService) Move(ctx context.Context, req *connect.Request[filesystem.MoveRequest]) (*connect.Response[filesystem.MoveResponse], error) {
	fi, err := s.g.api.Move(ctx, &pb.MoveRequest{SandboxId: sandboxOf(ctx), Session: fileSession(ctx), User: userOf(ctx), Source: req.Msg.Source, Destination: req.Msg.Destination})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&filesystem.MoveResponse{Entry: entry(req.Msg.Destination, fi)}), nil
}

// maxListEntries bounds a recursive listing.
const maxListEntries = 100000

func (s *filesystemService) ListDir(ctx context.Context, req *connect.Request[filesystem.ListDirRequest]) (*connect.Response[filesystem.ListDirResponse], error) {
	id, out := sandboxOf(ctx), &filesystem.ListDirResponse{}
	depth := int(max(req.Msg.Depth, 1))
	var walk func(dir string, level int) error
	walk = func(dir string, level int) error {
		l, err := s.g.api.ListDir(ctx, &pb.FileRequest{SandboxId: id, Session: fileSession(ctx), User: userOf(ctx), Path: dir})
		if err != nil {
			return err
		}
		for _, fi := range l.Entries {
			p := path.Join(dir, fi.Name)
			out.Entries = append(out.Entries, entry(p, fi))
			if len(out.Entries) > maxListEntries {
				return connect.NewError(connect.CodeResourceExhausted, errors.New("too many entries"))
			}
			if fi.Type == "dir" && level < depth {
				if err := walk(p, level+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(req.Msg.Path, 1); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(out), nil
}

func (s *filesystemService) Remove(ctx context.Context, req *connect.Request[filesystem.RemoveRequest]) (*connect.Response[filesystem.RemoveResponse], error) {
	if _, err := s.g.api.Remove(ctx, &pb.FileRequest{SandboxId: sandboxOf(ctx), Session: fileSession(ctx), User: userOf(ctx), Path: req.Msg.Path, Recursive: true}); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&filesystem.RemoveResponse{}), nil
}

var errNoWatch = connect.NewError(connect.CodeUnimplemented, errors.New("watching directories is not supported by the OpenDsec E2B gateway"))

func (s *filesystemService) WatchDir(context.Context, *connect.Request[filesystem.WatchDirRequest], *connect.ServerStream[filesystem.WatchDirResponse]) error {
	return errNoWatch
}

func (s *filesystemService) CreateWatcher(context.Context, *connect.Request[filesystem.CreateWatcherRequest]) (*connect.Response[filesystem.CreateWatcherResponse], error) {
	return nil, errNoWatch
}

func (s *filesystemService) GetWatcherEvents(context.Context, *connect.Request[filesystem.GetWatcherEventsRequest]) (*connect.Response[filesystem.GetWatcherEventsResponse], error) {
	return nil, errNoWatch
}

func (s *filesystemService) RemoveWatcher(context.Context, *connect.Request[filesystem.RemoveWatcherRequest]) (*connect.Response[filesystem.RemoveWatcherResponse], error) {
	return nil, errNoWatch
}

// ---- files over HTTP -------------------------------------------------------------------

// fileChunk is how much of a file one ReadFile/WriteFile call moves: well
// under gRPC's default 4 MB message limit.
const fileChunk = 2 << 20

// download streams a file (GET /files?path=).
func (g *Gateway) download(w http.ResponseWriter, r *http.Request) {
	ctx, id, p := r.Context(), sandboxOf(r.Context()), r.URL.Query().Get("path")
	var off int64
	for {
		d, err := g.api.ReadFile(ctx, &pb.FileRequest{SandboxId: id, Session: fileSession(ctx), User: userOf(ctx), Path: p, Offset: off, Length: fileChunk})
		if err != nil {
			if off == 0 {
				writeAPIErr(w, err)
			}
			return // mid-file: the response is cut short
		}
		if off == 0 {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(d.Size, 10))
			w.WriteHeader(http.StatusOK)
		}
		if _, err := w.Write(d.Data); err != nil {
			return
		}
		off += int64(len(d.Data))
		if len(d.Data) == 0 || off >= d.Size {
			return
		}
	}
}

type uploaded struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// upload writes files (POST /files?path=): the body (application/
// octet-stream), or each "file" part of a multipart form, at path, or at
// the part's file name when there is no path.
func (g *Gateway) upload(w http.ResponseWriter, r *http.Request) {
	ctx, id, target := r.Context(), sandboxOf(r.Context()), r.URL.Query().Get("path")
	var out []uploaded
	write := func(p string, body io.Reader) error {
		buf := make([]byte, fileChunk)
		for first := true; ; first = false {
			n, rerr := io.ReadFull(body, buf)
			if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
				return rerr
			}
			if n > 0 || first {
				if _, err := g.api.WriteFile(ctx, &pb.WriteFileRequest{SandboxId: id, Session: fileSession(ctx), User: userOf(ctx), Path: p, Data: buf[:n], Append: !first}); err != nil {
					return err
				}
			}
			if rerr != nil {
				out = append(out, uploaded{Name: path.Base(p), Type: "file", Path: p})
				return nil
			}
		}
	}
	switch enc := r.Header.Get("Content-Encoding"); enc {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "gzip body: "+err.Error())
			return
		}
		defer zr.Close()
		r.Body = zr
	default:
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported Content-Encoding "+enc)
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "multipart/form-data" {
		if target == "" {
			writeErr(w, http.StatusBadRequest, "path required")
			return
		}
		if err := write(target, r.Body); err != nil {
			writeAPIErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if part.FormName() != "file" {
			continue
		}
		// The SDKs send each file's path as its file name; Part.FileName
		// keeps only the base, which would put every "x" in one place.
		_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		p := cmpOr(target, params["filename"])
		if p == "" {
			writeErr(w, http.StatusBadRequest, "path required")
			return
		}
		if err := write(p, part); err != nil {
			writeAPIErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}
