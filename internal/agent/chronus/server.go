package chronus

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const (
	// MaxOutput caps the output returned by one Exec/GetOutput call.
	MaxOutput = 16 << 20
	// MaxFileRead caps one ReadFile call.
	MaxFileRead = 64 << 20
	streamPoll  = 25 * time.Millisecond
)

// Server implements pb.RuntimeServer for one session.
type Server struct {
	pb.UnimplementedRuntimeServer
	Session string
	Shell   *Shell
}

func dur(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

func (s *Server) result(c *Command, outOff, errOff int64) (*pb.ExecResult, error) {
	code, timedOut, d := c.Status()
	done := c.IsDone()
	out, outSize, err := ReadRange(c.OutPath, outOff, MaxOutput)
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Internal, "read output: %v", err)
	}
	errb, errSize, err := ReadRange(c.ErrPath, errOff, MaxOutput)
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Internal, "read output: %v", err)
	}
	r := &pb.ExecResult{
		CmdId: c.ID, Done: done, TimedOut: timedOut, Stdout: out, Stderr: errb,
		DurationS: d.Seconds(), StdoutSize: outSize, StderrSize: errSize,
		Truncated:    outOff+int64(len(out)) < outSize || errOff+int64(len(errb)) < errSize,
		DroppedBytes: c.Dropped(),
	}
	if done {
		r.ExitCode = int32(code)
	}
	return r, nil
}

func (s *Server) submit(ctx context.Context, r *pb.ExecRequest) (*Command, error) {
	if r.Cmd == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "cmd required")
	}
	c, err := s.Shell.Submit(ctx, r.Cmd, dur(r.TimeoutS), r.Env, r.Cwd, r.RequestId)
	if err != nil {
		if ctx.Err() != nil {
			return nil, rpcutil.Err(rpcutil.Timeout, "session %s busy", s.Session)
		}
		return nil, rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	return c, nil
}

func (s *Server) Exec(ctx context.Context, r *pb.ExecRequest) (*pb.ExecResult, error) {
	c, err := s.submit(ctx, r)
	if err != nil {
		return nil, err
	}
	if r.Background {
		return &pb.ExecResult{CmdId: c.ID}, nil
	}
	select {
	case <-c.Done():
	case <-ctx.Done():
		// The command keeps running; its output stays retrievable by id.
		return nil, rpcutil.Err(rpcutil.Timeout, "command %d still running (fetch with GetOutput)", c.ID)
	}
	return s.result(c, 0, 0)
}

func (s *Server) ExecStream(r *pb.ExecRequest, st pb.Runtime_ExecStreamServer) error {
	ctx := st.Context()
	c, err := s.submit(ctx, r)
	if err != nil {
		return err
	}
	if err := st.Send(&pb.ExecEvent{Event: &pb.ExecEvent_Started{Started: c.ID}}); err != nil {
		return err
	}
	oo, eo := max(r.StdoutOffset, 0), max(r.StderrOffset, 0)
	tick := time.NewTicker(streamPoll)
	defer tick.Stop()
	for {
		finished := c.IsDone() // read output after observing done, so nothing is missed
		for _, f := range []struct {
			path string
			off  *int64
			wrap func([]byte) *pb.ExecEvent
		}{
			{c.OutPath, &oo, func(b []byte) *pb.ExecEvent { return &pb.ExecEvent{Event: &pb.ExecEvent_Stdout{Stdout: b}} }},
			{c.ErrPath, &eo, func(b []byte) *pb.ExecEvent { return &pb.ExecEvent{Event: &pb.ExecEvent_Stderr{Stderr: b}} }},
		} {
			for {
				b, _, err := ReadRange(f.path, *f.off, 1<<20)
				if err != nil || len(b) == 0 {
					break
				}
				*f.off += int64(len(b))
				if err := st.Send(f.wrap(b)); err != nil {
					return err
				}
			}
		}
		if finished {
			code, timedOut, d := c.Status()
			return st.Send(&pb.ExecEvent{Event: &pb.ExecEvent_Exit{Exit: &pb.ExecResult{
				CmdId: c.ID, Done: true, ExitCode: int32(code), TimedOut: timedOut, DurationS: d.Seconds(),
				StdoutSize: oo, StderrSize: eo}}})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.Done():
		case <-tick.C:
		}
	}
}

func (s *Server) GetOutput(ctx context.Context, r *pb.OutputRequest) (*pb.ExecResult, error) {
	c := s.Shell.Get(r.CmdId)
	if c == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "command %d in session %s", r.CmdId, s.Session)
	}
	if r.WaitS > 0 {
		select {
		case <-c.Done():
		case <-time.After(dur(r.WaitS)):
		case <-ctx.Done():
		}
	}
	return s.result(c, r.StdoutOffset, r.StderrOffset)
}

// ---- files ---------------------------------------------------------------------

func (s *Server) path(p string) (string, error) {
	if p == "" {
		return "", rpcutil.Err(rpcutil.Invalid, "path required")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.Shell.Workdir, p)
	}
	return filepath.Clean(p), nil
}

func fsErr(err error, path string) error {
	switch {
	case os.IsNotExist(err):
		return rpcutil.Err(rpcutil.NotFound, "%s", path)
	case os.IsPermission(err):
		return rpcutil.Err(rpcutil.Forbidden, "%s: permission denied", path)
	}
	return rpcutil.Err(rpcutil.Invalid, "%v", err)
}

func info(name string, st fs.FileInfo) *pb.FileInfo {
	t := "other"
	switch m := st.Mode(); {
	case m.IsDir():
		t = "dir"
	case m&fs.ModeSymlink != 0:
		t = "symlink"
	case m.IsRegular():
		t = "file"
	}
	return &pb.FileInfo{Name: name, Type: t, Size: st.Size(), Mode: uint32(st.Mode().Perm()),
		Mtime: float64(st.ModTime().UnixNano()) / 1e9}
}

func (s *Server) ReadFile(_ context.Context, r *pb.FileRequest) (*pb.FileData, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(p); err != nil {
		return nil, fsErr(err, p)
	} else if st.IsDir() {
		return nil, rpcutil.Err(rpcutil.Invalid, "%s is a directory", p)
	}
	limit := int64(MaxFileRead)
	if r.Length > 0 && r.Length < limit {
		limit = r.Length
	}
	b, size, err := ReadRange(p, r.Offset, limit)
	if err != nil {
		return nil, fsErr(err, p)
	}
	return &pb.FileData{Data: b, Size: size}, nil
}

func (s *Server) WriteFile(_ context.Context, r *pb.WriteFileRequest) (*pb.FileInfo, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, fsErr(err, p)
	}
	mode := os.FileMode(0o644)
	if r.Mode != 0 {
		mode = os.FileMode(r.Mode)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if r.Append {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(p, flags, mode)
	if err != nil {
		return nil, fsErr(err, p)
	}
	_, werr := f.Write(r.Data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return nil, fsErr(errorsJoin(werr, cerr), p)
	}
	if r.Mode != 0 {
		os.Chmod(p, mode)
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, fsErr(err, p)
	}
	return info(filepath.Base(p), st), nil
}

func errorsJoin(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func (s *Server) ListDir(_ context.Context, r *pb.FileRequest) (*pb.DirListing, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, fsErr(err, p)
	}
	out := &pb.DirListing{}
	for _, e := range ents {
		st, err := e.Info()
		if err != nil {
			continue
		}
		out.Entries = append(out.Entries, info(e.Name(), st))
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Name < out.Entries[j].Name })
	return out, nil
}

func (s *Server) Stat(_ context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, fsErr(err, p)
	}
	return info(filepath.Base(p), st), nil
}

func (s *Server) Remove(_ context.Context, r *pb.FileRequest) (*pb.Empty, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(p); err != nil {
		return nil, fsErr(err, p)
	}
	if r.Recursive {
		err = os.RemoveAll(p)
	} else {
		err = os.Remove(p)
	}
	if err != nil {
		return nil, fsErr(err, p)
	}
	return &pb.Empty{}, nil
}

// MakeDir creates a directory and its parents; an existing directory is
// not an error (its info is returned).
func (s *Server) MakeDir(_ context.Context, r *pb.FileRequest) (*pb.FileInfo, error) {
	p, err := s.path(r.Path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return nil, fsErr(err, p)
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, fsErr(err, p)
	}
	return info(filepath.Base(p), st), nil
}

// Move renames a file or directory (within one file system).
func (s *Server) Move(_ context.Context, r *pb.MoveRequest) (*pb.FileInfo, error) {
	src, err := s.path(r.Source)
	if err != nil {
		return nil, err
	}
	dst, err := s.path(r.Destination)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, fsErr(err, dst)
	}
	if err := os.Rename(src, dst); err != nil {
		return nil, fsErr(err, src)
	}
	st, err := os.Lstat(dst)
	if err != nil {
		return nil, fsErr(err, dst)
	}
	return info(filepath.Base(dst), st), nil
}

// ---- http ---------------------------------------------------------------------------

// httpClient opens a connection per request: a kept-alive one could be
// dead after a snapshot restore (the copy has a new network, spec §20) or
// outlive a network rule taken back.
var httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true,
	TLSHandshakeTimeout: 10 * time.Second}}

func (s *Server) Http(ctx context.Context, r *pb.HttpRequest) (*pb.HttpResponse, error) {
	timeout := dur(r.TimeoutS)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, r.Url, bytes.NewReader(r.Body))
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "%v", err)
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "http: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFileRead))
	if err != nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "http body: %v", err)
	}
	out := &pb.HttpResponse{Status: int32(resp.StatusCode), Body: body, Headers: map[string]string{}}
	for k := range resp.Header {
		out.Headers[k] = resp.Header.Get(k)
	}
	return out, nil
}

func (s *Server) ListSessions(context.Context, *pb.SessionRef) (*pb.SessionList, error) {
	return &pb.SessionList{Sessions: []string{s.Session}}, nil
}
