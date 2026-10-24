package apiserver

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// AuditRecord is one line of the audit log (spec §14.4).
type AuditRecord struct {
	Time      string  `json:"ts"`
	RequestID string  `json:"request_id"`
	Principal string  `json:"principal"`
	Method    string  `json:"method"`
	Project   string  `json:"project,omitempty"`
	SandboxID string  `json:"sandbox_id,omitempty"`
	TaskID    string  `json:"task_id,omitempty"`
	Target    string  `json:"target,omitempty"` // principal/project acted upon by IAM calls
	Code      string  `json:"code"`
	Reason    string  `json:"reason,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
	Peer      string  `json:"peer,omitempty"`
	CmdLen    int     `json:"cmd_len,omitempty"`
	CmdSHA256 string  `json:"cmd_sha256,omitempty"` // exec: never the command text itself
	Count     int32   `json:"count,omitempty"`
}

// Verbose methods (runtime operations and read-only queries) are only
// audited when audit_runtime is set; everything else always is.
var verboseMethods = map[string]bool{
	"Exec": true, "ExecStream": true, "GetOutput": true, "ReadFile": true, "WriteFile": true,
	"ListDir": true, "Stat": true, "Remove": true, "Http": true, "ListSessions": true, "CloseSession": true,
	"MakeDir": true, "Move": true, "StartProcess": true, "ConnectProcess": true, "ListProcesses": true,
	"SendProcessInput": true, "CloseProcessStdin": true, "SignalProcess": true, "ResizeProcess": true, "ConnectPort": true,
	"GetSandbox": true, "ListSandboxes": true, "ClusterStatus": true, "WhoAmI": true, "GetProject": true, "GetUsage": true, "ListTokens": true,
}

// Auditor appends records to JSON-lines files, rotating by size. Writes are
// asynchronous but never dropped: a full buffer blocks the request.
type Auditor struct {
	dir, name string
	maxBytes  int64
	keep      int // files kept
	verbose   bool

	sinks []ext.AuditSink // the extensions' (ext), after the file

	ch   chan AuditRecord
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	size int64
}

// NewAuditor writes the audit log of apiserver name into dir, starting a
// new file past maxMB and keeping the newest keep files (defaults 256 MB and
// 8): without a bound the log fills the disk (spec §33.2).
func NewAuditor(dir, name string, maxMB int64, keep int, verbose bool) (*Auditor, error) {
	if maxMB <= 0 {
		maxMB = 256
	}
	if keep <= 0 {
		keep = 8
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &Auditor{dir: dir, name: name, maxBytes: maxMB << 20, keep: keep, verbose: verbose,
		sinks: ext.AuditSinks(), ch: make(chan AuditRecord, 4096), done: make(chan struct{})}
	if err := a.rotate(); err != nil {
		return nil, err
	}
	go a.loop()
	return a, nil
}

func (a *Auditor) rotate() error {
	if a.w != nil {
		a.w.Flush()
		a.f.Sync()
		a.f.Close()
	}
	path := filepath.Join(a.dir, fmt.Sprintf("audit-%s-%s.log", a.name, time.Now().UTC().Format("20060102T150405.000000")))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	a.f, a.w, a.size = f, bufio.NewWriterSize(f, 64<<10), 0
	a.prune()
	return nil
}

// prune removes this apiserver's oldest audit files beyond keep (names
// sort by their start time).
func (a *Auditor) prune() {
	files, _ := filepath.Glob(filepath.Join(a.dir, "audit-"+a.name+"-*.log"))
	sort.Strings(files)
	for len(files) > a.keep {
		os.Remove(files[0])
		files = files[1:]
	}
}

func (a *Auditor) loop() {
	defer close(a.done)
	flush := time.NewTicker(100 * time.Millisecond)
	defer flush.Stop()
	for {
		select {
		case r, ok := <-a.ch:
			if !ok {
				a.mu.Lock()
				a.w.Flush()
				a.f.Sync()
				a.f.Close()
				a.mu.Unlock()
				return
			}
			b, _ := json.Marshal(r)
			b = append(b, '\n')
			a.mu.Lock()
			if a.size+int64(len(b)) > a.maxBytes && a.size > 0 {
				if err := a.rotate(); err != nil {
					fmt.Fprintln(os.Stderr, "audit: rotate:", err)
				}
			}
			n, _ := a.w.Write(b)
			a.size += int64(n)
			a.mu.Unlock()
			for _, s := range a.sinks {
				s.Write(b)
			}
		case <-flush.C:
			a.mu.Lock()
			a.w.Flush()
			a.mu.Unlock()
		}
	}
}

// Flush writes buffered records to the file (tests, shutdown).
func (a *Auditor) Flush() {
	for len(a.ch) > 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond) // let the loop finish the record it dequeued
	a.mu.Lock()
	a.w.Flush()
	a.mu.Unlock()
}

// Close flushes and closes the log.
func (a *Auditor) Close() {
	a.once.Do(func() { close(a.ch); <-a.done })
}

// ---- interceptors ------------------------------------------------------------------------

type auditKey struct{}

type auditCtx struct {
	mu        sync.Mutex
	principal string
}

// noteActor records the authenticated principal of the current call.
func noteActor(ctx context.Context, principal string) {
	if ac, ok := ctx.Value(auditKey{}).(*auditCtx); ok {
		ac.mu.Lock()
		ac.principal = principal
		ac.mu.Unlock()
	}
}

func newRequestID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (a *Auditor) record(ctx context.Context, ac *auditCtx, full, rid string, req any, start time.Time, err error) {
	method := full[strings.LastIndexByte(full, '/')+1:]
	reason := ""
	if err != nil {
		reason = rpcutil.Reason(err)
	}
	// Failed authentication is always audited; other verbose calls only on request.
	if verboseMethods[method] && !a.verbose && reason != rpcutil.Unauthenticated {
		return
	}
	ac.mu.Lock()
	r := AuditRecord{
		Time: start.UTC().Format(time.RFC3339Nano), RequestID: rid, Principal: ac.principal, Method: method,
		Code: status.Code(err).String(), Reason: reason,
		LatencyMs: float64(time.Since(start).Microseconds()) / 1000,
	}
	ac.mu.Unlock()
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		r.Peer = p.Addr.String()
	}
	describe(&r, req)
	a.ch <- r
}

// describe copies the resource fields of a request into the record.
func describe(r *AuditRecord, req any) {
	switch q := req.(type) {
	case *pb.CreateSandboxRequest:
		r.Project, r.TaskID = q.Project, q.Spec.GetTaskId()
	case *pb.CreateSandboxesRequest:
		r.Project, r.TaskID, r.Count = q.Project, q.Spec.GetTaskId(), q.Count
	case *pb.ForkSandboxRequest:
		r.SandboxID, r.TaskID, r.Count = q.SandboxId, q.TaskId, q.Count
	case *pb.CreateSnapshotRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Image
	case *pb.PackDiffRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Image
	case *pb.SandboxRef:
		r.SandboxID = q.Id
	case *pb.SetTimeoutRequest:
		r.SandboxID, r.Target = q.SandboxId, fmt.Sprintf("timeout %ds", q.TimeoutS)
	case *pb.SandboxFilter:
		r.Project, r.TaskID = q.Project, q.TaskId
	case *pb.TaskActionRequest:
		r.Project, r.TaskID, r.Target = q.Project, q.TaskId, q.Action.String()
	case *pb.ExecRequest:
		sum := sha256.Sum256([]byte(q.Cmd))
		r.SandboxID, r.CmdLen, r.CmdSHA256 = q.SandboxId, len(q.Cmd), hex.EncodeToString(sum[:])
	case *pb.StartProcessRequest: // like exec: never the command line itself
		line := strings.Join(append([]string{q.Cmd}, q.Args...), " ")
		sum := sha256.Sum256([]byte(line))
		r.SandboxID, r.CmdLen, r.CmdSHA256 = q.SandboxId, len(line), hex.EncodeToString(sum[:])
	case *pb.ProcessRef:
		r.SandboxID, r.Target = q.SandboxId, processTarget(q.Pid, q.Tag)
	case *pb.ProcessInput:
		r.SandboxID, r.Target = q.SandboxId, processTarget(q.Pid, q.Tag)
	case *pb.ProcessSignal:
		r.SandboxID, r.Target = q.SandboxId, processTarget(q.Pid, q.Tag)+fmt.Sprintf(" signal %d", q.Signal)
	case *pb.ProcessResize:
		r.SandboxID, r.Target = q.SandboxId, processTarget(q.Pid, q.Tag)
	case *pb.PortData:
		r.SandboxID, r.Target = q.SandboxId, fmt.Sprintf("port %d", q.Port)
	case *pb.MoveRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Source+" -> "+q.Destination
	case *pb.OutputRequest:
		r.SandboxID = q.SandboxId
	case *pb.FileRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Path
	case *pb.WriteFileRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Path
	case *pb.HttpRequest:
		r.SandboxID, r.Target = q.SandboxId, q.Url
	case *pb.UpdateNetworkRequest:
		r.SandboxID = q.SandboxId
	case *pb.SessionRef:
		r.SandboxID, r.Target = q.SandboxId, q.Session
	case *pb.CreateProjectRequest:
		r.Project, r.Target = q.Parent, q.Parent+"/"+q.Name
	case *pb.CreatePrincipalRequest:
		r.Project, r.Target = q.Project, q.Id
	case *pb.GrantRequest:
		r.Project, r.Target = q.Project, q.Principal+":"+strings.Join(q.Perms, ",")
	case *pb.RevokeRequest:
		r.Project, r.Target = q.Project, q.Principal+":"+strings.Join(q.Perms, ",")
	case *pb.SetQuotaRequest:
		r.Project = q.Project
	case *pb.GetProjectRequest:
		r.Project = q.Project
	case *pb.UsageRequest:
		r.Project = q.Project
	case *pb.CreateTokenRequest:
		r.Target = q.Principal
	case *pb.ListTokensRequest:
		r.Target = q.Principal
	case *pb.RevokeTokenRequest:
		r.Target = q.Principal + ":" + q.TokenId
	case *pb.DeletePrincipalRequest:
		r.Target = q.Principal
	case *pb.DeleteProjectRequest:
		r.Project, r.Target = q.Project, q.Project
	}
}

func processTarget(pid uint32, tag string) string {
	if pid == 0 && tag != "" {
		return "tag " + tag
	}
	return fmt.Sprintf("pid %d", pid)
}

// ServerOptions returns interceptors that audit every call and tag it with a
// request id (returned to the client as the "x-opendsec-request-id" header).
func (a *Auditor) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			start, rid, ac := time.Now(), newRequestID(), &auditCtx{}
			grpc.SetHeader(ctx, metadata.Pairs("x-opendsec-request-id", rid))
			resp, err := h(context.WithValue(ctx, auditKey{}, ac), req)
			a.record(ctx, ac, info.FullMethod, rid, req, start, err)
			return resp, err
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			start, rid, ac := time.Now(), newRequestID(), &auditCtx{}
			ss.SetHeader(metadata.Pairs("x-opendsec-request-id", rid))
			ws := &auditStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), auditKey{}, ac)}
			err := h(srv, ws)
			a.record(ss.Context(), ac, info.FullMethod, rid, ws.first, start, err)
			return err
		}),
	}
}

// auditStream captures the first request message of a server stream.
type auditStream struct {
	grpc.ServerStream
	ctx   context.Context
	first any
}

func (s *auditStream) Context() context.Context { return s.ctx }

func (s *auditStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil && s.first == nil {
		s.first = m
	}
	return err
}
