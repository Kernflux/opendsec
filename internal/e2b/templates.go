package e2b

// E2B template builds (spec §43.4): E2B's Template SDK (Template().
// from_image(...).pip_install(...).copy(...), Template.build) against the
// gateway. A build becomes an image in the caller's project,
// "<project>/<name>:default", which Sandbox.create(name) then starts.
//
// The gateway keeps no state, so a build lives in sandboxes of the
// caller's: a small staging sandbox (labeled e2b.build=<name>) made when
// the build is requested holds the files the SDK uploads for COPY steps,
// and the build's status and log, which any gateway reads. When the SDK
// starts the build, the gateway that receives it runs the steps in a
// builder sandbox of the base image, and saves the result: the files
// (pack_diff, on a container), or with a start command its memory too (a
// snapshot, on a microVM). If that gateway goes away mid-build, the status
// turns to error once its heartbeat is a minute old.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/pkg/client"
)

const (
	labelBuild    = "e2b.build" // the template name, on a build's staging sandbox
	labelBuildCPU = "e2b.build.cpu"
	labelBuildMem = "e2b.build.mem"
	buildDir      = "/tmp/e2b-build"
	buildFiles    = buildDir + "/files"
	buildStatus   = buildDir + "/status.json"
	buildLog      = buildDir + "/log.jsonl"
	// maxUpload bounds one COPY step's files (compressed).
	maxUpload = 2 << 30
	// buildTimeout bounds a whole build.
	buildTimeout = time.Hour
	chunk        = 32 << 20 // file transfer pieces, under the message limit
)

var (
	templateNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	filesHashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// buildState is the status file of a build.
type buildState struct {
	Status    string       `json:"status"` // waiting | building | ready | error
	Reason    *buildReason `json:"reason,omitempty"`
	Heartbeat float64      `json:"heartbeat,omitempty"`
	Image     string       `json:"image,omitempty"`
}

type buildReason struct {
	Message string `json:"message"`
	Step    string `json:"step,omitempty"`
}

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Step      string `json:"step,omitempty"`
}

// templateImage is the image template name builds into, in project.
func templateImage(project, name string) string { return project + "/" + name + ":default" }

// requestBuild serves POST /v3/templates: a staging sandbox for the build.
func (g *Gateway) requestBuild(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string   `json:"name"`
		Alias    string   `json:"alias"`
		Tags     []string `json:"tags"`
		CPUCount int      `json:"cpuCount"`
		MemoryMB int64    `json:"memoryMB"`
	}
	if !decode(w, r, &req) {
		return
	}
	name := cmpOr(req.Name, req.Alias)
	if !templateNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "template name "+strconv.Quote(name)+": use lowercase letters, digits, '.', '_' and '-'")
		return
	}
	if _, ok := g.cfg.Templates[name]; ok {
		writeErr(w, http.StatusBadRequest, "template "+name+" is one of the cluster's: choose another name")
		return
	}
	stage, ok := g.cfg.Templates["base"]
	if !ok {
		stage = g.cfg.DefaultTemplate
	}
	if stage.Image == "" {
		writeErr(w, http.StatusServiceUnavailable, "template builds need a \"base\" template in the gateway's config")
		return
	}
	cpu, mem := req.CPUCount, req.MemoryMB
	if cpu <= 0 {
		cpu = 2
	}
	if mem <= 0 {
		mem = 1024
	}
	spec := &pb.SandboxSpec{Backend: "container", Image: stage.Image,
		Resources: &pb.Resources{CpuCores: 0.25, MemoryMb: 128},
		Labels:    map[string]string{labelBuild: name, labelBuildCPU: strconv.Itoa(cpu), labelBuildMem: strconv.FormatInt(mem, 10)},
		// It holds the build's files and status: kept while it is read,
		// gone some time after.
		TtlMaxS: int64(2 * buildTimeout / time.Second), TtlRunningStopS: 1800}
	sb, err := g.api.CreateSandbox(ctx, &pb.CreateSandboxRequest{Project: g.project(ctx, r), Spec: spec})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	b := &builder{g: g, ctx: ctx, stage: sb.Id}
	if err := b.mkdirs(); err == nil {
		err = b.setStatus(buildState{Status: "waiting"})
	}
	if err != nil {
		g.api.StopSandbox(ctx, &pb.SandboxRef{Id: sb.Id})
		writeAPIErr(w, err)
		return
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"templateID": name, "buildID": toE2B(sb.Id), "public": false,
		"names": []string{name}, "aliases": []string{name}, "tags": tags})
}

// stageOf finds build bid's staging sandbox (an E2B id), checking it is
// template tid's; tid alone: its newest running one.
func (g *Gateway) stageOf(ctx context.Context, r *http.Request, tid, bid string) (string, error) {
	if bid != "" {
		id, err := fromE2B(bid)
		if err != nil {
			return "", err
		}
		sb, err := g.api.GetSandbox(ctx, &pb.SandboxRef{Id: id})
		if err != nil {
			return "", err
		}
		if sb.GetSpec().GetLabels()[labelBuild] != tid {
			return "", fmt.Errorf("build %s is not template %s's", bid, tid)
		}
		return id, nil
	}
	l, err := g.api.ListSandboxes(ctx, &pb.SandboxFilter{Project: g.project(ctx, r)})
	if err != nil {
		return "", err
	}
	var best *pb.Sandbox
	for _, sb := range l.Sandboxes {
		if sb.GetSpec().GetLabels()[labelBuild] == tid && sb.State == pb.SandboxState_RUNNING &&
			(best == nil || sb.CreatedAt > best.CreatedAt) {
			best = sb
		}
	}
	if best == nil {
		return "", fmt.Errorf("template %s has no build waiting for files", tid)
	}
	return best.Id, nil
}

// fileLink serves GET /templates/{tid}/files/{hash}: whether a COPY step's
// files are there, else where to upload them (to this gateway).
func (g *Gateway) fileLink(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	tid, hash := r.PathValue("tid"), r.PathValue("hash")
	if !filesHashRe.MatchString(hash) {
		writeErr(w, http.StatusBadRequest, "bad files hash")
		return
	}
	stage, err := g.stageOf(ctx, r, tid, "")
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if _, err := g.api.Stat(ctx, &pb.FileRequest{SandboxId: stage, Path: buildFiles + "/" + hash}); err == nil {
		writeJSON(w, http.StatusCreated, map[string]any{"present": true})
		return
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	// The link carries the caller's key: SDKs before 2.5x upload without
	// the headers given (newer ones send them too). The key goes back only
	// to its owner; the gateway logs no URLs.
	u := scheme + "://" + r.Host + "/templates/" + tid + "/builds/" + toE2B(stage) + "/files/" + hash +
		"?key=" + url.QueryEscape(apiKey(r))
	writeJSON(w, http.StatusCreated, map[string]any{"present": false, "url": u,
		"headers": map[string]string{"X-API-KEY": r.Header.Get("X-API-KEY")}})
}

// uploadFiles serves PUT /templates/{tid}/builds/{bid}/files/{hash}: a COPY
// step's files (a tar, gzipped or not), into the staging sandbox.
func (g *Gateway) uploadFiles(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	tid, hash := r.PathValue("tid"), r.PathValue("hash")
	if !filesHashRe.MatchString(hash) {
		writeErr(w, http.StatusBadRequest, "bad files hash")
		return
	}
	stage, err := g.stageOf(ctx, r, tid, r.PathValue("bid"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	tmp := buildFiles + "/." + hash + ".part"
	body := io.LimitReader(r.Body, maxUpload+1)
	buf := make([]byte, chunk)
	var total int64
	for first := true; ; first = false {
		n, rerr := io.ReadFull(body, buf)
		if n > 0 {
			total += int64(n)
			if total > maxUpload {
				writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("files over %d MB", maxUpload>>20))
				return
			}
			if _, err := g.api.WriteFile(ctx, &pb.WriteFileRequest{SandboxId: stage, Path: tmp, Data: buf[:n], Append: !first}); err != nil {
				writeAPIErr(w, err)
				return
			}
		} else if first {
			if _, err := g.api.WriteFile(ctx, &pb.WriteFileRequest{SandboxId: stage, Path: tmp}); err != nil {
				writeAPIErr(w, err)
				return
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			writeErr(w, http.StatusBadRequest, "reading the upload: "+rerr.Error())
			return
		}
	}
	if _, err := g.api.Move(ctx, &pb.MoveRequest{SandboxId: stage, Source: tmp, Destination: buildFiles + "/" + hash}); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// startBuild serves POST /v2/templates/{tid}/builds/{bid}: runs the build
// in the background, on this gateway.
func (g *Gateway) startBuild(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req buildSpec
	if !decode(w, r, &req) {
		return
	}
	tid := r.PathValue("tid")
	stage, err := g.stageOf(ctx, r, tid, r.PathValue("bid"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if req.FromImage == "" && req.FromTemplate == "" {
		writeErr(w, http.StatusBadRequest, "a build needs fromImage or fromTemplate")
		return
	}
	if reg := req.FromImageRegistry; reg != nil && reg.Type != "registry" {
		writeErr(w, http.StatusBadRequest, "fromImageRegistry type "+strconv.Quote(reg.Type)+" is not supported: use username and password")
		return
	}
	for _, st := range req.Steps {
		switch st.Type {
		case "RUN", "COPY", "ENV", "WORKDIR", "USER":
		default:
			writeErr(w, http.StatusBadRequest, "step type "+strconv.Quote(st.Type)+" is not supported")
			return
		}
	}
	sb, err := g.api.GetSandbox(ctx, &pb.SandboxRef{Id: stage})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	labels := sb.GetSpec().GetLabels()
	cpu, _ := strconv.ParseFloat(labels[labelBuildCPU], 64)
	mem, _ := strconv.ParseInt(labels[labelBuildMem], 10, 64)
	project := g.project(ctx, r)
	// The build outlives the request: the caller's token, on a context of
	// its own.
	bctx, cancel := context.WithTimeout(forwarded(client.WithToken(context.Background(), apiKey(r)), r), buildTimeout)
	b := &builder{g: g, ctx: bctx, stage: stage, name: tid, project: project, spec: req, cpu: cpu, mem: mem}
	if err := b.setStatus(buildState{Status: "building", Heartbeat: now()}); err != nil {
		cancel()
		writeAPIErr(w, err)
		return
	}
	go func() {
		defer cancel()
		b.run()
	}()
	w.WriteHeader(http.StatusAccepted)
}

// buildStatus serves GET /templates/{tid}/builds/{bid}/status.
func (g *Gateway) buildStatus(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	tid, bid := r.PathValue("tid"), r.PathValue("bid")
	stage, err := g.stageOf(ctx, r, tid, bid)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	b := &builder{g: g, ctx: ctx, stage: stage}
	st, err := b.status()
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	if st.Status == "building" && now()-st.Heartbeat > 60 {
		st.Status, st.Reason = "error", &buildReason{Message: "the build stopped: its gateway went away; build again"}
	}
	entries, err := b.logs()
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("logsOffset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	off = min(max(off, 0), len(entries))
	page := entries[off:min(off+limit, len(entries))]
	lines := make([]string, len(page))
	for i, e := range page {
		lines[i] = e.Message
	}
	resp := map[string]any{"templateID": tid, "buildID": bid, "status": st.Status, "logEntries": page, "logs": lines}
	if st.Reason != nil {
		reason := map[string]any{"message": st.Reason.Message}
		if st.Reason.Step != "" {
			reason["step"] = st.Reason.Step
		}
		resp["reason"] = reason
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- the build ------------------------------------------------------------------------

type buildSpec struct {
	FromImage         string `json:"fromImage"`
	FromTemplate      string `json:"fromTemplate"`
	FromImageRegistry *struct {
		Type     string `json:"type"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"fromImageRegistry"`
	Steps []struct {
		Type      string   `json:"type"`
		Args      []string `json:"args"`
		FilesHash string   `json:"filesHash"`
	} `json:"steps"`
	StartCmd string `json:"startCmd"`
	ReadyCmd string `json:"readyCmd"`
}

type builder struct {
	g       *Gateway
	ctx     context.Context
	stage   string // staging sandbox
	name    string
	project string
	spec    buildSpec
	cpu     float64
	mem     int64
	box     string // builder sandbox
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (b *builder) mkdirs() error {
	_, err := b.g.api.MakeDir(b.ctx, &pb.FileRequest{SandboxId: b.stage, Path: buildFiles})
	if err == nil {
		_, err = b.g.api.WriteFile(b.ctx, &pb.WriteFileRequest{SandboxId: b.stage, Path: buildLog})
	}
	return err
}

func (b *builder) setStatus(st buildState) error {
	data, _ := json.Marshal(st)
	_, err := b.g.api.WriteFile(b.ctx, &pb.WriteFileRequest{SandboxId: b.stage, Path: buildStatus, Data: data})
	return err
}

func (b *builder) status() (buildState, error) {
	var st buildState
	f, err := b.g.api.ReadFile(b.ctx, &pb.FileRequest{SandboxId: b.stage, Path: buildStatus})
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(f.Data, &st)
}

func (b *builder) logs() ([]logEntry, error) {
	f, err := b.g.api.ReadFile(b.ctx, &pb.FileRequest{SandboxId: b.stage, Path: buildLog})
	if err != nil {
		return nil, err
	}
	var out []logEntry
	for _, l := range bytes.Split(f.Data, []byte("\n")) {
		var e logEntry
		if len(l) > 0 && json.Unmarshal(l, &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

func (b *builder) log(level, step, msg string) {
	var buf bytes.Buffer
	for _, line := range strings.Split(strings.TrimRight(msg, "\n"), "\n") {
		e, _ := json.Marshal(logEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: level, Message: line, Step: step})
		buf.Write(e)
		buf.WriteByte('\n')
	}
	if _, err := b.g.api.WriteFile(b.ctx, &pb.WriteFileRequest{SandboxId: b.stage, Path: buildLog, Data: buf.Bytes(), Append: true}); err != nil {
		b.g.log.Warn("template build: writing its log failed", "template", b.name, "err", err)
	}
}

// run builds, then records the outcome; it never returns an error.
func (b *builder) run() {
	stop := make(chan struct{})
	go func() { // heartbeat: tells a running build from one whose gateway went away
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				b.setStatus(buildState{Status: "building", Heartbeat: now()})
			}
		}
	}()
	img, step, err := b.build()
	close(stop)
	if b.box != "" {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(b.ctx), 30*time.Second)
		b.g.api.StopSandbox(ctx, &pb.SandboxRef{Id: b.box})
		cancel()
	}
	if err != nil {
		msg := err.Error()
		if s, ok := statusMessage(err); ok {
			msg = s
		}
		b.log("error", step, msg)
		b.setStatus(buildState{Status: "error", Reason: &buildReason{Message: msg, Step: step}})
		b.g.log.Info("template build failed", "template", b.name, "project", b.project, "step", step, "err", msg)
		return
	}
	b.log("info", "", "Template built: "+img)
	b.setStatus(buildState{Status: "ready", Image: img})
	b.g.log.Info("template built", "template", b.name, "image", img)
	// The staging sandbox is read a little longer (the last logs), then goes.
	b.g.api.SetSandboxTimeout(b.ctx, &pb.SetTimeoutRequest{SandboxId: b.stage, TimeoutS: 600})
}

func statusMessage(err error) (string, bool) {
	if st, ok := status.FromError(err); ok {
		return st.Message(), true
	}
	return "", false
}

// build runs the steps; it returns the image, or the failing step's index
// (as E2B counts: 0 is the base) and the error.
func (b *builder) build() (string, string, error) {
	api, ctx := b.g.api, b.ctx
	target := templateImage(b.project, b.name)
	base := ""
	switch {
	case b.spec.FromTemplate != "":
		t, ok := b.g.template(b.spec.FromTemplate)
		if !ok {
			if _, err := api.GetImage(ctx, &pb.ImageRef{Name: templateImage(b.project, b.spec.FromTemplate)}); err != nil {
				return "", "0", fmt.Errorf("template %s not found", b.spec.FromTemplate)
			}
			t.Image = templateImage(b.project, b.spec.FromTemplate)
		}
		base = t.Image
	default:
		b.log("info", "0", "Pulling "+b.spec.FromImage)
		req := &pb.ImportImageRequest{Image: target, Ref: b.spec.FromImage, Overwrite: true}
		if reg := b.spec.FromImageRegistry; reg != nil {
			req.Username, req.Password = reg.Username, reg.Password
		}
		if _, err := api.ImportImage(ctx, req); err != nil {
			return "", "0", err
		}
		base = target
	}
	info, err := api.GetImage(ctx, &pb.ImageRef{Name: base})
	if err != nil {
		return "", "0", err
	}
	// Files only: a container, saved with pack_diff. A start command, or a
	// base that is a memory snapshot: a microVM, saved with its memory.
	memory := b.spec.StartCmd != "" || info.Memory
	backend, cpu, mem := "container", b.cpu, b.mem
	if memory {
		backend = "microvm"
		if info.Memory {
			cpu, mem = 0, 0 // its own shape
		}
	}
	b.log("info", "0", fmt.Sprintf("Starting a %s sandbox from %s", backend, base))
	sb, err := api.CreateSandbox(ctx, &pb.CreateSandboxRequest{Project: b.project, Spec: &pb.SandboxSpec{Backend: backend, Image: base,
		Resources: &pb.Resources{CpuCores: cpu, MemoryMb: mem}, NetworkRules: map[string]bool{"*": true},
		TtlMaxS: int64(buildTimeout / time.Second), TtlRunningStopS: int64(buildTimeout / time.Second),
		Labels: map[string]string{labelBuild + ".builder": b.name}}})
	if err != nil {
		return "", "0", err
	}
	b.box = sb.Id
	env := map[string]string{}
	cwd, user := info.Workdir, cmpOr(info.User, "root")
	for i, st := range b.spec.Steps {
		step := strconv.Itoa(i + 1)
		b.log("info", step, fmt.Sprintf("[%d/%d] %s %s", i+1, len(b.spec.Steps), st.Type, strings.Join(redactArgs(st.Type, st.Args), " ")))
		switch st.Type {
		case "ENV":
			for j := 0; j+1 < len(st.Args); j += 2 {
				env[st.Args[j]] = st.Args[j+1]
			}
		case "WORKDIR":
			if len(st.Args) > 0 {
				cwd = st.Args[0]
				if err := b.sh(step, "root", "mkdir -p "+shq(cwd), nil, ""); err != nil {
					return "", step, err
				}
			}
		case "USER":
			if len(st.Args) > 0 {
				user = st.Args[0]
			}
		case "RUN":
			if len(st.Args) == 0 {
				continue
			}
			u := user
			if len(st.Args) > 1 && st.Args[1] != "" {
				u = st.Args[1]
			}
			if err := b.sh(step, u, st.Args[0], env, cwd); err != nil {
				return "", step, err
			}
		case "COPY":
			if err := b.copyStep(step, st.Args, st.FilesHash, cwd); err != nil {
				return "", step, err
			}
		}
	}
	final := strconv.Itoa(len(b.spec.Steps) + 1)
	if memory {
		if b.spec.StartCmd != "" {
			b.log("info", final, "Starting: "+b.spec.StartCmd)
			if _, err := api.Exec(ctx, &pb.ExecRequest{SandboxId: b.box, Session: "start-" + user, User: userArg(user),
				Cmd: b.spec.StartCmd, Env: env, Cwd: cwd, Background: true, RequestId: ids.NewLease()}); err != nil {
				return "", final, err
			}
			if err := b.waitReady(final, user, env, cwd); err != nil {
				return "", final, err
			}
		}
		b.log("info", final, "Saving the sandbox with its memory")
		if _, err := api.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{SandboxId: b.box, Image: target, Memory: true, Overwrite: true}); err != nil {
			return "", final, err
		}
		return target, "", nil
	}
	b.log("info", final, "Saving the sandbox's files")
	if _, err := api.PackDiff(ctx, &pb.PackDiffRequest{SandboxId: b.box, Image: target, Overwrite: true}); err != nil {
		return "", final, err
	}
	if len(env) > 0 || cwd != info.Workdir || user != cmpOr(info.User, "root") {
		if _, err := api.ComposeImage(ctx, &pb.ComposeImageRequest{Name: target, Parts: []string{target}, Env: env,
			Workdir: cwd, User: user, Overwrite: true}); err != nil {
			return "", final, err
		}
	}
	return target, "", nil
}

// redactArgs: ENV values may be secrets; the log shows their names.
func redactArgs(typ string, args []string) []string {
	if typ != "ENV" {
		return args
	}
	var out []string
	for j := 0; j < len(args); j += 2 {
		out = append(out, args[j]+"=…")
	}
	return out
}

func userArg(u string) string {
	if u == "root" {
		return ""
	}
	return u
}

// sh runs cmd in the builder sandbox as user, logging its output.
func (b *builder) sh(step, user, cmd string, env map[string]string, cwd string) error {
	res, err := b.g.api.Exec(b.ctx, &pb.ExecRequest{SandboxId: b.box, Session: "build-" + user, User: userArg(user),
		Cmd: cmd, Env: env, Cwd: cwd, TimeoutS: buildTimeout.Seconds(), RequestId: ids.NewLease()})
	if err != nil {
		return err
	}
	if out := strings.TrimSpace(string(res.Stdout)); out != "" {
		b.log("info", step, tail(out, 64<<10))
	}
	if out := strings.TrimSpace(string(res.Stderr)); out != "" {
		b.log("info", step, tail(out, 64<<10))
	}
	if res.TimedOut {
		return fmt.Errorf("timed out")
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("exited with %d", res.ExitCode)
	}
	return nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// copyStep moves an uploaded tar from the staging sandbox into the builder
// and copies its src (globs allowed) to dest as Docker's COPY does: a
// directory's contents, files into a dest ending in "/".
func (b *builder) copyStep(step string, args []string, hash, cwd string) error {
	if len(args) < 2 || !filesHashRe.MatchString(hash) {
		return fmt.Errorf("COPY needs a source, a destination and its files")
	}
	src, dest := args[0], args[1]
	owner, mode := "", ""
	if len(args) > 2 {
		owner = args[2]
	}
	if len(args) > 3 {
		mode = args[3]
	}
	if !path.IsAbs(dest) {
		dest = path.Join(cmpOr(cwd, "/"), dest) + map[bool]string{true: "/"}[strings.HasSuffix(dest, "/")]
	}
	tarPath := "/tmp/.e2b-files/" + hash + ".tar"
	if err := b.transfer(buildFiles+"/"+hash, tarPath); err != nil {
		return fmt.Errorf("files of %s: %w", src, err)
	}
	script := `set -e
d=/tmp/.e2b-files/` + hash + `
mkdir -p "$d"
tar -xf ` + shq(tarPath) + ` -C "$d"
cd "$d"
dest=` + shq(dest) + `
set -- ` + globArg(src) + `
[ -e "$1" ] || { echo "COPY: nothing matches $1" >&2; exit 1; }
case "$dest" in */) mkdir -p "$dest" ;; *) if [ $# -gt 1 ]; then mkdir -p "$dest"; dest="$dest/"; else mkdir -p "$(dirname "$dest")"; fi ;; esac
targets=""
for s in "$@"; do
	if [ -d "$s" ]; then
		mkdir -p "$dest"
		cp -a "$s"/. "$dest"
		targets="$targets $dest"
	else
		case "$dest" in */) cp -a "$s" "$dest"; targets="$targets $dest$(basename "$s")" ;; *) cp -a "$s" "$dest"; targets="$targets $dest" ;; esac
	fi
done
`
	if owner != "" {
		script += "chown -R " + shq(owner) + " $targets\n"
	}
	if mode != "" {
		script += "chmod -R " + shq(mode) + " $targets\n"
	}
	script += `rm -rf "$d" ` + shq(tarPath) + "\n"
	return b.sh(step, "root", script, nil, "")
}

// globArg quotes src for the shell but keeps its glob characters.
func globArg(src string) string {
	src = strings.TrimPrefix(path.Clean("/"+src), "/")
	if src == "" {
		src = "."
	}
	var out strings.Builder
	for _, r := range src {
		switch r {
		case '*', '?', '[', ']':
			out.WriteRune(r)
		default:
			if r == '/' || r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				out.WriteRune(r)
			} else {
				out.WriteString(`\` + string(r))
			}
		}
	}
	return out.String()
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// transfer copies a file from the staging sandbox into the builder.
func (b *builder) transfer(from, to string) error {
	api, ctx := b.g.api, b.ctx
	if _, err := api.MakeDir(ctx, &pb.FileRequest{SandboxId: b.box, Path: path.Dir(to)}); err != nil {
		return err
	}
	for off := int64(0); ; off += chunk {
		f, err := api.ReadFile(ctx, &pb.FileRequest{SandboxId: b.stage, Path: from, Offset: off, Length: chunk})
		if err != nil {
			return err
		}
		if _, err := api.WriteFile(ctx, &pb.WriteFileRequest{SandboxId: b.box, Path: to, Data: f.Data, Append: off > 0}); err != nil {
			return err
		}
		if int64(len(f.Data)) < chunk {
			return nil
		}
	}
}

// waitReady runs the ready command until it succeeds (E2B's default: a
// few seconds' wait).
func (b *builder) waitReady(step, user string, env map[string]string, cwd string) error {
	if b.spec.ReadyCmd == "" {
		time.Sleep(3 * time.Second)
		return nil
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		res, err := b.g.api.Exec(b.ctx, &pb.ExecRequest{SandboxId: b.box, Session: "ready-" + user, User: userArg(user),
			Cmd: b.spec.ReadyCmd, Env: env, Cwd: cwd, TimeoutS: 30, RequestId: ids.NewLease()})
		if err == nil && res.ExitCode == 0 && !res.TimedOut {
			return nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("ready command %q never succeeded", b.spec.ReadyCmd)
			}
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// builtTemplate resolves a template name without "/" to an image the
// caller built (templateImage), if there is one.
func (g *Gateway) builtTemplate(ctx context.Context, r *http.Request, id string) (string, bool) {
	if strings.Contains(id, "/") || !templateNameRe.MatchString(id) {
		return "", false
	}
	name := templateImage(g.project(ctx, r), id)
	if _, err := g.api.GetImage(ctx, &pb.ImageRef{Name: name}); err != nil {
		return "", false
	}
	return name, true
}
