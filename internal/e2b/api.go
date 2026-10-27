package e2b

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/pkg/client"
)

// The control API: the routes E2B's SDKs use (spec §37).

func (g *Gateway) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Health check successful"})
	})
	auth := func(h func(context.Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			key := apiKey(r)
			if key == "" {
				writeErr(w, http.StatusUnauthorized, "missing API key (X-API-KEY): an OpenDsec token")
				return
			}
			h(client.WithToken(r.Context(), key), w, r)
		}
	}
	mux.HandleFunc("POST /sandboxes", auth(g.create))
	mux.HandleFunc("POST /v2/sandboxes", auth(g.create))
	mux.HandleFunc("GET /sandboxes", auth(g.list))
	mux.HandleFunc("GET /v2/sandboxes", auth(g.list))
	mux.HandleFunc("GET /sandboxes/{id}", auth(g.get))
	mux.HandleFunc("DELETE /sandboxes/{id}", auth(g.kill))
	mux.HandleFunc("POST /sandboxes/{id}/timeout", auth(g.setTimeout))
	mux.HandleFunc("POST /sandboxes/{id}/pause", auth(g.pause))
	mux.HandleFunc("POST /sandboxes/{id}/resume", auth(g.connect))
	mux.HandleFunc("POST /sandboxes/{id}/connect", auth(g.connect))
	mux.HandleFunc("POST /v2/sandboxes/{id}/connect", auth(g.connect))
	mux.HandleFunc("PUT /sandboxes/{id}/network", auth(g.updateNetwork))
	mux.HandleFunc("POST /sandboxes/{id}/refreshes", auth(g.refresh))
	mux.HandleFunc("POST /sandboxes/{id}/fork", auth(g.fork))
	mux.HandleFunc("POST /sandboxes/{id}/snapshots", auth(g.createSnapshot))
	mux.HandleFunc("GET /snapshots", auth(g.listSnapshots))
	mux.HandleFunc("DELETE /templates/{id...}", auth(g.deleteSnapshot))
	mux.HandleFunc("GET /sandboxes/{id}/metrics", auth(func(_ context.Context, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []any{})
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not served by the OpenDsec E2B gateway: "+r.Method+" "+r.URL.Path)
	})
	return mux
}

// sandboxResp is E2B's Sandbox.
type sandboxResp struct {
	TemplateID      string `json:"templateID"`
	SandboxID       string `json:"sandboxID"`
	ClientID        string `json:"clientID"`
	EnvdVersion     string `json:"envdVersion"`
	EnvdAccessToken string `json:"envdAccessToken,omitempty"`
	// TrafficAccessToken makes the SDKs send the token to the sandbox's
	// other ports (E2B-Traffic-Access-Token), which the gateway requires.
	TrafficAccessToken *string `json:"trafficAccessToken"`
	Domain             *string `json:"domain"`
}

// sandboxDetail is E2B's SandboxDetail and ListedSandbox.
type sandboxDetail struct {
	TemplateID      string            `json:"templateID"`
	SandboxID       string            `json:"sandboxID"`
	ClientID        string            `json:"clientID"`
	StartedAt       string            `json:"startedAt"`
	EndAt           string            `json:"endAt"`
	CPUCount        int               `json:"cpuCount"`
	MemoryMB        int64             `json:"memoryMB"`
	DiskSizeMB      int64             `json:"diskSizeMB"`
	Metadata        map[string]string `json:"metadata"`
	State           string            `json:"state"`
	EnvdVersion     string            `json:"envdVersion"`
	EnvdAccessToken string            `json:"envdAccessToken,omitempty"`
	Domain          *string           `json:"domain"`
	// Detail only (omitted in lists).
	AllowInternetAccess *bool          `json:"allowInternetAccess,omitempty"`
	Network             *networkConfig `json:"network,omitempty"`
	Lifecycle           *lifecycle     `json:"lifecycle,omitempty"`
}

// lifecycle is E2B's SandboxLifecycle.
type lifecycle struct {
	AutoResume bool   `json:"autoResume"`
	OnTimeout  string `json:"onTimeout"`
}

const clientID = "opendsec"

func (g *Gateway) domain() *string {
	if g.cfg.Domain == "" {
		return nil
	}
	d := g.cfg.Domain
	return &d
}

func (g *Gateway) sandboxResp(sb *pb.Sandbox, key string) sandboxResp {
	var traffic *string
	if key != "" {
		traffic = &key
	}
	return sandboxResp{TemplateID: sb.GetSpec().GetLabels()[labelTemplate], SandboxID: toE2B(sb.Id), ClientID: clientID,
		EnvdVersion: EnvdVersion, EnvdAccessToken: key, TrafficAccessToken: traffic, Domain: g.domain()}
}

// full is detail with what E2B's sandbox info adds: the network and the
// lifecycle.
func (g *Gateway) full(sb *pb.Sandbox, key string) sandboxDetail {
	d := g.detail(sb, key)
	labels := sb.GetSpec().GetLabels()
	if v, ok := labels[labelInternet]; ok {
		b := v == "true"
		d.AllowInternetAccess = &b
	}
	d.Network = networkOf(sb.GetSpec().GetNetworkRules())
	// Any call resumes a paused sandbox: auto-resume is always on.
	d.Lifecycle = &lifecycle{AutoResume: true, OnTimeout: "kill"}
	if sb.GetSpec().GetTtlPausedS() > 0 {
		d.Lifecycle.OnTimeout = "pause"
	}
	return d
}

// endsAfter reports whether sb's lifetime (ttl_max_s; 0 = none) lasts
// beyond t.
func endsAfter(sb *pb.Sandbox, t time.Time) bool {
	ttl := sb.GetSpec().GetTtlMaxS()
	return ttl <= 0 || time.Unix(0, int64(sb.CreatedAt*1e9)).Add(time.Duration(ttl)*time.Second).After(t)
}

func (g *Gateway) detail(sb *pb.Sandbox, key string) sandboxDetail {
	spec := sb.GetSpec()
	started := time.Unix(0, int64(sb.CreatedAt*1e9)).UTC()
	end := started
	if spec.GetTtlMaxS() > 0 {
		end = started.Add(time.Duration(spec.GetTtlMaxS()) * time.Second)
	}
	state := "running"
	if sb.State == pb.SandboxState_PAUSED {
		state = "paused"
	}
	return sandboxDetail{TemplateID: spec.GetLabels()[labelTemplate], SandboxID: toE2B(sb.Id), ClientID: clientID,
		StartedAt: started.Format(time.RFC3339Nano), EndAt: end.Format(time.RFC3339Nano),
		CPUCount: int(spec.GetResources().GetCpuCores() + 0.999), MemoryMB: spec.GetResources().GetMemoryMb(),
		DiskSizeMB: spec.GetResources().GetDiskMb(), Metadata: metadataOf(sb), State: state,
		EnvdVersion: EnvdVersion, EnvdAccessToken: key, Domain: g.domain()}
}

// template resolves an E2B template id.
func (g *Gateway) template(id string) (config.E2BTemplate, bool) {
	if t, ok := g.cfg.Templates[id]; ok {
		return withDefaults(t, g.cfg.DefaultTemplate), true
	}
	if strings.Contains(id, "/") { // an OpenDsec image name
		t := g.cfg.DefaultTemplate
		t.Image = id
		return withDefaults(t, config.E2BTemplate{}), true
	}
	return config.E2BTemplate{}, false
}

func (g *Gateway) timeout(s int64) int64 {
	if g.cfg.MaxTimeout > 0 && s > g.cfg.MaxTimeout {
		return g.cfg.MaxTimeout
	}
	return s
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err == nil && len(b) > 0 {
		err = json.Unmarshal(b, v)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return false
	}
	return true
}

func (g *Gateway) create(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID      string            `json:"templateID"`
		Timeout         *int64            `json:"timeout"`
		AutoPause       bool              `json:"autoPause"`
		AutoPauseMemory *bool             `json:"autoPauseMemory"`
		Metadata        map[string]string `json:"metadata"`
		EnvVars         map[string]string `json:"envVars"`
		Internet        *bool             `json:"allow_internet_access"`
		Network         *networkConfig    `json:"network"`
		Mcp             json.RawMessage   `json:"mcp"`
		VolumeMounts    json.RawMessage   `json:"volumeMounts"`
	}
	if !decode(w, r, &req) {
		return
	}
	t, ok := g.template(req.TemplateID)
	if !ok {
		writeErr(w, http.StatusNotFound, "template '"+req.TemplateID+"' not found")
		return
	}
	if _, configured := g.cfg.Templates[req.TemplateID]; !configured {
		// Sandbox.create(snapshot_id): a memory snapshot restores into a VM
		// of its own shape, which the apiserver fills in when left unset.
		if img, err := g.api.GetImage(ctx, &pb.ImageRef{Name: req.TemplateID}); err == nil && img.Memory {
			t.Backend, t.CPU, t.MemoryMB, t.DiskMB = "microvm", 0, 0, 0
		}
	}
	if req.AutoPauseMemory != nil && !*req.AutoPauseMemory {
		writeErr(w, http.StatusBadRequest, "filesystem-only pauses are not supported by the OpenDsec E2B gateway: pauses keep memory")
		return
	}
	if unset(req.Mcp) || unset(req.VolumeMounts) {
		writeErr(w, http.StatusBadRequest, "mcp and volumeMounts are not supported by the OpenDsec E2B gateway")
		return
	}
	rules, err := networkRules(req.Internet, req.Network)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	timeout := int64(15) // E2B's default
	if req.Timeout != nil {
		timeout = *req.Timeout
	}
	timeout = g.timeout(timeout)
	labels := map[string]string{labelTemplate: req.TemplateID}
	for k, v := range req.Metadata {
		labels[labelMeta+k] = v
	}
	if len(req.EnvVars) > 0 {
		b, _ := json.Marshal(req.EnvVars)
		labels[labelEnvs] = string(b)
	}
	if req.Internet != nil {
		labels[labelInternet] = strconv.FormatBool(*req.Internet)
	}
	spec := &pb.SandboxSpec{Backend: t.Backend, Image: t.Image, Labels: labels, NetworkRules: rules,
		Resources: &pb.Resources{CpuCores: t.CPU, MemoryMb: t.MemoryMB, DiskMb: t.DiskMB},
		// E2B's timeout is a deadline, whether the sandbox is used or not.
		TtlMaxS: timeout, TtlRunningStopS: timeout}
	if req.AutoPause {
		spec.TtlPausedS = pausedTimeout
	}
	sb, err := g.api.CreateSandbox(ctx, &pb.CreateSandboxRequest{Project: g.project(r), Spec: spec})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	if err := g.start(ctx, sb.Id, t, req.EnvVars); err != nil {
		g.api.StopSandbox(context.WithoutCancel(ctx), &pb.SandboxRef{Id: sb.Id})
		writeErr(w, http.StatusInternalServerError, "template start command: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, g.sandboxResp(sb, apiKey(r)))
}

// start runs the template's start command in a new sandbox and waits for
// its ready port.
func (g *Gateway) start(ctx context.Context, id string, t config.E2BTemplate, env map[string]string) error {
	if t.StartCmd != "" {
		sctx, cancel := context.WithCancel(ctx)
		st, err := g.api.StartProcess(sctx, &pb.StartProcessRequest{SandboxId: id, Cmd: "/bin/bash",
			Args: []string{"-l", "-c", t.StartCmd}, Env: env, Tag: "e2b-start"})
		if err == nil {
			_, err = st.Recv() // started; it keeps running when the stream goes
		}
		cancel()
		if err != nil {
			return err
		}
	}
	if t.ReadyPort == 0 {
		return nil
	}
	timeout := time.Duration(t.ReadyTimeout) * time.Second
	if timeout <= 0 {
		timeout = time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		probe, cancel := context.WithDeadline(ctx, deadline) // a probe hanging is bounded too
		c, err := g.dialPort(ctx, probe, id, t.ReadyPort)
		cancel()
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("port %d not ready after %v: %v", t.ReadyPort, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// sandbox is the sandbox of the request's {id}, if it was made by the
// gateway and is not over.
func (g *Gateway) sandbox(ctx context.Context, w http.ResponseWriter, r *http.Request) (*pb.Sandbox, bool) {
	id, err := fromE2B(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return nil, false
	}
	sb, err := g.api.GetSandbox(ctx, &pb.SandboxRef{Id: id})
	if err != nil {
		writeAPIErr(w, err)
		return nil, false
	}
	switch sb.State {
	case pb.SandboxState_STOPPED, pb.SandboxState_FAILED, pb.SandboxState_STOPPING:
		writeErr(w, http.StatusNotFound, "sandbox "+r.PathValue("id")+" not found")
		return nil, false
	}
	return sb, true
}

func (g *Gateway) get(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if sb, ok := g.sandbox(ctx, w, r); ok {
		writeJSON(w, http.StatusOK, g.full(sb, apiKey(r)))
	}
}

func (g *Gateway) list(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	states := map[string]bool{}
	for _, s := range q["state"] {
		for _, x := range strings.Split(s, ",") {
			states[x] = true
		}
	}
	meta := map[string]string{}
	if m := q.Get("metadata"); m != "" { // "k1=v1&k2=v2", itself URL-encoded
		if vs, err := url.ParseQuery(m); err == nil {
			for k := range vs {
				meta[k] = vs.Get(k)
			}
		}
	}
	limit := 0
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	l, err := g.api.ListSandboxes(ctx, &pb.SandboxFilter{Project: g.project(r)})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	out := []sandboxDetail{}
	for _, sb := range l.Sandboxes {
		if _, ok := sb.GetSpec().GetLabels()[labelTemplate]; !ok {
			continue // not made through the gateway
		}
		if sb.State != pb.SandboxState_RUNNING && sb.State != pb.SandboxState_PAUSED {
			continue
		}
		d := g.detail(sb, "")
		if len(states) > 0 && !states[d.State] {
			continue
		}
		match := true
		for k, v := range meta {
			match = match && d.Metadata[k] == v
		}
		if !match {
			continue
		}
		out = append(out, d)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) kill(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	if _, err := g.api.StopSandbox(ctx, &pb.SandboxRef{Id: sb.Id}); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gateway) setTimeout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timeout int64 `json:"timeout"`
	}
	if !decode(w, r, &req) {
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	if _, err := g.api.SetSandboxTimeout(ctx, &pb.SetTimeoutRequest{SandboxId: sb.Id, TimeoutS: max(g.timeout(req.Timeout), 1)}); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pausedTimeout is how long a paused sandbox is kept (the admission cap on
// lifetimes, if lower, applies): E2B keeps paused sandboxes until killed.
const pausedTimeout = 30 * 24 * 3600

func (g *Gateway) pause(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Memory *bool `json:"memory"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Memory != nil && !*req.Memory {
		writeErr(w, http.StatusBadRequest, "filesystem-only pauses are not supported by the OpenDsec E2B gateway: pauses keep memory")
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	if sb.State == pb.SandboxState_PAUSED {
		writeErr(w, http.StatusConflict, "sandbox "+r.PathValue("id")+" is already paused")
		return
	}
	if _, err := g.api.PauseSandbox(ctx, &pb.SandboxRef{Id: sb.Id}); err != nil {
		writeAPIErr(w, err)
		return
	}
	if _, err := g.api.SetSandboxTimeout(ctx, &pb.SetTimeoutRequest{SandboxId: sb.Id, TimeoutS: pausedTimeout}); err != nil {
		g.log.Warn("e2b: extending a paused sandbox's timeout failed", "id", sb.Id, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// connect resumes a paused sandbox (201) or returns a running one (200),
// with its timeout set from now.
func (g *Gateway) connect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timeout int64 `json:"timeout"`
		Memory  *bool `json:"memory"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Memory != nil && !*req.Memory {
		writeErr(w, http.StatusBadRequest, "resuming from disk only (on_resume=\"reboot\") is not supported by the OpenDsec E2B gateway")
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	code := http.StatusOK
	if sb.State == pb.SandboxState_PAUSED {
		var err error
		if sb, err = g.api.ResumeSandbox(ctx, &pb.SandboxRef{Id: sb.Id}); err != nil {
			writeAPIErr(w, err)
			return
		}
		code = http.StatusCreated
	}
	// E2B's connect only extends the sandbox's life: a shorter timeout than
	// what is left keeps the current end.
	if t := g.timeout(req.Timeout); t > 0 && !endsAfter(sb, time.Now().Add(time.Duration(t)*time.Second)) {
		var err error
		if sb, err = g.api.SetSandboxTimeout(ctx, &pb.SetTimeoutRequest{SandboxId: sb.Id, TimeoutS: t}); err != nil {
			writeAPIErr(w, err)
			return
		}
	}
	writeJSON(w, code, g.sandboxResp(sb, apiKey(r)))
}
