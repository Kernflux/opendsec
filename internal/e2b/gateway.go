// Package e2b serves E2B's API in front of an OpenDsec cluster (spec §37), so
// that E2B's SDKs (and the agent frameworks built on them) run their
// sandboxes on OpenDsec unchanged: point E2B_API_URL and E2B_SANDBOX_URL at
// the gateway and use an OpenDsec token as E2B_API_KEY.
//
// Two APIs share the listener:
//   - the control API (create, list, kill, timeout, pause, connect), REST;
//   - envd, E2B's in-sandbox API (processes and files; Connect RPC plus a
//     few HTTP routes), for requests naming a sandbox: by the E2b-Sandbox-Id
//     header the SDKs send, or by a host "<port>-<sandbox id>.<domain>".
//
// The gateway holds no state: everything is a call to the apiserver, made
// with the caller's own token.
package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// EnvdVersion is the envd version the gateway reports: the SDKs gate
// features on it. 0.5.7 has default users, stdin control, closing stdin and
// octet-stream uploads; file metadata (0.6.2) and watches are not served.
const EnvdVersion = "0.5.7"

// EnvdPort is envd's port in E2B sandboxes, as in sandbox hosts.
const EnvdPort = 49983

// withDefaults fills in a template's unset fields from d, then the
// built-in defaults: microvm, 2 vCPUs, 512 MB.
func withDefaults(t, d config.E2BTemplate) config.E2BTemplate {
	if t.Backend == "" {
		t.Backend = cmpOr(d.Backend, "microvm")
	}
	if t.CPU == 0 {
		t.CPU = d.CPU
		if t.CPU == 0 {
			t.CPU = 2
		}
	}
	if t.MemoryMB == 0 {
		t.MemoryMB = d.MemoryMB
		if t.MemoryMB == 0 {
			t.MemoryMB = 512
		}
	}
	if t.DiskMB == 0 {
		t.DiskMB = d.DiskMB
	}
	return t
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type Gateway struct {
	cfg config.E2B
	api *client.Client // dialed without a token: each call carries its caller's
	log *slog.Logger

	envMu sync.Mutex
	envs  map[string]envEntry // sandbox id -> its envVars, briefly cached
}

type envEntry struct {
	env map[string]string
	at  time.Time
}

func New(cfg config.E2B, api *client.Client, log *slog.Logger) *Gateway {
	return &Gateway{cfg: cfg, api: api, log: log, envs: map[string]envEntry{}}
}

// ---- ids --------------------------------------------------------------------------

// E2B sandbox ids are DNS labels (sandbox hosts "<port>-<id>.<domain>");
// OpenDsec's are "<edge>.<lease>". An edge id may hold "-", a lease never.

func toE2B(id string) string { return strings.Replace(id, ".", "-", 1) }

func fromE2B(e2bID string) (string, error) {
	i := strings.LastIndexByte(e2bID, '-')
	if i <= 0 {
		return "", fmt.Errorf("bad sandbox id %q", e2bID)
	}
	id := e2bID[:i] + "." + e2bID[i+1:]
	if _, _, err := ids.Parse(id); err != nil {
		return "", fmt.Errorf("bad sandbox id %q", e2bID)
	}
	return id, nil
}

// ---- labels -----------------------------------------------------------------------

// Sandboxes created through the gateway carry their E2B attributes in
// labels: the template, the metadata (one label per key) and envVars.
const (
	labelTemplate = "e2b.template"
	labelEnvs     = "e2b.envs"
	labelMeta     = "e2b.m."
	labelInternet = "e2b.internet" // allow_internet_access, when set
)

func metadataOf(sb *pb.Sandbox) map[string]string {
	m := map[string]string{}
	for k, v := range sb.GetSpec().GetLabels() {
		if key, ok := strings.CutPrefix(k, labelMeta); ok {
			m[key] = v
		}
	}
	return m
}

// sandboxEnv is the envVars sandbox id was created with (applied to every
// process), cached for a minute.
func (g *Gateway) sandboxEnv(ctx context.Context, id string) (map[string]string, error) {
	g.envMu.Lock()
	if e, ok := g.envs[id]; ok && time.Since(e.at) < time.Minute {
		g.envMu.Unlock()
		return e.env, nil
	}
	g.envMu.Unlock()
	sb, err := g.api.GetSandbox(ctx, &pb.SandboxRef{Id: id})
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if s := sb.GetSpec().GetLabels()[labelEnvs]; s != "" {
		json.Unmarshal([]byte(s), &env)
	}
	g.envMu.Lock()
	if len(g.envs) > 10000 {
		g.envs = map[string]envEntry{}
	}
	g.envs[id] = envEntry{env, time.Now()}
	g.envMu.Unlock()
	return env, nil
}

// ---- errors -----------------------------------------------------------------------

// httpStatus maps an apiserver error to an HTTP status (control API).
func httpStatus(err error) int { return reasonStatus(rpcutil.Reason(err)) }

// reasonStatus maps an OpenDsec error reason to an HTTP status.
func reasonStatus(reason string) int {
	switch reason {
	case rpcutil.Invalid:
		return http.StatusBadRequest
	case rpcutil.Unauthenticated:
		return http.StatusUnauthorized
	case rpcutil.Forbidden:
		return http.StatusForbidden
	case rpcutil.NotFound:
		return http.StatusNotFound
	case rpcutil.QuotaExceeded, rpcutil.RateLimited:
		return http.StatusTooManyRequests
	case rpcutil.NoCapacity, rpcutil.Unavailable:
		return http.StatusServiceUnavailable
	case rpcutil.Timeout:
		return http.StatusGatewayTimeout
	}
	return http.StatusInternalServerError
}

// connectErr maps an apiserver error to a Connect error (envd); the codes
// are gRPC's.
func connectErr(err error) error {
	if err == nil {
		return nil
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	st := status.Convert(err)
	return connect.NewError(connect.Code(st.Code()), errors.New(st.Message()))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

// writeErr writes E2B's error body.
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errBody(code, msg))
}

func errBody(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

func writeAPIErr(w http.ResponseWriter, err error) {
	st := status.Convert(err)
	writeErr(w, httpStatus(err), st.Message())
}

// ---- routing ----------------------------------------------------------------------

// Handler is the gateway's HTTP handler.
func (g *Gateway) Handler() http.Handler {
	api := g.apiHandler()
	envd := g.envdHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, port, ok := g.sandboxTarget(r); ok {
			if port != EnvdPort {
				g.portProxy(id, port).ServeHTTP(w, r)
				return
			}
			envd.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sandboxKey{}, id)))
			return
		}
		api.ServeHTTP(w, r)
	})
}

type sandboxKey struct{}

// sandboxTarget finds the sandbox (OpenDsec id) and port a request is for:
// the E2b-Sandbox-Id and E2b-Sandbox-Port headers, or a host
// "<port>-<id>.<domain>".
func (g *Gateway) sandboxTarget(r *http.Request) (id string, port int, ok bool) {
	e2bID, portS := r.Header.Get("E2b-Sandbox-Id"), r.Header.Get("E2b-Sandbox-Port")
	if e2bID == "" && g.cfg.Domain != "" {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
			host = host[:i]
		}
		if label, ok := strings.CutSuffix(host, "."+g.cfg.Domain); ok {
			portS, e2bID, _ = strings.Cut(label, "-")
		}
	}
	if e2bID == "" {
		return "", 0, false
	}
	id, err := fromE2B(e2bID)
	if err != nil {
		return "", 0, false
	}
	port = EnvdPort
	if portS != "" {
		if _, err := fmt.Sscanf(portS, "%d", &port); err != nil {
			return "", 0, false
		}
	}
	return id, port, true
}

// apiKey is the caller's token: X-API-KEY (the control API), X-Access-Token
// or E2B-Traffic-Access-Token (envd and other ports: the envdAccessToken and
// trafficAccessToken the control API returned, which are the same token), or
// a bearer token.
func apiKey(r *http.Request) string {
	for _, h := range []string{"X-API-KEY", "X-Access-Token", "E2B-Traffic-Access-Token"} {
		if k := r.Header.Get(h); k != "" {
			return k
		}
	}
	if k, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return k
	}
	return ""
}

func (g *Gateway) project(r *http.Request) string {
	return cmpOr(r.Header.Get("X-OpenDsec-Project"), g.cfg.Project)
}
