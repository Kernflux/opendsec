package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/apiserver"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

type tlsCluster struct {
	*cluster.Local
	pki   string
	audit string
}

func startTLS(t *testing.T) (*tlsCluster, *client.Client) {
	t.Helper()
	cfg := cluster.SimConfig(2, 2, 16, 64*1024, 100)
	cfg.ServiceToken = "" // production mode: mTLS only
	dir, audit := t.TempDir(), t.TempDir()
	if err := cluster.GeneratePKI(cfg, dir, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	cfg.TLS.Dir = dir
	for i := range cfg.APIServers {
		cfg.APIServers[i].AuditDir = audit
	}
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	c, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root", client.WithCAFile(filepath.Join(dir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &tlsCluster{Local: l, pki: dir, audit: audit}, c
}

// as dials addr with component identity id's certificate.
func (tc *tlsCluster) as(t *testing.T, id pki.Identity, addr string, expect *pki.Identity) *grpc.ClientConn {
	t.Helper()
	m, err := pki.Load(tc.pki, id)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rpcutil.Dial(addr, &rpcutil.Security{TLS: m}, expect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func short(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestTLSPublicAPI(t *testing.T) {
	tc, c := startTLS(t)
	sb, err := c.Create(ctx(t), spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stop(ctx(t), sb.Id); err != nil {
		t.Fatal(err)
	}
	// A plaintext client cannot talk to the TLS apiserver.
	plain, _ := client.Dial(tc.Cfg.APIServers[0].Addr, tc.AdminToken, "root")
	defer plain.Close()
	if _, err := plain.WhoAmI(short(t), &pb.Empty{}); err == nil {
		t.Fatal("plaintext client accepted by TLS apiserver")
	}
	// A client that does not trust the cluster CA refuses the server.
	other, _ := pki.NewCA("other", time.Hour)
	wrongCA := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(wrongCA, other.PEM, 0o644)
	untrusting, _ := client.Dial(tc.Cfg.APIServers[0].Addr, tc.AdminToken, "root", client.WithCAFile(wrongCA))
	defer untrusting.Close()
	if _, err := untrusting.WhoAmI(short(t), &pb.Empty{}); err == nil {
		t.Fatal("client accepted a server certificate from an untrusted CA")
	}
}

func TestInternalMTLS(t *testing.T) {
	tc, _ := startTLS(t)
	cfg := tc.Cfg
	iamAddr, watcherAddr, edgeAddr := cfg.IAM.Addr, cfg.Watcher.Addr, cfg.Edges[0].Addr

	// No client certificate: the handshake itself fails.
	b, _ := os.ReadFile(filepath.Join(tc.pki, "ca.crt"))
	pool := mustPool(t, b)
	noCert, _ := grpc.NewClient("passthrough:///"+iamAddr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsConfig{pool}.cfg())))
	defer noCert.Close()
	if _, err := pb.NewIAMClient(noCert).SecurityEpoch(short(t), &pb.Empty{}); err == nil {
		t.Fatal("IAM accepted a client without certificate")
	}

	// An edge certificate may release leases but not admit.
	edgeID := pki.Identity{Role: pki.RoleEdge, ID: cfg.Edges[0].ID}
	asEdge := pb.NewIAMClient(tc.as(t, edgeID, iamAddr, nil))
	if _, err := asEdge.Release(short(t), &pb.ReleaseRequest{Lease: "x"}); err != nil {
		t.Fatalf("edge Release: %v", err)
	}
	if _, err := asEdge.Admit(short(t), &pb.AdmitRequest{Token: tc.AdminToken, Project: "root"}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("edge Admit: %v", err)
	}
	// The apiserver certificate may.
	asAPI := pb.NewIAMClient(tc.as(t, pki.Identity{Role: pki.RoleAPIServer, ID: "0"}, iamAddr, nil))
	if _, err := asAPI.Admit(short(t), &pb.AdmitRequest{Token: tc.AdminToken, Project: "root"}); err != nil {
		t.Fatalf("apiserver Admit: %v", err)
	}
	// The key-value area: apiservers reach only their extensions' ext/ keys,
	// never the fleet service's state.
	if _, err := asAPI.KVPut(short(t), &pb.KVPutRequest{Key: "ext/sso/users/x", Value: []byte("{}")}); err != nil {
		t.Fatalf("apiserver KVPut ext/: %v", err)
	}
	if e, err := asAPI.KVGet(short(t), &pb.KVGetRequest{Key: "ext/sso/users/x"}); err != nil || string(e.Value) != "{}" {
		t.Fatalf("apiserver KVGet ext/: %v %v", e, err)
	}
	for name, call := range map[string]func() error{
		"KVPut": func() error {
			_, err := asAPI.KVPut(short(t), &pb.KVPutRequest{Key: "fleet/node/x", Value: []byte("{}")})
			return err
		},
		"KVGet":    func() error { _, err := asAPI.KVGet(short(t), &pb.KVGetRequest{Key: "fleet/node/x"}); return err },
		"KVList":   func() error { _, err := asAPI.KVList(short(t), &pb.KVListRequest{Prefix: ""}); return err },
		"KVDelete": func() error { _, err := asAPI.KVDelete(short(t), &pb.KVDeleteRequest{Key: "fleet/node/x"}); return err },
	} {
		if err := call(); rpcutil.Reason(err) != rpcutil.Forbidden {
			t.Fatalf("apiserver %s outside ext/: %v", name, err)
		}
	}

	// An edge may only register itself with the watcher.
	w := pb.NewWatcherClient(tc.as(t, edgeID, watcherAddr, nil))
	if _, err := w.Register(short(t), &pb.RegisterEdgeRequest{Id: cfg.Edges[1].ID, Addr: "127.0.0.1:1"}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("edge registered another edge: %v", err)
	}
	if _, err := w.Register(short(t), &pb.RegisterEdgeRequest{Id: edgeID.ID, Addr: edgeAddr}); err != nil {
		t.Fatalf("edge self-registration: %v", err)
	}
	if _, err := w.GetSnapshot(short(t), &pb.Empty{}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("edge read the watcher snapshot: %v", err)
	}

	// The watcher may probe an edge but not create sandboxes on it.
	ew := pb.NewEdgeClient(tc.as(t, pki.Identity{Role: pki.RoleWatcher}, edgeAddr, &edgeID))
	if _, err := ew.Status(short(t), &pb.EdgeStatusRequest{}); err != nil {
		t.Fatalf("watcher Status: %v", err)
	}
	if _, err := ew.CreateSandbox(short(t), &pb.EdgeCreateRequest{}); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("watcher CreateSandbox: %v", err)
	}
	// Dialing edge 0's address while expecting edge 1 fails: no impersonation.
	wrong := pki.Identity{Role: pki.RoleEdge, ID: cfg.Edges[1].ID}
	imp := pb.NewEdgeClient(tc.as(t, pki.Identity{Role: pki.RoleAPIServer, ID: "0"}, edgeAddr, &wrong))
	if _, err := imp.Status(short(t), &pb.EdgeStatusRequest{}); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("connected to the wrong edge: %v", err)
	}
	// The legacy service token is worthless in TLS mode.
	tokOnly, _ := rpcutil.Dial(iamAddr, &rpcutil.Security{Token: "anything"}, nil)
	defer tokOnly.Close()
	if _, err := pb.NewIAMClient(tokOnly).SecurityEpoch(short(t), &pb.Empty{}); err == nil {
		t.Fatal("service token accepted in TLS mode")
	}
}

func TestTokenRevocationAndExpiry(t *testing.T) {
	tc, admin := startTLS(t)
	ca := client.WithCAFile(filepath.Join(tc.pki, "ca.crt"))
	cx := ctx(t)
	pr, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root", Id: "agent", Kind: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	admin.Grant(cx, &pb.GrantRequest{Project: "root", Principal: "agent", Perms: []string{"sandbox.create", "sandbox.operate"}})
	// Use the token through apiserver 1 so it is cached there...
	a1, _ := client.Dial(tc.Cfg.APIServers[1].Addr, pr.Token, "root", ca)
	defer a1.Close()
	if _, err := a1.WhoAmI(cx, &pb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a1.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"}); err != nil {
		t.Fatal(err)
	}
	// ...then revoke it through apiserver 0. Apiserver 1 learns via the epoch.
	start := time.Now()
	if _, err := admin.RevokeToken(cx, &pb.RevokeTokenRequest{Principal: "agent", TokenId: pr.TokenInfo.Id}); err != nil {
		t.Fatal(err)
	}
	eventuallyFor(t, 3*time.Second, func() bool {
		_, err := a1.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"})
		return rpcutil.Reason(err) == rpcutil.Unauthenticated
	})
	t.Logf("revocation effective on the other apiserver after %v", time.Since(start).Round(10*time.Millisecond))

	// A short-lived token stops working when it expires, even if cached.
	tk, err := admin.CreateToken(cx, &pb.CreateTokenRequest{Principal: "agent", TtlS: 1})
	if err != nil {
		t.Fatal(err)
	}
	a0, _ := client.Dial(tc.Cfg.APIServers[0].Addr, tk.Token, "root", ca)
	defer a0.Close()
	if _, err := a0.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := a0.ListSandboxes(cx, &pb.SandboxFilter{Project: "root"}); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("expired token still accepted: %v", err)
	}
	// Tokens can be listed (without secrets) and the principal deleted.
	tl, err := admin.ListTokens(cx, &pb.ListTokensRequest{Principal: "agent"})
	if err != nil || len(tl.Tokens) != 1 {
		t.Fatalf("list tokens: %v %v", tl, err)
	}
	if _, err := admin.DeletePrincipal(cx, &pb.DeletePrincipalRequest{Principal: "agent"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditLog(t *testing.T) {
	tc, c := startTLS(t)
	cx := ctx(t)
	var hdr metadata.MD
	sb, err := c.CreateSandbox(cx, &pb.CreateSandboxRequest{Project: "root", Spec: spec}, grpc.Header(&hdr))
	if err != nil {
		t.Fatal(err)
	}
	rid := hdr.Get("x-opendsec-request-id")
	if len(rid) != 1 {
		t.Fatalf("no request id header: %v", hdr)
	}
	c.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id}) // read: not audited by default
	c.Stop(cx, sb.Id)
	c.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "audited"})
	bad, _ := client.Dial(tc.Cfg.APIServers[0].Addr, "dsk.admin.wrong", "root", client.WithCAFile(filepath.Join(tc.pki, "ca.crt")))
	defer bad.Close()
	bad.Create(cx, spec)
	bad.GetSandbox(cx, &pb.SandboxRef{Id: sb.Id}) // auth failures are audited even for reads

	tc.APIServers[0].Audit.Flush()
	recs := readAudit(t, tc.audit)
	byMethod := map[string][]apiserver.AuditRecord{}
	for _, r := range recs {
		byMethod[r.Method] = append(byMethod[r.Method], r)
	}
	cr := byMethod["CreateSandbox"]
	if len(cr) != 2 {
		t.Fatalf("CreateSandbox records = %d: %+v", len(cr), recs)
	}
	ok := cr[0]
	if ok.Reason != "" {
		ok = cr[1]
	}
	if ok.Principal != "admin" || ok.Project != "root" || ok.TaskID != "job-1" || ok.Code != "OK" || ok.RequestID != rid[0] || ok.Peer == "" {
		t.Fatalf("create record: %+v", ok)
	}
	if s := byMethod["StopSandbox"]; len(s) != 1 || s[0].SandboxID != sb.Id || s[0].Principal != "admin" {
		t.Fatalf("stop record: %+v", s)
	}
	if p := byMethod["CreateProject"]; len(p) != 1 || p[0].Target != "root/audited" {
		t.Fatalf("project record: %+v", p)
	}
	unauth := 0
	for _, r := range recs {
		if r.Reason == rpcutil.Unauthenticated {
			unauth++
			if r.Principal != "" {
				t.Errorf("unauthenticated record has principal %q", r.Principal)
			}
		}
	}
	if unauth != 2 {
		t.Fatalf("unauthenticated records = %d, want 2", unauth)
	}
	for _, r := range byMethod["GetSandbox"] {
		if r.Reason != rpcutil.Unauthenticated {
			t.Fatalf("successful read audited without audit_runtime: %+v", r)
		}
	}
}

func readAudit(t *testing.T, dir string) []apiserver.AuditRecord {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-0-*.log"))
	var out []apiserver.AuditRecord
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			var r apiserver.AuditRecord
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("bad audit line %q: %v", sc.Text(), err)
			}
			out = append(out, r)
		}
		fh.Close()
	}
	return out
}

type tlsConfig struct{ pool *x509.CertPool }

func (c tlsConfig) cfg() *tls.Config {
	return &tls.Config{RootCAs: c.pool, ServerName: pki.InternalName, MinVersion: tls.VersionTLS13}
}

func mustPool(t *testing.T, pemBytes []byte) *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pemBytes) {
		t.Fatal("bad CA")
	}
	return p
}

// TestSeveralAPIServers: "addr,addr" spreads calls over both apiservers,
// verifies them under TLS as client.APIServerName (which every apiserver
// certificate carries), and keeps working when one of them stops.
func TestSeveralAPIServers(t *testing.T) {
	tc, _ := startTLS(t)
	addrs := []string{tc.Cfg.APIServers[0].Addr, tc.Cfg.APIServers[1].Addr}
	c, err := client.Dial(strings.Join(addrs, ","), tc.AdminToken, "root", client.WithCAFile(filepath.Join(tc.pki, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 10; i++ {
		if _, err := c.WhoAmI(short(t), &pb.Empty{}); err != nil {
			t.Fatalf("call %d with both apiservers up: %v", i, err)
		}
	}

	tc.APIComps[0].Stop()
	// The balancer drops the stopped one once its connection breaks; calls
	// picked for it before that may fail.
	deadline := time.Now().Add(10 * time.Second)
	for ok := 0; ok < 10; {
		if _, err := c.WhoAmI(short(t), &pb.Empty{}); err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("one apiserver down: calls still fail after 10s: %v", err)
			}
			ok = 0
			time.Sleep(100 * time.Millisecond)
			continue
		}
		ok++
	}
}
