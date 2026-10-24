package e2e

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// ssoTokens stands in for an enterprise SSO authenticator (ext):
// "sso.<principal>" authenticates as <principal>, and IAM never sees these
// tokens; "sso.bad" is a token the provider rejects.
type ssoTokens struct{}

func (ssoTokens) Authenticate(_ context.Context, tok string) (string, time.Time, bool, error) {
	id, ok := strings.CutPrefix(tok, "sso.")
	switch {
	case !ok:
		return "", time.Time{}, false, nil
	case id == "bad":
		return "", time.Time{}, false, errors.New("sso: token expired")
	}
	return id, time.Now().Add(time.Minute), true, nil
}

type auditLines struct {
	mu    sync.Mutex
	lines []string
}

func (a *auditLines) Write(line []byte) {
	a.mu.Lock()
	a.lines = append(a.lines, string(line))
	a.mu.Unlock()
}

func (a *auditLines) has(subs ...string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.lines {
		all := true
		for _, s := range subs {
			all = all && strings.Contains(l, s)
		}
		if all {
			return true
		}
	}
	return false
}

var (
	extOnce sync.Once
	audits  = &auditLines{}
)

// TestExtensionHooks: a token from an extension's authenticator is a
// first-class caller (who am I, creations against its quota, operations,
// permissions checked by IAM), and an extension's audit sink gets the audit
// log's records. The hooks are process-wide; they only act on "sso." tokens
// and only collect, so other tests are unaffected.
func TestExtensionHooks(t *testing.T) {
	extOnce.Do(func() {
		ext.AddAuthenticator(ssoTokens{})
		ext.AddAuditSink(audits)
	})
	cfg := cluster.SimConfig(2, 2, 16, 64*1024, 100)
	cfg.APIServers[0].AuditDir = t.TempDir()
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	cx := ctx(t)
	admin, err := client.Dial(cfg.APIServers[0].Addr, l.AdminToken, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.CreateProject(cx, &pb.CreateProjectRequest{Parent: "root", Name: "sso", Quota: map[string]float64{"sandboxes": 2}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if _, err := admin.CreatePrincipal(cx, &pb.CreatePrincipalRequest{Project: "root/sso", Id: id, Kind: "user"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Grant(cx, &pb.GrantRequest{Project: "root/sso", Principal: "alice",
		Perms: []string{"sandbox.create", "sandbox.operate"}}); err != nil {
		t.Fatal(err)
	}
	dial := func(tok string) *client.Client {
		c, err := client.Dial(cfg.APIServers[0].Addr, tok, "root/sso")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	alice, bob, bad := dial("sso.alice"), dial("sso.bob"), dial("sso.bad")

	if p, err := alice.WhoAmI(cx, &pb.Empty{}); err != nil || p.Id != "alice" {
		t.Fatalf("who am I: %v %v", p, err)
	}
	var made []string
	for i := 0; i < 2; i++ {
		sb, err := alice.Create(cx, spec)
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, sb.Id)
	}
	if _, err := alice.Create(cx, spec); rpcutil.Reason(err) != rpcutil.QuotaExceeded {
		t.Fatalf("over quota: %v", err)
	}
	if _, err := bob.Create(cx, spec); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("no permission: %v", err)
	}
	if _, err := bad.Create(cx, spec); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("rejected token: %v", err)
	}
	for _, id := range made {
		if _, err := alice.Stop(cx, id); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool {
		return audits.has(`"principal":"alice"`, `"method":"CreateSandbox"`, `"code":"OK"`) &&
			audits.has(`"principal":"alice"`, `"method":"StopSandbox"`)
	})
}
