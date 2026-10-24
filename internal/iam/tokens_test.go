package iam

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

func TestTokenLifecycle(t *testing.T) {
	m, adminTok := setup(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	m.CreateProject("admin", "root", "rl", nil)

	// The initial token of a new principal is a tracked, revocable token.
	tok, info, err := m.CreatePrincipal("admin", "root/rl", "agent", "agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := m.Authenticate(tok); err != nil || p.ID != "agent" || p.Project != "root/rl" {
		t.Fatalf("auth new token: %v", err)
	}
	if info.ExpiresAt == 0 {
		t.Fatal("initial token should expire")
	}
	// Expiry.
	now = now.Add(2 * time.Hour)
	if _, err := m.Authenticate(tok); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("expired token accepted: %v", err)
	}
	// The principal itself (via another token) or a project admin may issue tokens.
	tok2, t2, err := m.CreateToken("admin", "agent", 0, "ci")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(tok2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.CreateToken("agent", "agent", time.Minute, "self"); err != nil {
		t.Fatalf("self-issue: %v", err)
	}
	m.CreatePrincipal("admin", "root", "other", "agent", 0)
	if _, _, err := m.CreateToken("other", "agent", 0, ""); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("unrelated principal issued a token: %v", err)
	}
	// Listing never exposes secrets.
	ts, _ := m.ListTokens("agent", "agent")
	if len(ts) != 3 {
		t.Fatalf("tokens = %d, want 3", len(ts))
	}
	for _, x := range ts {
		if x.Hash != "" {
			t.Fatal("ListTokens leaked a hash")
		}
	}
	// Revocation bumps the epoch and takes effect immediately.
	e0 := m.SecurityEpoch()
	if err := m.RevokeToken("admin", "agent", t2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(tok2); rpcutil.Reason(err) != rpcutil.Unauthenticated {
		t.Fatalf("revoked token accepted: %v", err)
	}
	if m.SecurityEpoch() == e0 {
		t.Fatal("revocation did not bump the epoch")
	}
	// A token for one principal cannot be replayed as another's.
	forged := "dsk.admin." + tok[len("dsk.agent."):]
	if _, err := m.Authenticate(forged); err == nil {
		t.Fatal("token accepted for a different principal")
	}
	// The legacy primary token keeps working and is revocable as "primary".
	if _, err := m.Authenticate(adminTok); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeToken("admin", "admin", PrimaryTokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(adminTok); err == nil {
		t.Fatal("revoked primary token accepted")
	}
}

func TestMaxTokenTTL(t *testing.T) {
	m, _ := setup(t)
	m.MaxTokenTTL = time.Hour
	_, info, err := m.CreatePrincipal("admin", "root", "a", "agent", 0)
	if err != nil || info.ExpiresAt == 0 {
		t.Fatalf("default TTL not applied: %+v %v", info, err)
	}
	if _, _, err := m.CreateToken("admin", "a", 2*time.Hour, ""); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("over-long TTL accepted: %v", err)
	}
}

func TestDeletePrincipalAndProject(t *testing.T) {
	m, _ := setup(t)
	m.CreateProject("admin", "root", "rl", nil)
	tok, _, _ := m.CreatePrincipal("admin", "root/rl", "agent", "agent", 0)
	m.Grant("admin", "root/rl", "agent", []string{SandboxCreate})
	if err := m.DeleteProject("admin", "root/rl"); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("deleted a project that owns a principal: %v", err)
	}
	e0 := m.SecurityEpoch()
	if err := m.DeletePrincipal("admin", "agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(tok); err == nil {
		t.Fatal("deleted principal's token still works")
	}
	if len(m.EffectivePermissions("agent", "root/rl")) != 0 || m.SecurityEpoch() == e0 {
		t.Fatal("grants survived principal deletion")
	}
	if err := m.DeletePrincipal("admin", "admin"); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("bootstrap admin deleted: %v", err)
	}
	// A project in use cannot be deleted; an empty leaf can.
	m.Reserve("l1", "root/rl", map[string]float64{QSandboxes: 1})
	if err := m.DeleteProject("admin", "root/rl"); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("deleted a project in use: %v", err)
	}
	m.Release("l1")
	if err := m.DeleteProject("admin", "root/rl"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteProject("admin", "root"); rpcutil.Reason(err) != rpcutil.Forbidden {
		t.Fatalf("root deleted: %v", err)
	}
}

func TestTokensPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam.json")
	m, _ := New(path)
	m.Bootstrap("admin", "", nil)
	tok, _, _ := m.CreatePrincipal("admin", "root", "agent", "agent", time.Hour)
	tok2, t2, _ := m.CreateToken("admin", "agent", 0, "")
	m.RevokeToken("admin", "agent", t2.ID)

	m2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Authenticate(tok); err != nil {
		t.Fatalf("token lost across restart: %v", err)
	}
	if _, err := m2.Authenticate(tok2); err == nil {
		t.Fatal("revoked token came back after restart")
	}
}
