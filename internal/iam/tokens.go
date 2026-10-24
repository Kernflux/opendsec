package iam

import (
	"sort"
	"time"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// PrimaryTokenID names a principal's legacy dsk.<id>.<secret> token.
const PrimaryTokenID = "primary"

// Token is an issued bearer token; only the hash of its secret is stored.
type Token struct {
	ID          string  `json:"id"`
	Principal   string  `json:"principal"`
	Hash        string  `json:"hash"`
	CreatedAt   float64 `json:"created_at"`
	ExpiresAt   float64 `json:"expires_at"` // 0 = never
	Description string  `json:"description"`
	CreatedBy   string  `json:"created_by"`
}

// canManageLocked: a principal manages its own tokens; admins of the project a
// principal belongs to manage that principal.
func (m *IAM) canManageLocked(actor, principal string) (*Principal, error) {
	p := m.principals[principal]
	if p == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "principal %q", principal)
	}
	if actor == principal {
		return p, nil
	}
	if m.projects[p.Project] != nil && m.effectiveLocked(actor, p.Project)[ProjectAdmin] {
		return p, nil
	}
	return nil, rpcutil.Err(rpcutil.Forbidden, "%s may not manage principal %s (needs project.admin on %s)", actor, principal, p.Project)
}

// CreateToken issues a new token for principal.
func (m *IAM) CreateToken(actor, principal string, ttl time.Duration, desc string) (string, *Token, error) {
	exp, err := m.expiry(ttl)
	if err != nil {
		return "", nil, err
	}
	tid, secret, hash := newTokenMaterial()
	v, err := m.propose(&Command{Op: opCreateToken, Actor: actor, Principal: principal,
		TokenID: tid, Hash: hash, ExpiresAt: exp, Desc: desc})
	if err != nil {
		return "", nil, err
	}
	return "dsk." + principal + "." + tid + "." + secret, v.(*Token), nil
}

func (m *IAM) createTokenLocked(c *Command) (*Token, error) {
	if _, err := m.canManageLocked(c.Actor, c.Principal); err != nil {
		return nil, err
	}
	t := &Token{ID: c.TokenID, Principal: c.Principal, Hash: c.Hash, CreatedAt: c.Now,
		ExpiresAt: c.ExpiresAt, Description: c.Desc, CreatedBy: c.Actor}
	m.tokens[t.ID] = t
	cp := *t
	return &cp, nil
}

// ListTokens returns principal's tokens (never their secrets).
func (m *IAM) ListTokens(actor, principal string) ([]Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, err := m.canManageLocked(actor, principal)
	if err != nil {
		return nil, err
	}
	var out []Token
	if p.SecretHash != "" {
		out = append(out, Token{ID: PrimaryTokenID, Principal: principal, CreatedAt: p.CreatedAt, CreatedBy: p.CreatedBy})
	}
	for _, t := range m.tokens {
		if t.Principal == principal {
			c := *t
			c.Hash = ""
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

// RevokeToken invalidates one token ("primary" for the legacy token).
func (m *IAM) RevokeToken(actor, principal, tid string) error {
	_, err := m.propose(&Command{Op: opRevokeToken, Actor: actor, Principal: principal, TokenID: tid})
	return err
}

func (m *IAM) revokeTokenLocked(c *Command) error {
	p, err := m.canManageLocked(c.Actor, c.Principal)
	if err != nil {
		return err
	}
	switch t := m.tokens[c.TokenID]; {
	case c.TokenID == PrimaryTokenID && p.SecretHash != "":
		p.SecretHash = ""
	case t != nil && t.Principal == c.Principal:
		delete(m.tokens, c.TokenID)
	default:
		return rpcutil.Err(rpcutil.NotFound, "token %q of %s", c.TokenID, c.Principal)
	}
	m.epoch++
	return nil
}

// DeletePrincipal removes a principal, all its tokens and all its grants.
// The bootstrap admin cannot be deleted.
func (m *IAM) DeletePrincipal(actor, principal string) error {
	_, err := m.propose(&Command{Op: opDeletePrincipal, Actor: actor, Principal: principal})
	return err
}

func (m *IAM) deletePrincipalLocked(c *Command) error {
	p, err := m.canManageLocked(c.Actor, c.Principal)
	if err != nil {
		return err
	}
	if p.CreatedBy == "bootstrap" {
		return rpcutil.Err(rpcutil.Forbidden, "the bootstrap admin cannot be deleted")
	}
	for id, t := range m.tokens {
		if t.Principal == c.Principal {
			delete(m.tokens, id)
		}
	}
	for _, proj := range m.projects {
		delete(proj.Policies, c.Principal)
	}
	delete(m.principals, c.Principal)
	m.epoch++
	return nil
}

// DeleteProject removes an empty leaf project (no children, no usage, no
// principals belonging to it).
func (m *IAM) DeleteProject(actor, path string) error {
	_, err := m.propose(&Command{Op: opDeleteProject, Actor: actor, Project: path})
	return err
}

func (m *IAM) deleteProjectLocked(c *Command) error {
	path := c.Project
	proj := m.projects[path]
	if proj == nil {
		return rpcutil.Err(rpcutil.NotFound, "project %q", path)
	}
	parent := parentOf(path)
	if parent == "" {
		return rpcutil.Err(rpcutil.Forbidden, "the root project cannot be deleted")
	}
	if err := m.authorizeLocked(c.Actor, parent, ProjectAdmin); err != nil {
		return err
	}
	for k := range m.projects {
		if parentOf(k) == path {
			return rpcutil.Err(rpcutil.Invalid, "project %s has subprojects", path)
		}
	}
	ks := keysF(proj.usage)
	for _, k := range ks {
		if v := proj.usage[k]; v > 0 {
			return rpcutil.Err(rpcutil.Invalid, "project %s still uses %s=%g", path, k, v)
		}
	}
	owners := []string{}
	for _, p := range m.principals {
		if p.Project == path {
			owners = append(owners, p.ID)
		}
	}
	if len(owners) > 0 {
		sort.Strings(owners)
		return rpcutil.Err(rpcutil.Invalid, "project %s still owns principal %s", path, owners[0])
	}
	delete(m.projects, path)
	m.epoch++
	return nil
}

func keysF(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
