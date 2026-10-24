// Package iam implements principals, multi-level nested projects, inherited
// policies, bounded delegation and hierarchical quotas (paper §3, spec §3.2).
//
// Every state change is a deterministic Command (commands.go). In standalone
// mode commands are applied directly and persisted to a JSON file; with
// replicas they are replicated through Raft (raft.go, spec §15).
package iam

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Permissions.
const (
	SandboxCreate  = "sandbox.create"
	SandboxOperate = "sandbox.operate"
	LayerPublish   = "layer.publish"
	LayerUse       = "layer.use"
	ProjectAdmin   = "project.admin"
	// Cluster management (spec §28.8), meaningful on the root project.
	FleetView    = "fleet.view"
	FleetOperate = "fleet.operate"
)

var AllPermissions = []string{SandboxCreate, SandboxOperate, LayerPublish, LayerUse, ProjectAdmin, FleetView, FleetOperate}

// Quota / usage keys.
const (
	QSandboxes = "sandboxes"
	QCPU       = "cpu_cores"
	QMemory    = "memory_mb"
	QGPUs      = "gpus"
)

var quotaKeys = map[string]bool{QSandboxes: true, QCPU: true, QMemory: true, QGPUs: true}

type Principal struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	SecretHash string  `json:"secret_hash"` // legacy primary token (dsk.<id>.<secret>); "" = none
	Project    string  `json:"project"`     // project it was created in; its admins manage it
	CreatedBy  string  `json:"created_by"`
	CreatedAt  float64 `json:"created_at"`
}

type Project struct {
	Path      string              `json:"path"`
	Quota     map[string]float64  `json:"quota"` // missing key = inherit parent's
	Policies  map[string][]string `json:"policies"`
	CreatedBy string              `json:"created_by"`
	usage     map[string]float64  // derived from reservations
}

// Reservation is a quota lease: the resources of one sandbox, charged to its
// project and every ancestor until released.
type Reservation struct {
	Lease   string             `json:"lease"`
	Project string             `json:"project"`
	Res     map[string]float64 `json:"res"`
	At      float64            `json:"at"`             // reserved at (unix seconds)
	Edge    string             `json:"edge,omitempty"` // edge that reported it; "" = not yet claimed
}

type IAM struct {
	// MaxTokenTTL caps issued token lifetimes; 0 = no cap (spec §14.3).
	MaxTokenTTL time.Duration

	mu           sync.RWMutex
	principals   map[string]*Principal
	projects     map[string]*Project
	tokens       map[string]*Token // token id -> token
	reservations map[string]*Reservation
	usage        map[string]*UsageRow       // "<project>|<day>" (usage.go)
	byEdge       map[string]map[string]bool // edge -> leases claimed by it
	locks        map[string]*Lock           // lease locks (leader election)
	epoch        uint64                     // bumped on every revocation
	members      map[string]string          // Raft replica id -> gRPC addr, for added replicas (spec §27.2)
	configAddrs  map[string]string          // the same, from the cluster config (SetConfigAddrs)
	kv           map[string]*KVEntry        // key-value area (kv.go)
	kvRev        uint64                     // revision of the last key-value write

	statePath  string     // standalone persistence; "" with Raft or in-memory
	raft       *raft.Raft // nil in standalone mode
	closeStore func() error
	now        func() time.Time
}

func New(statePath string) (*IAM, error) {
	m := newEmpty()
	m.statePath = statePath
	if statePath != "" {
		if err := m.load(); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return m, nil
}

func newEmpty() *IAM {
	return &IAM{
		principals:   map[string]*Principal{},
		projects:     map[string]*Project{},
		tokens:       map[string]*Token{},
		reservations: map[string]*Reservation{},
		usage:        map[string]*UsageRow{},
		byEdge:       map[string]map[string]bool{},
		locks:        map[string]*Lock{},
		members:      map[string]string{},
		kv:           map[string]*KVEntry{},
		now:          time.Now,
	}
}

// Ancestors returns "a/b/c" -> ["a/b/c", "a/b", "a"].
func Ancestors(path string) []string {
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for i := len(parts); i > 0; i-- {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

func parentOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return ""
	}
	return path[:i]
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// splitToken parses "dsk.<pid>.<secret>" (primary) or "dsk.<pid>.<tid>.<secret>".
func splitToken(token string) (pid, tid, secret string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || len(parts) > 4 || parts[0] != "dsk" {
		return "", "", "", false
	}
	for _, p := range parts[1:] {
		if p == "" {
			return "", "", "", false
		}
	}
	if len(parts) == 3 {
		return parts[1], "", parts[2], true
	}
	return parts[1], parts[2], parts[3], true
}

// ---- authn / authz (reads; served from local state) --------------------------------

func (m *IAM) Authenticate(token string) (*Principal, error) {
	p, _, err := m.AuthenticateToken(token)
	return p, err
}

// AuthenticateToken also returns the token's expiry (0 = never), so callers
// never cache a token past its lifetime.
func (m *IAM) AuthenticateToken(token string) (*Principal, float64, error) {
	pid, tid, secret, ok := splitToken(token)
	if !ok {
		return nil, 0, rpcutil.Err(rpcutil.Unauthenticated, "malformed token")
	}
	h := []byte(hashSecret(secret))
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := m.principals[pid]
	if p == nil {
		return nil, 0, rpcutil.Err(rpcutil.Unauthenticated, "invalid token")
	}
	if tid == "" {
		if p.SecretHash == "" || subtle.ConstantTimeCompare([]byte(p.SecretHash), h) != 1 {
			return nil, 0, rpcutil.Err(rpcutil.Unauthenticated, "invalid token")
		}
		return p, 0, nil
	}
	t := m.tokens[tid]
	if t == nil || t.Principal != pid || subtle.ConstantTimeCompare([]byte(t.Hash), h) != 1 {
		return nil, 0, rpcutil.Err(rpcutil.Unauthenticated, "invalid token")
	}
	if t.ExpiresAt > 0 && unix(m.now()) >= t.ExpiresAt {
		return nil, 0, rpcutil.Err(rpcutil.Unauthenticated, "token expired")
	}
	return p, t.ExpiresAt, nil
}

func (m *IAM) effectiveLocked(principal, project string) map[string]bool {
	out := map[string]bool{}
	for _, a := range Ancestors(project) {
		if p := m.projects[a]; p != nil {
			for _, perm := range p.Policies[principal] {
				out[perm] = true
			}
		}
	}
	return out
}

// EffectivePermissions returns the permissions principal holds on project,
// including those inherited from ancestors.
func (m *IAM) EffectivePermissions(principal, project string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return keys(m.effectiveLocked(principal, project))
}

func (m *IAM) authorizeLocked(principal, project, perm string) error {
	if m.projects[project] == nil {
		return rpcutil.Err(rpcutil.NotFound, "project %q", project)
	}
	if !m.effectiveLocked(principal, project)[perm] {
		return rpcutil.Err(rpcutil.Forbidden, "%s lacks %s on %s", principal, perm, project)
	}
	return nil
}

func (m *IAM) Authorize(principal, project, perm string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authorizeLocked(principal, project, perm)
}

// ProjectView is a project with live usage and children, for GetProject.
type ProjectView struct {
	Path     string
	Quota    map[string]float64
	Usage    map[string]float64
	Policies map[string][]string
	Children []string
}

// GetProject requires the actor to hold any permission on the project.
func (m *IAM) GetProject(actor, project string) (*ProjectView, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.projects[project] == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "project %q", project)
	}
	if actor != "" && len(m.effectiveLocked(actor, project)) == 0 {
		return nil, rpcutil.Err(rpcutil.Forbidden, "%s has no access to %s", actor, project)
	}
	return m.viewLocked(project), nil
}

func (m *IAM) viewLocked(path string) *ProjectView {
	p := m.projects[path]
	v := &ProjectView{Path: path, Quota: copyMap(p.Quota), Usage: copyMap(p.usage), Policies: map[string][]string{}}
	for k, perms := range p.Policies {
		v.Policies[k] = append([]string(nil), perms...)
	}
	for k := range m.projects {
		if parentOf(k) == path {
			v.Children = append(v.Children, k)
		}
	}
	sort.Strings(v.Children)
	return v
}

// SecurityEpoch changes whenever a credential or grant is revoked.
func (m *IAM) SecurityEpoch() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.epoch
}

// ---- state (persistence and Raft snapshots) -----------------------------------------

type state struct {
	Principals   []*Principal      `json:"principals"`
	Projects     []*Project        `json:"projects"`
	Tokens       []*Token          `json:"tokens"`
	Reservations []*Reservation    `json:"reservations,omitempty"` // Raft snapshots only
	Locks        []*Lock           `json:"locks,omitempty"`        // Raft snapshots only
	Members      map[string]string `json:"members,omitempty"`      // Raft snapshots only
	Epoch        uint64            `json:"epoch,omitempty"`
	KV           []*KVEntry        `json:"kv,omitempty"`
	Usage        []*UsageRow       `json:"usage,omitempty"`
	KVRev        uint64            `json:"kv_rev,omitempty"`
}

func (m *IAM) stateLocked(withLeases bool) *state {
	s := &state{Epoch: m.epoch, KVRev: m.kvRev}
	for _, e := range m.kv {
		s.KV = append(s.KV, e)
	}
	sort.Slice(s.KV, func(i, j int) bool { return s.KV[i].Key < s.KV[j].Key })
	for _, p := range m.principals {
		s.Principals = append(s.Principals, p)
	}
	for _, p := range m.projects {
		s.Projects = append(s.Projects, p)
	}
	for _, t := range m.tokens {
		s.Tokens = append(s.Tokens, t)
	}
	for _, u := range m.usage {
		cp := *u
		s.Usage = append(s.Usage, &cp)
	}
	sort.Slice(s.Usage, func(i, j int) bool {
		return s.Usage[i].Project+"|"+s.Usage[i].Day < s.Usage[j].Project+"|"+s.Usage[j].Day
	})
	if withLeases {
		for _, r := range m.reservations {
			s.Reservations = append(s.Reservations, r)
		}
		for _, l := range m.locks {
			s.Locks = append(s.Locks, l)
		}
		s.Members = maps.Clone(m.members)
	}
	return s
}

// restoreLocked replaces all state, recomputing usage from reservations.
func (m *IAM) restoreLocked(s *state) {
	m.principals = map[string]*Principal{}
	m.projects = map[string]*Project{}
	m.tokens = map[string]*Token{}
	m.reservations = map[string]*Reservation{}
	m.usage = map[string]*UsageRow{}
	for _, u := range s.Usage {
		m.usage[u.Project+"|"+u.Day] = u
	}
	m.byEdge = map[string]map[string]bool{}
	m.locks = map[string]*Lock{}
	m.members = map[string]string{}
	maps.Copy(m.members, s.Members)
	m.epoch = s.Epoch
	m.kv = map[string]*KVEntry{}
	m.kvRev = s.KVRev
	for _, e := range s.KV {
		m.kv[e.Key] = e
		m.kvRev = max(m.kvRev, e.Rev)
	}
	for _, l := range s.Locks {
		m.locks[l.Name] = l
	}
	for _, p := range s.Principals {
		if p.Project == "" {
			p.Project = "root" // state written before principals recorded their project
		}
		m.principals[p.ID] = p
	}
	for _, t := range s.Tokens {
		m.tokens[t.ID] = t
	}
	for _, p := range s.Projects {
		if p.Quota == nil {
			p.Quota = map[string]float64{}
		}
		if p.Policies == nil {
			p.Policies = map[string][]string{}
		}
		p.usage = nil
		m.projects[p.Path] = p
	}
	for _, r := range s.Reservations {
		m.addReservationLocked(r)
	}
}

// saveLocked persists standalone state (usage is rebuilt by reconcile).
func (m *IAM) saveLocked() error {
	if m.statePath == "" {
		return nil
	}
	b, err := json.MarshalIndent(m.stateLocked(false), "", " ")
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

func (m *IAM) load() error {
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%s: %w", m.statePath, err)
	}
	m.restoreLocked(&s)
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func copyMap(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func unix(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }
