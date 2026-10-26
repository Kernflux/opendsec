package iam

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/raft"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Command is one deterministic state change. Everything nondeterministic
// (time, token ids and secret hashes) is chosen by the proposer and carried
// in the command, so every replica computes the same result (spec §15.1).
type Command struct {
	Op    string  `json:"op"`
	Now   float64 `json:"now"`
	Actor string  `json:"actor,omitempty"`

	Project   string             `json:"project,omitempty"`
	Parent    string             `json:"parent,omitempty"`
	Name      string             `json:"name,omitempty"`
	Principal string             `json:"principal,omitempty"`
	Kind      string             `json:"kind,omitempty"`
	Perms     []string           `json:"perms,omitempty"`
	Quota     map[string]float64 `json:"quota,omitempty"`
	TokenID   string             `json:"token_id,omitempty"`
	Hash      string             `json:"hash,omitempty"`
	ExpiresAt float64            `json:"expires_at,omitempty"`
	Desc      string             `json:"desc,omitempty"`

	Holder string  `json:"holder,omitempty"`
	TTL    float64 `json:"ttl,omitempty"`

	Lease   string             `json:"lease,omitempty"`
	Leases  []string           `json:"leases,omitempty"` // opReleaseLeases
	Res     map[string]float64 `json:"res,omitempty"`
	Edge    string             `json:"edge,omitempty"`
	Fresh   bool               `json:"fresh,omitempty"` // opReserve: the lease must not be held yet
	Adopt   []*Reservation     `json:"adopt,omitempty"`
	Bind    []string           `json:"bind,omitempty"`
	Release []string           `json:"release,omitempty"`

	State     *state `json:"state,omitempty"`      // restore
	ReplaceKV bool   `json:"replace_kv,omitempty"` // restore: the backup carries the key-value area
	Addr      string `json:"addr,omitempty"`       // set_member

	Key       string `json:"key,omitempty"` // kv_put, kv_delete
	Value     []byte `json:"value,omitempty"`
	Check     bool   `json:"check,omitempty"`
	ExpectRev uint64 `json:"expect_rev,omitempty"`
}

const (
	opBootstrap       = "bootstrap"
	opCreatePrincipal = "create_principal"
	opCreateProject   = "create_project"
	opSetQuota        = "set_quota"
	opGrant           = "grant"
	opRevoke          = "revoke"
	opCreateToken     = "create_token"
	opRevokeToken     = "revoke_token"
	opDeletePrincipal = "delete_principal"
	opDeleteProject   = "delete_project"
	opReserve         = "reserve"
	opRelease         = "release"
	opReleaseLeases   = "release_leases"
	opReconcileEdge   = "reconcile_edge"
	opReleaseUnbound  = "release_unbound"
	opAcquireLock     = "acquire_lock"
	opReleaseLock     = "release_lock"
	opRestore         = "restore"
	opSetMember       = "set_member"
	opDropMember      = "drop_member"
	opKVPut           = "kv_put"
	opKVDelete        = "kv_delete"
)

// Standalone mode persists these to the JSON file; quota ops are not
// persisted there (usage is rebuilt by reconcile), only in Raft.
var persistentOps = map[string]bool{
	opBootstrap: true, opCreatePrincipal: true, opCreateProject: true, opSetQuota: true, opGrant: true,
	opRevoke: true, opCreateToken: true, opRevokeToken: true, opDeletePrincipal: true, opDeleteProject: true,
	opRestore: true, opKVPut: true, opKVDelete: true,
}

type applyResult struct {
	V   any
	Err error
}

// propose applies c locally (standalone) or through Raft, returning the
// state machine's result.
func (m *IAM) propose(c *Command) (any, error) {
	if c.Now == 0 {
		c.Now = unix(m.now())
	}
	if m.raft == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		v, err := m.apply(c)
		if err == nil && persistentOps[c.Op] {
			if serr := m.saveLocked(); serr != nil {
				return nil, serr
			}
		}
		return v, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	f := m.raft.Apply(b, 10*time.Second)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) || errors.Is(err, raft.ErrLeadershipTransferInProgress) {
			return nil, rpcutil.Err(rpcutil.Unavailable, "iam: %v", err)
		}
		return nil, rpcutil.Err(rpcutil.Unavailable, "iam raft apply: %v", err)
	}
	r := f.Response().(applyResult)
	return r.V, r.Err
}

// apply executes c against the state; the caller holds m.mu. It must be
// deterministic: same state + same command => same result on every replica.
func (m *IAM) apply(c *Command) (any, error) {
	switch c.Op {
	case opBootstrap:
		return nil, m.bootstrapLocked(c)
	case opCreatePrincipal:
		return m.createPrincipalLocked(c)
	case opCreateProject:
		return m.createProjectLocked(c)
	case opSetQuota:
		return m.setQuotaLocked(c)
	case opGrant:
		return m.grantLocked(c)
	case opRevoke:
		return m.revokeLocked(c)
	case opCreateToken:
		return m.createTokenLocked(c)
	case opRevokeToken:
		return nil, m.revokeTokenLocked(c)
	case opDeletePrincipal:
		return nil, m.deletePrincipalLocked(c)
	case opDeleteProject:
		return nil, m.deleteProjectLocked(c)
	case opReserve:
		return nil, m.reserveLocked(c)
	case opRelease:
		return m.releaseFromLocked(c.Lease, c.Edge, c.Now), nil
	case opReleaseLeases:
		n := 0
		for _, l := range c.Leases {
			if m.releaseFromLocked(l, c.Edge, c.Now) {
				n++
			}
		}
		return n, nil
	case opReconcileEdge:
		return m.applyReconcileEdgeLocked(c), nil
	case opReleaseUnbound:
		return m.applyReleaseUnboundLocked(c), nil
	case opAcquireLock:
		return m.acquireLockLocked(c), nil
	case opReleaseLock:
		if l := m.locks[c.Name]; l != nil && l.Holder == c.Holder {
			delete(m.locks, c.Name)
		}
		return nil, nil
	case opRestore:
		return nil, m.restoreBackupLocked(c)
	case opSetMember:
		m.members[c.Name] = c.Addr
		return nil, nil
	case opDropMember:
		delete(m.members, c.Name)
		return nil, nil
	case opKVPut:
		return m.kvPutLocked(c)
	case opKVDelete:
		return nil, m.kvDeleteLocked(c)
	}
	return nil, fmt.Errorf("unknown iam command %q", c.Op)
}

// ---- token material (proposer side) -------------------------------------------------

var tidEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTokenMaterial returns a token id, its secret and the secret's hash.
func newTokenMaterial() (tid, secret, hash string) {
	var idb [8]byte
	var sec [24]byte
	rand.Read(idb[:])
	rand.Read(sec[:])
	tid = "t" + strings.ToLower(tidEnc.EncodeToString(idb[:]))
	// base64url may contain '-' and '_' but never '.', the token separator.
	secret = base64.RawURLEncoding.EncodeToString(sec[:])
	return tid, secret, hashSecret(secret)
}

// expiry turns a requested TTL into an absolute expiry, enforcing MaxTokenTTL.
func (m *IAM) expiry(ttl time.Duration) (float64, error) {
	if ttl < 0 {
		return 0, rpcutil.Err(rpcutil.Invalid, "ttl must be >= 0")
	}
	if m.MaxTokenTTL > 0 {
		if ttl == 0 {
			ttl = m.MaxTokenTTL
		} else if ttl > m.MaxTokenTTL {
			return 0, rpcutil.Err(rpcutil.Invalid, "ttl %v exceeds the maximum %v", ttl, m.MaxTokenTTL)
		}
	}
	if ttl == 0 {
		return 0, nil
	}
	return unix(m.now().Add(ttl)), nil
}

// ---- management: public API ------------------------------------------------------------

// Bootstrap creates the root project and its admin (idempotent) and returns
// the admin token. A provided token must look like "dsk.<adminID>.<secret>";
// without one a token is generated (standalone mode only).
func (m *IAM) Bootstrap(adminID, adminToken string, rootQuota map[string]float64) (string, error) {
	if adminToken == "" {
		if m.raft != nil {
			return "", fmt.Errorf("replicated IAM needs iam.admin_token in the config")
		}
		var sec [24]byte
		rand.Read(sec[:])
		adminToken = "dsk." + adminID + "." + base64.RawURLEncoding.EncodeToString(sec[:])
	}
	pid, tid, secret, ok := splitToken(adminToken)
	if !ok || pid != adminID || tid != "" {
		return "", fmt.Errorf("admin token must look like dsk.%s.<secret>", adminID)
	}
	// The permission list travels in the command: during a rolling upgrade,
	// replicas of different releases must still apply the same state.
	_, err := m.propose(&Command{Op: opBootstrap, Principal: adminID, Hash: hashSecret(secret), Quota: rootQuota,
		Perms: AllPermissions})
	return adminToken, err
}

// CreatePrincipal creates a principal with no permissions in project and
// issues its first token (lifetime ttl, 0 = server default).
func (m *IAM) CreatePrincipal(actor, project, id, kind string, ttl time.Duration) (string, *Token, error) {
	exp, err := m.expiry(ttl)
	if err != nil {
		return "", nil, err
	}
	tid, secret, hash := newTokenMaterial()
	v, err := m.propose(&Command{Op: opCreatePrincipal, Actor: actor, Project: project, Principal: id, Kind: kind,
		TokenID: tid, Hash: hash, ExpiresAt: exp, Desc: "initial"})
	if err != nil {
		return "", nil, err
	}
	return "dsk." + id + "." + tid + "." + secret, v.(*Token), nil
}

func (m *IAM) CreateProject(actor, parent, name string, quota map[string]float64) (*Project, error) {
	v, err := m.propose(&Command{Op: opCreateProject, Actor: actor, Parent: parent, Name: name, Quota: quota})
	if err != nil {
		return nil, err
	}
	return v.(*Project), nil
}

func (m *IAM) SetQuota(actor, project string, quota map[string]float64) (*Project, error) {
	v, err := m.propose(&Command{Op: opSetQuota, Actor: actor, Project: project, Quota: quota})
	if err != nil {
		return nil, err
	}
	return v.(*Project), nil
}

// Grant gives principal perms on project. The actor must hold project.admin
// and every granted permission there: nobody can grant what they do not hold.
func (m *IAM) Grant(actor, project, principal string, perms []string) (*Project, error) {
	v, err := m.propose(&Command{Op: opGrant, Actor: actor, Project: project, Principal: principal, Perms: perms})
	if err != nil {
		return nil, err
	}
	return v.(*Project), nil
}

func (m *IAM) Revoke(actor, project, principal string, perms []string) (*Project, error) {
	v, err := m.propose(&Command{Op: opRevoke, Actor: actor, Project: project, Principal: principal, Perms: perms})
	if err != nil {
		return nil, err
	}
	return v.(*Project), nil
}

// Reserve charges res to project and every ancestor, or fails without
// charging anything. Reserving an existing lease is a no-op (idempotent retry).
func (m *IAM) Reserve(lease, project string, res map[string]float64) error {
	return m.ReserveOn(lease, project, res, "")
}

// ReserveOn is Reserve with the lease bound to the edge chosen for the
// sandbox, so a crash of that edge releases it even before the first
// reconcile. Re-reserving on another edge (placement retry) moves the binding.
func (m *IAM) ReserveOn(lease, project string, res map[string]float64, edge string) error {
	return m.reserve(lease, project, res, edge, false)
}

// ReserveFresh is ReserveOn for the first attempt of a create: a lease
// already held is refused rather than rebound.
func (m *IAM) ReserveFresh(lease, project string, res map[string]float64, edge string) error {
	return m.reserve(lease, project, res, edge, true)
}

func (m *IAM) reserve(lease, project string, res map[string]float64, edge string, fresh bool) error {
	_, err := m.propose(&Command{Op: opReserve, Lease: lease, Project: project, Res: res, Edge: edge, Fresh: fresh})
	return err
}

// Release returns a lease's resources; false if it was not held (or the
// release could not be committed).
func (m *IAM) Release(lease string) bool {
	ok, err := m.ReleaseLease(lease, "")
	return err == nil && ok
}

// LeaseEdge reports whether lease is held, and the edge it is bound to.
func (m *IAM) LeaseEdge(lease string) (held bool, edge string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if r := m.reservations[lease]; r != nil {
		return true, r.Edge
	}
	return false, ""
}

// MaxReleaseLeases bounds the leases of one ReleaseLeases call (one Raft
// command).
const MaxReleaseLeases = 10000

// ReleaseLeases returns many leases in one command and reports how many
// were held. Releasing a lease twice is harmless. With edge, leases bound
// to another edge are kept (spec §36): a sandbox that edge created after
// its caller gave up, and placed it elsewhere, must not free the quota of
// the one that runs there.
func (m *IAM) ReleaseLeases(edge string, leases []string) (int, error) {
	if len(leases) > MaxReleaseLeases {
		return 0, rpcutil.Err(rpcutil.Invalid, "at most %d leases per release", MaxReleaseLeases)
	}
	if len(leases) == 0 {
		return 0, nil
	}
	v, err := m.propose(&Command{Op: opReleaseLeases, Leases: leases, Edge: edge})
	if err != nil {
		return 0, err
	}
	return v.(int), nil
}

// ReleaseLease is Release reporting commit failures (e.g. no Raft leader),
// and with edge as in ReleaseLeases.
func (m *IAM) ReleaseLease(lease, edge string) (bool, error) {
	v, err := m.propose(&Command{Op: opRelease, Lease: lease, Edge: edge})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

// ---- management: state machine -----------------------------------------------------------

func (m *IAM) bootstrapLocked(c *Command) error {
	root := m.projects["root"]
	if root == nil {
		root = &Project{Path: "root", Quota: map[string]float64{}, Policies: map[string][]string{}, CreatedBy: "bootstrap"}
		m.projects["root"] = root
	}
	for k, v := range c.Quota {
		root.Quota[k] = v
	}
	p := m.principals[c.Principal]
	if p == nil {
		p = &Principal{ID: c.Principal, Kind: "user", Project: "root", CreatedBy: "bootstrap", CreatedAt: c.Now}
		m.principals[c.Principal] = p
	}
	p.SecretHash = c.Hash
	perms := c.Perms
	if len(perms) == 0 { // proposed by a release from before the list was carried
		perms = AllPermissions
	}
	root.Policies[c.Principal] = append([]string(nil), perms...)
	sort.Strings(root.Policies[c.Principal])
	return nil
}

func (m *IAM) createPrincipalLocked(c *Command) (*Token, error) {
	if err := m.authorizeLocked(c.Actor, c.Project, ProjectAdmin); err != nil {
		return nil, err
	}
	id := c.Principal
	if id == "" || strings.ContainsAny(id, "./ ") {
		return nil, rpcutil.Err(rpcutil.Invalid, "principal id must be non-empty without '.', '/' or spaces")
	}
	if m.principals[id] != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "principal %q exists", id)
	}
	kind := c.Kind
	if kind == "" {
		kind = "agent"
	}
	m.principals[id] = &Principal{ID: id, Kind: kind, Project: c.Project, CreatedBy: c.Actor, CreatedAt: c.Now}
	t := &Token{ID: c.TokenID, Principal: id, Hash: c.Hash, CreatedAt: c.Now, ExpiresAt: c.ExpiresAt,
		Description: c.Desc, CreatedBy: c.Actor}
	m.tokens[t.ID] = t
	cp := *t
	return &cp, nil
}

func (m *IAM) createProjectLocked(c *Command) (*Project, error) {
	if err := m.authorizeLocked(c.Actor, c.Parent, ProjectAdmin); err != nil {
		return nil, err
	}
	if c.Name == "" || strings.ContainsAny(c.Name, "/ ") {
		return nil, rpcutil.Err(rpcutil.Invalid, "project name must be non-empty without '/' or spaces")
	}
	path := c.Parent + "/" + c.Name
	if m.projects[path] != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "project %q exists", path)
	}
	q, err := m.boundQuotaLocked(c.Parent, c.Quota)
	if err != nil {
		return nil, err
	}
	p := &Project{Path: path, Quota: q, Policies: map[string][]string{}, CreatedBy: c.Actor}
	m.projects[path] = p
	return p, nil
}

func (m *IAM) setQuotaLocked(c *Command) (*Project, error) {
	p := m.projects[c.Project]
	if p == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "project %q", c.Project)
	}
	parent := parentOf(c.Project)
	if parent == "" {
		return nil, rpcutil.Err(rpcutil.Forbidden, "root quota is set by operators")
	}
	if err := m.authorizeLocked(c.Actor, parent, ProjectAdmin); err != nil {
		return nil, err
	}
	q, err := m.boundQuotaLocked(parent, c.Quota)
	if err != nil {
		return nil, err
	}
	p.Quota = q
	return p, nil
}

// boundQuotaLocked enforces bounded delegation: unset keys inherit the
// tightest ancestor limit and no key may exceed any ancestor's.
func (m *IAM) boundQuotaLocked(parent string, quota map[string]float64) (map[string]float64, error) {
	out := map[string]float64{}
	for k, v := range quota {
		if !quotaKeys[k] {
			return nil, rpcutil.Err(rpcutil.Invalid, "unknown quota key %q", k)
		}
		if v < 0 {
			return nil, rpcutil.Err(rpcutil.Invalid, "quota %s must be >= 0", k)
		}
		out[k] = v
	}
	for _, a := range Ancestors(parent) {
		ks := make([]string, 0, len(m.projects[a].Quota))
		for k := range m.projects[a].Quota {
			ks = append(ks, k)
		}
		sort.Strings(ks) // deterministic error messages across replicas
		for _, k := range ks {
			limit := m.projects[a].Quota[k]
			v, set := out[k]
			if !set {
				out[k] = limit
			} else if v > limit {
				return nil, rpcutil.Err(rpcutil.QuotaExceeded, "%s=%g exceeds %s limit %g", k, v, a, limit)
			}
		}
	}
	return out, nil
}

func (m *IAM) grantLocked(c *Command) (*Project, error) {
	if err := m.authorizeLocked(c.Actor, c.Project, ProjectAdmin); err != nil {
		return nil, err
	}
	if m.principals[c.Principal] == nil {
		return nil, rpcutil.Err(rpcutil.NotFound, "principal %q", c.Principal)
	}
	held := m.effectiveLocked(c.Actor, c.Project)
	valid := map[string]bool{}
	for _, p := range AllPermissions {
		valid[p] = true
	}
	for _, p := range c.Perms {
		if !valid[p] {
			return nil, rpcutil.Err(rpcutil.Invalid, "unknown permission %q", p)
		}
		if !held[p] {
			return nil, rpcutil.Err(rpcutil.Forbidden, "cannot grant %q: actor does not hold it on %s", p, c.Project)
		}
	}
	proj := m.projects[c.Project]
	set := map[string]bool{}
	for _, p := range proj.Policies[c.Principal] {
		set[p] = true
	}
	for _, p := range c.Perms {
		set[p] = true
	}
	proj.Policies[c.Principal] = keys(set)
	return proj, nil
}

func (m *IAM) revokeLocked(c *Command) (*Project, error) {
	if err := m.authorizeLocked(c.Actor, c.Project, ProjectAdmin); err != nil {
		return nil, err
	}
	m.epoch++
	proj := m.projects[c.Project]
	if len(c.Perms) == 0 {
		delete(proj.Policies, c.Principal)
	} else {
		set := map[string]bool{}
		for _, p := range proj.Policies[c.Principal] {
			set[p] = true
		}
		for _, p := range c.Perms {
			delete(set, p)
		}
		proj.Policies[c.Principal] = keys(set)
	}
	return proj, nil
}

// ---- quota admission: state machine ----------------------------------------------------

func (m *IAM) reserveLocked(c *Command) error {
	if r := m.reservations[c.Lease]; r != nil {
		// A lease is an idempotency key: reusing it for another project or
		// other resources would run a sandbox the quota never charged.
		if c.Fresh || r.Project != c.Project || !sameRes(r.Res, c.Res) {
			return rpcutil.Err(rpcutil.Conflict, "lease %s is already in use", c.Lease)
		}
		if c.Edge != "" && r.Edge != c.Edge { // retried on another edge
			if r.Edge != "" {
				delete(m.byEdge[r.Edge], c.Lease)
			}
			m.bindLocked(c.Lease, c.Edge)
		}
		return nil
	}
	for _, a := range Ancestors(c.Project) {
		p := m.projects[a]
		if p == nil {
			return rpcutil.Err(rpcutil.NotFound, "project %q", a)
		}
		ks := make([]string, 0, len(c.Res))
		for k := range c.Res {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			v := c.Res[k]
			if limit, ok := p.Quota[k]; ok && p.usage[k]+v > limit+1e-9 {
				return rpcutil.Err(rpcutil.QuotaExceeded, "%s: %s %g+%g > %g", a, k, p.usage[k], v, limit)
			}
		}
	}
	m.addReservationLocked(&Reservation{Lease: c.Lease, Project: c.Project, Res: copyMap(c.Res), At: c.Now, Edge: c.Edge})
	return nil
}

func sameRes(a, b map[string]float64) bool {
	for k, v := range a {
		if math.Abs(b[k]-v) > 1e-9 {
			return false
		}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok && v != 0 {
			return false
		}
	}
	return true
}

// addReservationLocked records r and charges it (no quota check: used for
// admitted leases, adoption of live sandboxes and snapshot restore).
func (m *IAM) addReservationLocked(r *Reservation) {
	m.chargeLocked(Ancestors(r.Project), r.Res, 1)
	m.reservations[r.Lease] = r
	if r.Edge != "" {
		m.bindLocked(r.Lease, r.Edge)
	}
}

func (m *IAM) bindLocked(lease, edge string) {
	set := m.byEdge[edge]
	if set == nil {
		set = map[string]bool{}
		m.byEdge[edge] = set
	}
	set[lease] = true
	m.reservations[lease].Edge = edge
}

func (m *IAM) chargeLocked(chain []string, res map[string]float64, sign float64) {
	for _, a := range chain {
		p := m.projects[a]
		if p == nil {
			continue
		}
		if p.usage == nil {
			p.usage = map[string]float64{}
		}
		for k, v := range res {
			p.usage[k] += sign * v
			if p.usage[k] < 1e-9 {
				p.usage[k] = 0
			}
		}
	}
}

// releaseFromLocked is releaseLocked for a release by edge ("": anyone),
// which keeps a lease bound to another edge.
func (m *IAM) releaseFromLocked(lease, edge string, now float64) bool {
	if r := m.reservations[lease]; r != nil && edge != "" && r.Edge != "" && r.Edge != edge {
		return false
	}
	return m.releaseLocked(lease, now)
}

// releaseLocked ends lease at now (the command's time), adding its usage.
func (m *IAM) releaseLocked(lease string, now float64) bool {
	r := m.reservations[lease]
	if r == nil {
		return false
	}
	m.accrueLocked(r, now)
	delete(m.reservations, lease)
	if r.Edge != "" {
		delete(m.byEdge[r.Edge], lease)
	}
	m.chargeLocked(Ancestors(r.Project), r.Res, -1)
	return true
}

// ---- lease locks (leader election for other components, spec §16.1) ---------------------

// Lock is a named lease held by one holder until Expires (IAM clock).
type Lock struct {
	Name    string  `json:"name"`
	Holder  string  `json:"holder"`
	Expires float64 `json:"expires"`
}

// LockResult is the lock's state after an acquire attempt.
type LockResult struct {
	Lock     Lock
	Acquired bool
}

// AcquireLock grants or renews name to holder for ttl if it is free, expired
// or already held by holder; otherwise it reports the current holder.
func (m *IAM) AcquireLock(name, holder string, ttl time.Duration) (LockResult, error) {
	if name == "" || holder == "" || ttl <= 0 {
		return LockResult{}, rpcutil.Err(rpcutil.Invalid, "lock name, holder and a positive ttl are required")
	}
	v, err := m.propose(&Command{Op: opAcquireLock, Name: name, Holder: holder, TTL: ttl.Seconds()})
	if err != nil {
		return LockResult{}, err
	}
	return v.(LockResult), nil
}

// ReleaseLock frees name if holder holds it.
func (m *IAM) ReleaseLock(name, holder string) error {
	_, err := m.propose(&Command{Op: opReleaseLock, Name: name, Holder: holder})
	return err
}

func (m *IAM) acquireLockLocked(c *Command) LockResult {
	cur := m.locks[c.Name]
	if cur == nil || cur.Expires <= c.Now || cur.Holder == c.Holder {
		cur = &Lock{Name: c.Name, Holder: c.Holder, Expires: c.Now + c.TTL}
		m.locks[c.Name] = cur
		return LockResult{Lock: *cur, Acquired: true}
	}
	return LockResult{Lock: *cur}
}
