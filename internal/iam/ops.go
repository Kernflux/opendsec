package iam

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"maps"
	"sort"
	"time"

	"github.com/hashicorp/raft"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// ---- backup and restore (spec §27.2) ------------------------------------------------

// BackupFormat names the layout of a backup, checked on restore. Format 2
// adds the key-value area (spec §28.3).
const BackupFormat = "opendsec-iam-backup/2"

// Older layouts, without the key-value area: restoring one keeps the current
// key-value area, which they never contained. legacyBackupFormat is from
// before the rename to OpenDsec, so a backup taken by the old release
// restores into the renamed cluster.
const (
	backupFormatV1     = "opendsec-iam-backup/1"
	legacyBackupFormat = "dsec-iam-backup/1"
)

type backup struct {
	Format  string  `json:"format"`
	TakenAt float64 `json:"taken_at"`
	State   *state  `json:"state"`
}

// Backup returns the IAM state as gzipped JSON: principals, projects with
// their quotas and policies, tokens (hashes, never secrets) and the security
// epoch, and the key-value area. Quota leases and locks are left out: they
// describe running sandboxes and components, which reconcile and election
// rebuild.
func (m *IAM) Backup(actor string) ([]byte, error) {
	m.mu.RLock()
	if err := m.authorizeLocked(actor, "root", ProjectAdmin); err != nil {
		m.mu.RUnlock()
		return nil, err
	}
	b, err := json.Marshal(&backup{Format: BackupFormat, TakenAt: unix(m.now()), State: m.stateLocked(false)})
	m.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(b)
	if err := w.Close(); err != nil {
		return nil, err
	}
	return z.Bytes(), nil
}

// Restore replaces principals, projects and tokens with those of a backup
// (as Backup wrote it). Leases of running sandboxes are kept where their
// project still exists; the security epoch moves past both, so every
// apiserver drops its auth caches.
func (m *IAM) Restore(actor string, data []byte) error {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return rpcutil.Err(rpcutil.Invalid, "backup: %v", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return rpcutil.Err(rpcutil.Invalid, "backup: %v", err)
	}
	var b backup
	if err := json.Unmarshal(raw, &b); err != nil {
		return rpcutil.Err(rpcutil.Invalid, "backup: %v", err)
	}
	if (b.Format != BackupFormat && b.Format != backupFormatV1 && b.Format != legacyBackupFormat) || b.State == nil {
		return rpcutil.Err(rpcutil.Invalid, "backup: format %q, want %q", b.Format, BackupFormat)
	}
	root := false
	for _, p := range b.State.Projects {
		root = root || p.Path == "root"
	}
	if !root {
		return rpcutil.Err(rpcutil.Invalid, "backup has no root project")
	}
	_, err = m.propose(&Command{Op: opRestore, Actor: actor, State: b.State, ReplaceKV: b.Format == BackupFormat})
	return err
}

func (m *IAM) restoreBackupLocked(c *Command) error {
	if err := m.authorizeLocked(c.Actor, "root", ProjectAdmin); err != nil {
		return err
	}
	s := *c.State
	s.Reservations, s.Locks = nil, nil
	exists := map[string]bool{}
	for _, p := range s.Projects {
		exists[p.Path] = true
	}
	for _, r := range m.reservations {
		if exists[r.Project] {
			s.Reservations = append(s.Reservations, r)
		}
	}
	sort.Slice(s.Reservations, func(i, j int) bool { return s.Reservations[i].Lease < s.Reservations[j].Lease })
	for _, l := range m.locks {
		s.Locks = append(s.Locks, l)
	}
	s.Members = maps.Clone(m.members)
	s.Epoch = max(s.Epoch, m.epoch) + 1
	if !c.ReplaceKV {
		s.KV, s.KVRev = nil, m.kvRev
		for _, e := range m.kv {
			s.KV = append(s.KV, e)
		}
		sort.Slice(s.KV, func(i, j int) bool { return s.KV[i].Key < s.KV[j].Key })
	}
	s.KVRev = max(s.KVRev, m.kvRev)
	if c.ReplaceKV { // fresh revisions: a writer holding one read before the restore must conflict
		sort.Slice(s.KV, func(i, j int) bool { return s.KV[i].Key < s.KV[j].Key })
		for i, e := range s.KV {
			cp := *e
			s.KVRev++
			cp.Rev = s.KVRev
			s.KV[i] = &cp
		}
	}
	m.restoreLocked(&s)
	return nil
}

// ---- Raft membership (spec §27.2) --------------------------------------------------------

// Member is one IAM replica in the Raft configuration.
type Member struct {
	ID, RaftAddr, Addr string
	Leader, Voter      bool
}

// SetConfigAddrs records the gRPC addresses of the replicas in the cluster
// config; replicas added later are known by the address given to AddMember.
func (m *IAM) SetConfigAddrs(addrs map[string]string) {
	m.mu.Lock()
	m.configAddrs = maps.Clone(addrs)
	m.mu.Unlock()
}

// MemberAddr returns the gRPC address of replica id ("" if unknown).
func (m *IAM) MemberAddr(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a := m.members[id]; a != "" {
		return a
	}
	return m.configAddrs[id]
}

// Replicated reports whether this IAM runs Raft.
func (m *IAM) Replicated() bool { return m.raft != nil }

// Members lists the Raft configuration as this replica knows it.
func (m *IAM) Members(actor string) ([]Member, error) {
	if err := m.Authorize(actor, "root", ProjectAdmin); err != nil {
		return nil, err
	}
	if m.raft == nil {
		return nil, nil
	}
	f := m.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "iam: %v", err)
	}
	_, leader := m.raft.LeaderWithID()
	var out []Member
	for _, s := range f.Configuration().Servers {
		out = append(out, Member{ID: string(s.ID), RaftAddr: string(s.Address), Addr: m.MemberAddr(string(s.ID)),
			Leader: s.ID == leader, Voter: s.Suffrage == raft.Voter})
	}
	return out, nil
}

// membershipTimeout bounds a configuration change; a new replica catches up
// from a snapshot in the background, after the change is committed.
const membershipTimeout = 30 * time.Second

// AddMember adds a voting replica (on the leader). The replica must be
// running with -join (no bootstrap of its own) or already hold this
// cluster's state.
func (m *IAM) AddMember(actor, id, raftAddr, addr string) error {
	if err := m.membershipCheck(actor); err != nil {
		return err
	}
	if id == "" || raftAddr == "" || addr == "" {
		return rpcutil.Err(rpcutil.Invalid, "a new replica needs id, raft_addr and addr")
	}
	if _, err := m.propose(&Command{Op: opSetMember, Name: id, Addr: addr}); err != nil {
		return err
	}
	if err := m.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(raftAddr), 0, membershipTimeout).Error(); err != nil {
		return rpcutil.Err(rpcutil.Unavailable, "iam: add replica %s: %v", id, err)
	}
	return nil
}

// RemoveMember removes a replica (on the leader), e.g. one whose node is
// gone; removing the leader itself makes another replica lead.
func (m *IAM) RemoveMember(actor, id string) error {
	if err := m.membershipCheck(actor); err != nil {
		return err
	}
	f := m.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return rpcutil.Err(rpcutil.Unavailable, "iam: %v", err)
	}
	found := false
	for _, s := range f.Configuration().Servers {
		found = found || string(s.ID) == id
	}
	if !found {
		return rpcutil.Err(rpcutil.NotFound, "iam replica %q", id)
	}
	if len(f.Configuration().Servers) == 1 {
		return rpcutil.Err(rpcutil.Invalid, "cannot remove the last iam replica")
	}
	if _, err := m.propose(&Command{Op: opDropMember, Name: id}); err != nil {
		return err
	}
	if err := m.raft.RemoveServer(raft.ServerID(id), 0, membershipTimeout).Error(); err != nil {
		return rpcutil.Err(rpcutil.Unavailable, "iam: remove replica %s: %v", id, err)
	}
	return nil
}

func (m *IAM) membershipCheck(actor string) error {
	if err := m.Authorize(actor, "root", ProjectAdmin); err != nil {
		return err
	}
	if m.raft == nil {
		return rpcutil.Err(rpcutil.Invalid, "iam is not replicated: membership is set in the config")
	}
	return nil
}
