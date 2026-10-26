package iam

import (
	"sort"
	"strings"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// ---- key-value area (spec §28.3) -----------------------------------------------------
//
// Other components keep small durable state here (the fleet service's nodes,
// releases and rollouts), replicated and backed up with the rest of IAM.
// IAM never interprets the values. Every write gets the next revision of a
// counter that is part of the state, so all replicas agree on revisions.

// KVPrefixes are the key prefixes the area accepts.
var KVPrefixes = []string{"fleet/"}

const (
	maxKVKey   = 256
	maxKVValue = 256 << 10
)

// KVEntry is one key with its value and the revision of its last write.
type KVEntry struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
	Rev   uint64 `json:"rev"`
}

func checkKVKey(key string) error {
	if key == "" || len(key) > maxKVKey || strings.ContainsAny(key, " \n") {
		return rpcutil.Err(rpcutil.Invalid, "bad key %q", key)
	}
	for _, p := range KVPrefixes {
		if strings.HasPrefix(key, p) {
			return nil
		}
	}
	return rpcutil.Err(rpcutil.Invalid, "key %q: allowed prefixes are %v", key, KVPrefixes)
}

// KVGet returns the entry for key (nil if absent).
func (m *IAM) KVGet(key string) *KVEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e := m.kv[key]; e != nil {
		cp := *e
		return &cp
	}
	return nil
}

// KVList returns the entries whose key starts with prefix, sorted by key.
func (m *IAM) KVList(prefix string, keysOnly bool) []*KVEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*KVEntry
	for k, e := range m.kv {
		if strings.HasPrefix(k, prefix) {
			cp := *e
			if keysOnly {
				cp.Value = nil
			}
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// KVPut writes key. With check, it applies only if the key's revision is
// expectRev (0: the key must not exist), else it fails with Conflict.
func (m *IAM) KVPut(key string, value []byte, check bool, expectRev uint64) (*KVEntry, error) {
	return m.KVPutFenced(key, value, check, expectRev, nil)
}

// KVPutFenced is KVPut applied only while f's holder holds its lock.
func (m *IAM) KVPutFenced(key string, value []byte, check bool, expectRev uint64, f *Fence) (*KVEntry, error) {
	if err := checkKVKey(key); err != nil {
		return nil, err
	}
	if len(value) > maxKVValue {
		return nil, rpcutil.Err(rpcutil.Invalid, "value of %s is %d bytes, the limit is %d", key, len(value), maxKVValue)
	}
	v, err := m.propose((&Command{Op: opKVPut, Key: key, Value: value, Check: check, ExpectRev: expectRev}).fence(f))
	if err != nil {
		return nil, err
	}
	return v.(*KVEntry), nil
}

// KVDelete removes key (no-op if absent, unless check requires a revision).
func (m *IAM) KVDelete(key string, check bool, expectRev uint64) error {
	return m.KVDeleteFenced(key, check, expectRev, nil)
}

// KVDeleteFenced is KVDelete applied only while f's holder holds its lock.
func (m *IAM) KVDeleteFenced(key string, check bool, expectRev uint64, f *Fence) error {
	if err := checkKVKey(key); err != nil {
		return err
	}
	_, err := m.propose((&Command{Op: opKVDelete, Key: key, Check: check, ExpectRev: expectRev}).fence(f))
	return err
}

func (m *IAM) kvCheckLocked(c *Command) error {
	if !c.Check {
		return nil
	}
	var cur uint64
	if e := m.kv[c.Key]; e != nil {
		cur = e.Rev
	}
	if cur != c.ExpectRev {
		return rpcutil.Err(rpcutil.Conflict, "%s is at revision %d, not %d", c.Key, cur, c.ExpectRev)
	}
	return nil
}

func (m *IAM) kvPutLocked(c *Command) (*KVEntry, error) {
	if err := m.kvCheckLocked(c); err != nil {
		return nil, err
	}
	m.kvRev++
	e := &KVEntry{Key: c.Key, Value: append([]byte(nil), c.Value...), Rev: m.kvRev}
	m.kv[c.Key] = e
	cp := *e
	return &cp, nil
}

func (m *IAM) kvDeleteLocked(c *Command) error {
	if err := m.kvCheckLocked(c); err != nil {
		return err
	}
	if m.kv[c.Key] != nil {
		m.kvRev++
		delete(m.kv, c.Key)
	}
	return nil
}
