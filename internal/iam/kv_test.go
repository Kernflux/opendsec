package iam

import (
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"testing"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

func TestKVPutGetListDelete(t *testing.T) {
	m, _ := setup(t)
	if _, err := m.KVPut("other/x", []byte("v"), false, 0); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("key outside the allowed prefixes: %v", err)
	}
	if _, err := m.KVPut("fleet/big", make([]byte, maxKVValue+1), false, 0); rpcutil.Reason(err) != rpcutil.Invalid {
		t.Fatalf("oversized value: %v", err)
	}
	a, err := m.KVPut("fleet/node/a", []byte("1"), true, 0) // create only
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.KVPut("fleet/node/a", []byte("x"), true, 0); rpcutil.Reason(err) != rpcutil.Conflict {
		t.Fatalf("create of an existing key: %v", err)
	}
	a2, err := m.KVPut("fleet/node/a", []byte("2"), true, a.Rev)
	if err != nil || a2.Rev <= a.Rev {
		t.Fatalf("update at the current revision: %v %v", a2, err)
	}
	if _, err := m.KVPut("fleet/node/a", []byte("3"), true, a.Rev); rpcutil.Reason(err) != rpcutil.Conflict {
		t.Fatalf("update at a stale revision: %v", err)
	}
	m.KVPut("fleet/node/b", []byte("b"), false, 0)
	m.KVPut("fleet/release/1", []byte("r"), false, 0)
	l := m.KVList("fleet/node/", false)
	if len(l) != 2 || l[0].Key != "fleet/node/a" || string(l[0].Value) != "2" || l[1].Key != "fleet/node/b" {
		t.Fatalf("list: %+v", l)
	}
	if l := m.KVList("fleet/", true); len(l) != 3 || l[0].Value != nil {
		t.Fatalf("keys only: %+v", l)
	}
	if err := m.KVDelete("fleet/node/a", true, a.Rev); rpcutil.Reason(err) != rpcutil.Conflict {
		t.Fatalf("delete at a stale revision: %v", err)
	}
	if err := m.KVDelete("fleet/node/a", true, a2.Rev); err != nil {
		t.Fatal(err)
	}
	if m.KVGet("fleet/node/a") != nil {
		t.Fatal("deleted key still there")
	}
}

// TestKVPersistsAndBacksUp: standalone state keeps the area across a
// restart; a format-2 backup carries it, with fresh revisions on restore; a
// format-1 backup leaves the current area alone.
func TestKVPersistsAndBacksUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Bootstrap("admin", "", nil)
	e, _ := m.KVPut("fleet/node/a", []byte("old"), false, 0)
	again, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if g := again.KVGet("fleet/node/a"); g == nil || string(g.Value) != "old" || g.Rev != e.Rev {
		t.Fatalf("after restart: %+v", g)
	}

	b, err := m.Backup("admin")
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := m.KVPut("fleet/node/a", []byte("new"), false, 0)
	m.KVPut("fleet/node/later", []byte("x"), false, 0)
	if err := m.Restore("admin", b); err != nil {
		t.Fatal(err)
	}
	g := m.KVGet("fleet/node/a")
	if g == nil || string(g.Value) != "old" || g.Rev <= cur.Rev {
		t.Fatalf("restored entry %+v: want the backup's value at a revision past %d", g, cur.Rev)
	}
	if m.KVGet("fleet/node/later") != nil {
		t.Fatal("a key written after the backup survived its restore")
	}

	v1 := rewriteFormat(t, b, backupFormatV1)
	m.KVPut("fleet/node/a", []byte("kept"), false, 0)
	if err := m.Restore("admin", v1); err != nil {
		t.Fatal(err)
	}
	if g := m.KVGet("fleet/node/a"); g == nil || string(g.Value) != "kept" {
		t.Fatalf("a format-1 restore changed the key-value area: %+v", g)
	}
}

func rewriteFormat(t *testing.T, b []byte, format string) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(r)
	raw = bytes.Replace(raw, []byte(`"`+BackupFormat+`"`), []byte(`"`+format+`"`), 1)
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(raw)
	w.Close()
	return z.Bytes()
}

// TestKVReplicated: writes through the leader reach every replica with the
// same revisions, and survive a Raft snapshot and restart.
func TestKVReplicated(t *testing.T) {
	rs := startReplicas(t, 3, "")
	var e *KVEntry
	if err := rs.onLeader(func(m *IAM) (err error) {
		if _, err := m.Bootstrap("admin", "dsk.admin.secret", nil); err != nil {
			return err
		}
		e, err = m.KVPut("fleet/node/a", []byte("1"), true, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rs.converged()
	for i, m := range rs.nodes {
		if g := m.KVGet("fleet/node/a"); g == nil || g.Rev != e.Rev || string(g.Value) != "1" {
			t.Fatalf("replica %d: %+v", i, g)
		}
	}
	li, lead := rs.leader()
	if err := lead.raft.Snapshot().Error(); err != nil {
		t.Fatal(err)
	}
	follower := (li + 1) % 3
	rs.nodes[follower].Shutdown()
	rs.nodes[follower] = rs.start(follower)
	rs.converged()
	if g := rs.nodes[follower].KVGet("fleet/node/a"); g == nil || g.Rev != e.Rev {
		t.Fatalf("restarted replica: %+v", g)
	}
}
