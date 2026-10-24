package iam

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"go.etcd.io/bbolt"

	"github.com/kernflux/opendsec/internal/pki"
)

// Peer is one IAM replica as seen by Raft.
type Peer struct {
	ID       string
	RaftAddr string
}

type RaftOptions struct {
	ID       string
	RaftAddr string
	DataDir  string
	Peers    []Peer        // full membership, including this replica
	TLS      *pki.Material // nil: plaintext replication (dev only)
	LogLevel string        // hclog level for Raft's own logging; default "warn"
	// Join: a replica without Raft state waits to be added to a running
	// cluster (AddMember) instead of bootstrapping one (spec §27.2).
	Join bool
}

// NewReplicated starts an IAM replica whose state is replicated with Raft
// (spec §15.1). A replica without existing Raft state bootstraps the cluster
// with the full peer list; every replica can do so safely with the same list.
func NewReplicated(opt RaftOptions) (*IAM, error) {
	if err := os.MkdirAll(opt.DataDir, 0o700); err != nil {
		return nil, err
	}
	m := newEmpty()
	level := opt.LogLevel
	if level == "" {
		level = "warn"
	}
	logger := hclog.New(&hclog.LoggerOptions{Name: "iam-raft-" + opt.ID, Level: hclog.LevelFromString(level), Output: os.Stderr})

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(opt.ID)
	conf.Logger = logger
	// Small, local clusters: detect a dead leader within ~1s.
	conf.HeartbeatTimeout = 500 * time.Millisecond
	conf.ElectionTimeout = 500 * time.Millisecond
	conf.LeaderLeaseTimeout = 250 * time.Millisecond
	conf.CommitTimeout = 5 * time.Millisecond
	conf.BatchApplyCh = true
	conf.SnapshotThreshold = 8192
	conf.SnapshotInterval = 30 * time.Second

	// A timeout, so a second process on the same data dir fails instead of
	// blocking forever on BoltDB's file lock.
	store, err := raftboltdb.New(raftboltdb.Options{
		Path: filepath.Join(opt.DataDir, "raft.db"), BoltOptions: &bbolt.Options{Timeout: 5 * time.Second}})
	if err != nil {
		return nil, fmt.Errorf("raft store: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStoreWithLogger(opt.DataDir, 2, logger)
	if err != nil {
		return nil, fmt.Errorf("raft snapshots: %w", err)
	}
	var trans raft.Transport
	if opt.TLS != nil {
		sl, err := newTLSStream(opt.RaftAddr, opt.TLS)
		if err != nil {
			return nil, err
		}
		trans = raft.NewNetworkTransportWithLogger(sl, 3, 10*time.Second, logger)
	} else {
		addr, err := net.ResolveTCPAddr("tcp", opt.RaftAddr)
		if err != nil {
			return nil, err
		}
		trans, err = raft.NewTCPTransportWithLogger(opt.RaftAddr, addr, 3, 10*time.Second, logger)
		if err != nil {
			return nil, err
		}
	}
	r, err := raft.NewRaft(conf, (*fsm)(m), store, store, snaps, trans)
	if err != nil {
		return nil, err
	}
	has, err := raft.HasExistingState(store, store, snaps)
	if err != nil {
		return nil, err
	}
	if !has && !opt.Join {
		var servers []raft.Server
		for _, p := range opt.Peers {
			servers = append(servers, raft.Server{ID: raft.ServerID(p.ID), Address: raft.ServerAddress(p.RaftAddr)})
		}
		if err := r.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
			return nil, fmt.Errorf("bootstrap raft: %w", err)
		}
	}
	m.raft = r
	m.closeStore = store.Close
	return m, nil
}

// IsLeader reports whether this replica is the Raft leader (standalone: always).
func (m *IAM) IsLeader() bool { return m.raft == nil || m.raft.State() == raft.Leader }

// LeaderID returns the id of the current leader replica ("" if unknown).
func (m *IAM) LeaderID() string {
	if m.raft == nil {
		return ""
	}
	_, id := m.raft.LeaderWithID()
	return string(id)
}

// LeaderCh notifies leadership changes of this replica (nil in standalone mode).
func (m *IAM) LeaderCh() <-chan bool {
	if m.raft == nil {
		return nil
	}
	return m.raft.LeaderCh()
}

// Shutdown stops Raft (no-op in standalone mode).
func (m *IAM) Shutdown() error {
	if m.raft == nil {
		return nil
	}
	err := m.raft.Shutdown().Error()
	if m.closeStore != nil {
		m.closeStore() // raft.Shutdown leaves the log store (and its file lock) open
	}
	return err
}

// AppliedIndex is the last Raft log index applied locally (tests).
func (m *IAM) AppliedIndex() uint64 {
	if m.raft == nil {
		return 0
	}
	return m.raft.AppliedIndex()
}

// ---- state machine adapter ---------------------------------------------------------------

type fsm IAM

func (f *fsm) Apply(l *raft.Log) any {
	m := (*IAM)(f)
	var c Command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return applyResult{Err: fmt.Errorf("decode iam command: %w", err)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, err := m.apply(&c)
	return applyResult{V: v, Err: err}
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	m := (*IAM)(f)
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, err := json.Marshal(m.stateLocked(true))
	if err != nil {
		return nil, err
	}
	return snapshot(b), nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var s state
	if err := json.NewDecoder(rc).Decode(&s); err != nil {
		return err
	}
	m := (*IAM)(f)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoreLocked(&s)
	return nil
}

type snapshot []byte

func (s snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (snapshot) Release() {}

// ---- mTLS transport for replication ------------------------------------------------------

// tlsStream is a Raft stream layer that only talks to iam/* identities.
type tlsStream struct {
	net.Listener
	m *pki.Material
}

func requireIAM(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("raft: peer presented no certificate")
	}
	id, err := pki.FromCert(cs.PeerCertificates[0])
	if err != nil {
		return err
	}
	if id.Role != pki.RoleIAM {
		return fmt.Errorf("raft: peer %s is not an IAM replica", id)
	}
	return nil
}

func newTLSStream(addr string, m *pki.Material) (*tlsStream, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := m.ServerConfig()
	cfg.VerifyConnection = requireIAM
	return &tlsStream{Listener: tls.NewListener(ln, cfg), m: m}, nil
}

func (s *tlsStream) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	cfg := s.m.ClientConfig(nil)
	cfg.VerifyConnection = requireIAM
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(addr), cfg)
}
