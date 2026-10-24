// Package fleet is the cluster management service (spec §28): it keeps the
// desired state of every machine, hands operations to the node agents and
// drives rollouts batch by batch. Durable state lives in the IAM key-value
// area; heartbeats are soft state held by the leader replica.
package fleet

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// KV is the IAM key-value area (spec §28.3).
type KV interface {
	Get(ctx context.Context, key string) (*pb.KVEntry, error) // Rev 0: absent
	List(ctx context.Context, prefix string) ([]*pb.KVEntry, error)
	Put(ctx context.Context, key string, value []byte, check bool, rev uint64) (*pb.KVEntry, error)
	Delete(ctx context.Context, key string, check bool, rev uint64) error
}

// IAMKV is KV over the IAM gRPC service.
type IAMKV struct{ C pb.IAMClient }

func (k IAMKV) Get(ctx context.Context, key string) (*pb.KVEntry, error) {
	return k.C.KVGet(ctx, &pb.KVGetRequest{Key: key})
}

func (k IAMKV) List(ctx context.Context, prefix string) ([]*pb.KVEntry, error) {
	r, err := k.C.KVList(ctx, &pb.KVListRequest{Prefix: prefix})
	if err != nil {
		return nil, err
	}
	return r.Entries, nil
}

func (k IAMKV) Put(ctx context.Context, key string, value []byte, check bool, rev uint64) (*pb.KVEntry, error) {
	return k.C.KVPut(ctx, &pb.KVPutRequest{Key: key, Value: value, Check: check, ExpectRev: rev})
}

func (k IAMKV) Delete(ctx context.Context, key string, check bool, rev uint64) error {
	_, err := k.C.KVDelete(ctx, &pb.KVDeleteRequest{Key: key, Check: check, ExpectRev: rev})
	return err
}

// Key layout.
const (
	pNode    = "fleet/node/"
	pRelease = "fleet/release/"
	pConfig  = "fleet/config/"
	pRollout = "fleet/rollout/"
	pStep    = "fleet/step/" // fleet/step/<rollout>/<node>
)

func configKey(gen uint64) string { return fmt.Sprintf("%s%020d", pConfig, gen) }
func stepKey(rollout, node string) string {
	return pStep + rollout + "/" + node
}

// Store reads and writes the fleet's records. Each record remembers the
// revision it was read at, so a write that raced another fails with
// Conflict instead of losing it.
type Store struct{ kv KV }

func NewStore(kv KV) *Store { return &Store{kv: kv} }

type rec[T proto.Message] struct {
	V   T
	Rev uint64
}

func get[T proto.Message](ctx context.Context, s *Store, key string, mk func() T) (rec[T], bool, error) {
	e, err := s.kv.Get(ctx, key)
	if err != nil {
		return rec[T]{}, false, err
	}
	if e.Rev == 0 {
		return rec[T]{V: mk()}, false, nil
	}
	v := mk()
	if err := proto.Unmarshal(e.Value, v); err != nil {
		return rec[T]{}, false, fmt.Errorf("%s: %w", key, err)
	}
	return rec[T]{V: v, Rev: e.Rev}, true, nil
}

func list[T proto.Message](ctx context.Context, s *Store, prefix string, mk func() T) ([]rec[T], error) {
	es, err := s.kv.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]rec[T], 0, len(es))
	for _, e := range es {
		v := mk()
		if err := proto.Unmarshal(e.Value, v); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Key, err)
		}
		out = append(out, rec[T]{V: v, Rev: e.Rev})
	}
	return out, nil
}

// put writes v at key if it is still at rev (0: must not exist).
func put(ctx context.Context, s *Store, key string, v proto.Message, rev uint64) (uint64, error) {
	b, err := proto.Marshal(v)
	if err != nil {
		return 0, err
	}
	e, err := s.kv.Put(ctx, key, b, true, rev)
	if err != nil {
		return 0, err
	}
	return e.Rev, nil
}

func newNode() *pb.FleetNode       { return &pb.FleetNode{} }
func newRelease() *pb.FleetRelease { return &pb.FleetRelease{} }
func newConfig() *pb.FleetConfig   { return &pb.FleetConfig{} }
func newRollout() *pb.FleetRollout { return &pb.FleetRollout{} }
func newStep() *pb.FleetStep       { return &pb.FleetStep{} }

func (s *Store) Node(ctx context.Context, name string) (rec[*pb.FleetNode], bool, error) {
	return get(ctx, s, pNode+name, newNode)
}

func (s *Store) Nodes(ctx context.Context) ([]rec[*pb.FleetNode], error) {
	return list(ctx, s, pNode, newNode)
}

// PutNode stores n (without its soft status).
func (s *Store) PutNode(ctx context.Context, n *pb.FleetNode, rev uint64) (uint64, error) {
	c := proto.Clone(n).(*pb.FleetNode)
	c.Status = nil
	return put(ctx, s, pNode+n.Name, c, rev)
}

// UpdateNode applies f to the stored node, retrying on conflicts.
func (s *Store) UpdateNode(ctx context.Context, name string, f func(n *pb.FleetNode) error) (*pb.FleetNode, error) {
	for try := 0; ; try++ {
		r, ok, err := s.Node(ctx, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, rpcutil.Err(rpcutil.NotFound, "node %q", name)
		}
		if err := f(r.V); err != nil {
			return nil, err
		}
		if _, err := s.PutNode(ctx, r.V, r.Rev); rpcutil.Reason(err) == rpcutil.Conflict && try < 10 {
			continue
		} else if err != nil {
			return nil, err
		}
		return r.V, nil
	}
}

func (s *Store) Release(ctx context.Context, version string) (rec[*pb.FleetRelease], bool, error) {
	return get(ctx, s, pRelease+version, newRelease)
}

func (s *Store) Releases(ctx context.Context) ([]rec[*pb.FleetRelease], error) {
	return list(ctx, s, pRelease, newRelease)
}

func (s *Store) PutRelease(ctx context.Context, r *pb.FleetRelease, rev uint64) (uint64, error) {
	return put(ctx, s, pRelease+r.Version, r, rev)
}

func (s *Store) DeleteRelease(ctx context.Context, version string) error {
	return s.kv.Delete(ctx, pRelease+version, false, 0)
}

// Config returns generation gen, or the latest with gen 0.
func (s *Store) Config(ctx context.Context, gen uint64) (*pb.FleetConfig, bool, error) {
	if gen != 0 {
		r, ok, err := get(ctx, s, configKey(gen), newConfig)
		return r.V, ok, err
	}
	cs, err := list(ctx, s, pConfig, newConfig)
	if err != nil || len(cs) == 0 {
		return &pb.FleetConfig{}, false, err
	}
	return cs[len(cs)-1].V, true, nil // keys sort by generation
}

// AddConfig stores c as the generation after the latest.
func (s *Store) AddConfig(ctx context.Context, c *pb.FleetConfig) (*pb.FleetConfig, error) {
	for try := 0; ; try++ {
		last, _, err := s.Config(ctx, 0)
		if err != nil {
			return nil, err
		}
		c.Gen = last.Gen + 1
		if _, err := put(ctx, s, configKey(c.Gen), c, 0); rpcutil.Reason(err) == rpcutil.Conflict && try < 10 {
			continue
		} else if err != nil {
			return nil, err
		}
		return c, nil
	}
}

func (s *Store) Rollout(ctx context.Context, id string) (rec[*pb.FleetRollout], bool, error) {
	return get(ctx, s, pRollout+id, newRollout)
}

// Rollouts returns every rollout, newest first.
func (s *Store) Rollouts(ctx context.Context) ([]rec[*pb.FleetRollout], error) {
	rs, err := list(ctx, s, pRollout, newRollout)
	if err != nil {
		return nil, err
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].V.Id > rs[j].V.Id })
	return rs, nil
}

func (s *Store) PutRollout(ctx context.Context, r *pb.FleetRollout, rev uint64) (uint64, error) {
	c := proto.Clone(r).(*pb.FleetRollout)
	c.Steps, c.Phases = nil, nil
	return put(ctx, s, pRollout+r.Id, c, rev)
}

func (s *Store) Steps(ctx context.Context, rollout string) ([]rec[*pb.FleetStep], error) {
	return list(ctx, s, pStep+rollout+"/", newStep)
}

func (s *Store) PutStep(ctx context.Context, rollout string, st *pb.FleetStep, rev uint64) (uint64, error) {
	return put(ctx, s, stepKey(rollout, st.Node), st, rev)
}

// rolloutID returns ids that sort by creation: r<seconds><counter>.
func rolloutID(now float64, n int) string {
	return "r" + strconv.FormatInt(int64(now), 10) + fmt.Sprintf("%03d", n%1000)
}

// validName reports whether s is a node name: [a-z0-9-]{1,32}.
func validName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
