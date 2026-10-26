package iam

import (
	"context"
	"strings"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Key-value area over gRPC (spec §28.3). Reads are forwarded to the leader
// like writes, so a caller always sees its own and everyone's committed writes.

func kvPB(e *KVEntry) *pb.KVEntry {
	return &pb.KVEntry{Key: e.Key, Value: e.Value, Rev: e.Rev}
}

func (s *Service) KVGet(ctx context.Context, r *pb.KVGetRequest) (*pb.KVEntry, error) {
	if err := kvScope(ctx, r.Key); err != nil {
		return nil, err
	}
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVGet(ctx, r)
	}
	if e := s.IAM.KVGet(r.Key); e != nil {
		return kvPB(e), nil
	}
	return &pb.KVEntry{Key: r.Key}, nil
}

func (s *Service) KVList(ctx context.Context, r *pb.KVListRequest) (*pb.KVEntries, error) {
	if err := kvScope(ctx, r.Prefix); err != nil {
		return nil, err
	}
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVList(ctx, r)
	}
	out := &pb.KVEntries{}
	for _, e := range s.IAM.KVList(r.Prefix, r.KeysOnly) {
		out.Entries = append(out.Entries, kvPB(e))
	}
	return out, nil
}

func (s *Service) KVPut(ctx context.Context, r *pb.KVPutRequest) (*pb.KVEntry, error) {
	if err := kvScope(ctx, r.Key); err != nil {
		return nil, err
	}
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVPut(ctx, r)
	}
	e, err := s.IAM.KVPutFenced(r.Key, r.Value, r.Check, r.ExpectRev, fenceOf(r.Fence))
	if err != nil {
		return nil, err
	}
	return kvPB(e), nil
}

func (s *Service) KVDelete(ctx context.Context, r *pb.KVDeleteRequest) (*pb.Empty, error) {
	if err := kvScope(ctx, r.Key); err != nil {
		return nil, err
	}
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVDelete(ctx, r)
	}
	return &pb.Empty{}, s.IAM.KVDeleteFenced(r.Key, r.Check, r.ExpectRev, fenceOf(r.Fence))
}

// kvScope keeps apiservers to the extensions' keys (ext/): the rest is
// the fleet service's, which says what runs on every node. It is checked
// where the call comes in, before any forwarding to the leader.
func kvScope(ctx context.Context, key string) error {
	if id, ok := rpcutil.PeerIdentity(ctx); ok && id.Role == pki.RoleAPIServer && !strings.HasPrefix(key, "ext/") {
		return rpcutil.Err(rpcutil.Forbidden, "%s may use only ext/ keys, not %q", id, key)
	}
	return nil
}
