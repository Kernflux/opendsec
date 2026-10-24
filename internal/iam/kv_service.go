package iam

import (
	"context"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// Key-value area over gRPC (spec §28.3). Reads are forwarded to the leader
// like writes, so a caller always sees its own and everyone's committed writes.

func kvPB(e *KVEntry) *pb.KVEntry {
	return &pb.KVEntry{Key: e.Key, Value: e.Value, Rev: e.Rev}
}

func (s *Service) KVGet(ctx context.Context, r *pb.KVGetRequest) (*pb.KVEntry, error) {
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
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVPut(ctx, r)
	}
	e, err := s.IAM.KVPut(r.Key, r.Value, r.Check, r.ExpectRev)
	if err != nil {
		return nil, err
	}
	return kvPB(e), nil
}

func (s *Service) KVDelete(ctx context.Context, r *pb.KVDeleteRequest) (*pb.Empty, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.KVDelete(ctx, r)
	}
	return &pb.Empty{}, s.IAM.KVDelete(r.Key, r.Check, r.ExpectRev)
}
