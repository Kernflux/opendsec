package iam

import (
	"context"
	"errors"
	"io"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// BackupChunkSize is the size of the pieces backups are streamed in.
const BackupChunkSize = 1 << 20

// maxBackup bounds a restore upload.
const maxBackup = 1 << 30

func (s *Service) Backup(r *pb.IAMBackupRequest, stream pb.IAM_BackupServer) error {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return err
		}
		up, err := c.Backup(stream.Context(), r)
		if err != nil {
			return err
		}
		return Pipe(up, stream)
	}
	b, err := s.IAM.Backup(r.Actor)
	if err != nil {
		return err
	}
	return SendChunks(b, func(ch *pb.BackupChunk) error { return stream.Send(ch) })
}

func (s *Service) Restore(stream pb.IAM_RestoreServer) error {
	actor, data, err := RecvChunks(stream.Recv)
	if err != nil {
		return err
	}
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return err
		}
		up, err := c.Restore(stream.Context())
		if err != nil {
			return err
		}
		first := true
		if err := SendChunks(data, func(ch *pb.BackupChunk) error {
			if first {
				ch.Actor, first = actor, false
			}
			return up.Send(ch)
		}); err != nil {
			return err
		}
		if _, err := up.CloseAndRecv(); err != nil {
			return err
		}
		return stream.SendAndClose(&pb.Empty{})
	}
	if err := s.IAM.Restore(actor, data); err != nil {
		return err
	}
	return stream.SendAndClose(&pb.Empty{})
}

func (s *Service) Members(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.Members(ctx, r)
	}
	return s.members(r.Actor)
}

func (s *Service) AddMember(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.AddMember(ctx, r)
	}
	if err := s.IAM.AddMember(r.Actor, r.Id, r.RaftAddr, r.Addr); err != nil {
		return nil, err
	}
	return s.members(r.Actor)
}

func (s *Service) RemoveMember(ctx context.Context, r *pb.IAMMemberRequest) (*pb.IAMMemberList, error) {
	if c, err := s.fwd(); c != nil || err != nil {
		if err != nil {
			return nil, err
		}
		return c.RemoveMember(ctx, r)
	}
	if err := s.IAM.RemoveMember(r.Actor, r.Id); err != nil {
		return nil, err
	}
	if !s.IAM.IsLeader() { // it removed itself
		return &pb.IAMMemberList{Replicated: true}, nil
	}
	return s.members(r.Actor)
}

func (s *Service) members(actor string) (*pb.IAMMemberList, error) {
	ms, err := s.IAM.Members(actor)
	if err != nil {
		return nil, err
	}
	out := &pb.IAMMemberList{Replicated: s.IAM.Replicated()}
	for _, m := range ms {
		pm := &pb.IAMMember{Id: m.ID, RaftAddr: m.RaftAddr, Addr: m.Addr, Leader: m.Leader, Voter: m.Voter}
		if m.Leader {
			pm.AppliedIndex = s.IAM.AppliedIndex()
		}
		out.Members = append(out.Members, pm)
	}
	return out, nil
}

// ---- chunked transfer, shared with the apiserver ---------------------------------------------

// SendChunks sends b in BackupChunkSize pieces (one empty piece for empty b).
func SendChunks(b []byte, send func(*pb.BackupChunk) error) error {
	for off := 0; off == 0 || off < len(b); off += BackupChunkSize {
		end := min(off+BackupChunkSize, len(b))
		if err := send(&pb.BackupChunk{Data: b[off:end]}); err != nil {
			return err
		}
		if end == len(b) {
			break
		}
	}
	return nil
}

// RecvChunks reads a chunk stream to its end: the actor of the first chunk
// and the data.
func RecvChunks(recv func() (*pb.BackupChunk, error)) (string, []byte, error) {
	var actor string
	var data []byte
	for first := true; ; first = false {
		ch, err := recv()
		if errors.Is(err, io.EOF) {
			return actor, data, nil
		}
		if err != nil {
			return "", nil, err
		}
		if first {
			actor = ch.Actor
		}
		if len(data)+len(ch.Data) > maxBackup {
			return "", nil, rpcutil.Err(rpcutil.Invalid, "backup larger than %d bytes", maxBackup)
		}
		data = append(data, ch.Data...)
	}
}

// Pipe copies a chunk stream from an upstream call to a downstream one.
func Pipe(up interface {
	Recv() (*pb.BackupChunk, error)
}, down interface{ Send(*pb.BackupChunk) error }) error {
	for {
		ch, err := up.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := down.Send(ch); err != nil {
			return err
		}
	}
}
