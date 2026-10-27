package apiserver

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// slowIAM answers once release is closed, telling when a call came in.
type slowIAM struct {
	pb.IAMClient
	asked, release chan struct{}
}

func (s *slowIAM) wait() { s.asked <- struct{}{}; <-s.release }

func (s *slowIAM) Authenticate(context.Context, *pb.AuthenticateRequest, ...grpc.CallOption) (*pb.Principal, error) {
	s.wait()
	return &pb.Principal{Id: "alice"}, nil
}

func (s *slowIAM) Authorize(context.Context, *pb.AuthorizeRequest, ...grpc.CallOption) (*pb.Empty, error) {
	s.wait()
	return &pb.Empty{}, nil
}

// TestRevocationDuringLookup: an answer IAM gave before a revocation
// flushed the caches is used for its call but not cached, else it would
// outlive the revocation by the cache TTL.
func TestRevocationDuringLookup(t *testing.T) {
	iam := &slowIAM{asked: make(chan struct{}), release: make(chan struct{})}
	s := New(config.APIServer{}, config.Placement{}, iam, nil, rpcutil.NewPool(nil), slog.New(slog.DiscardHandler))
	cached := func() (int, int) {
		s.cacheMu.Lock()
		defer s.cacheMu.Unlock()
		return len(s.authn), len(s.authz)
	}
	revokeDuring := func(call func() error) {
		done := make(chan error)
		go func() { done <- call() }()
		<-iam.asked
		s.flushAuth() // the revocation
		iam.release <- struct{}{}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	revokeDuring(func() error { _, err := s.identify(context.Background(), "tok"); return err })
	if n, _ := cached(); n != 0 {
		t.Fatal("authentication cached across a revocation")
	}
	revokeDuring(func() error { return s.authorize(context.Background(), "alice", "root", "sandbox.create") })
	if _, n := cached(); n != 0 {
		t.Fatal("authorization cached across a revocation")
	}
}
