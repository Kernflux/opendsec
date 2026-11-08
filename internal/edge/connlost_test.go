package edge

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// A runtime call cut by its connection closing (the sandbox paused or moved)
// is unavailable, which callers retry; the caller's own cancel, and other
// errors, stay as they are.
func TestConnLost(t *testing.T) {
	closing := status.Error(codes.Canceled, "grpc: the client connection is closing")
	if got := connLost(context.Background(), "e1.x", closing); rpcutil.Reason(got) != rpcutil.Unavailable {
		t.Fatalf("closed connection: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := connLost(ctx, "e1.x", closing); got != closing {
		t.Fatalf("caller's cancel changed: %v", got)
	}
	other := errors.New("boom")
	if connLost(context.Background(), "e1.x", other) != other || connLost(context.Background(), "e1.x", nil) != nil {
		t.Fatal("other errors must pass through")
	}
}
