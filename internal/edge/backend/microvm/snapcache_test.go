package microvm

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernflux/opendsec/internal/images"
)

// TestSnapCacheGCGrace: gc keeps a young cached snapshot the store does not
// know yet (a snapshot just taken here is renamed into the cache before its
// record is written) and removes an old one.
func TestSnapCacheGCGrace(t *testing.T) {
	st, err := images.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &snapCache{dir: t.TempDir(), store: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), pulling: map[string]*build{}}
	young, old := images.NewSnapshotID(), images.NewSnapshotID()
	for _, id := range []string{young, old} {
		if err := os.MkdirAll(filepath.Join(c.dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * snapGCGrace)
	os.Chtimes(filepath.Join(c.dir, old), past, past)
	c.gc()
	if _, err := os.Stat(filepath.Join(c.dir, young)); err != nil {
		t.Fatal("gc removed a snapshot taken just now")
	}
	if _, err := os.Stat(filepath.Join(c.dir, old)); err == nil {
		t.Fatal("gc kept an old snapshot the store does not have")
	}
}
