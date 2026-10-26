package edge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// store persists one record file per live sandbox (spec §13.2) so a
// restarted edge can re-adopt its sandboxes.
type store struct{ dir string }

func newStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &store{dir: dir}, nil
}

func (s *store) path(lease string) string { return filepath.Join(s.dir, lease+".json") }

// save atomically writes sb: temp file, fsync, rename.
func (s *store) save(lease string, sb *pb.Sandbox) error {
	b, err := protojson.Marshal(sb)
	if err != nil {
		return err
	}
	tmp := s.path(lease) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(lease)); err != nil {
		return err
	}
	// The rename is durable once the directory is.
	d, err := os.Open(filepath.Dir(s.path(lease)))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *store) remove(lease string) {
	os.Remove(s.path(lease))
}

// load returns every persisted record keyed by lease. Unreadable files are
// reported and removed (their sandboxes are then cleaned up as unknown).
func (s *store) load() (map[string]*pb.Sandbox, []error) {
	out := map[string]*pb.Sandbox{}
	var errs []error
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return out, []error{err}
	}
	for _, e := range ents {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			os.Remove(filepath.Join(s.dir, name))
			continue
		}
		lease, ok := strings.CutSuffix(name, ".json")
		if !ok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, name))
		sb := &pb.Sandbox{}
		if err == nil {
			err = protojson.Unmarshal(b, sb)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("record %s: %w", name, err))
			os.Remove(filepath.Join(s.dir, name))
			continue
		}
		out[lease] = sb
	}
	return out, errs
}
