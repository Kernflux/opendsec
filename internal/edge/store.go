package edge

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

// save atomically writes sb.
func (s *store) save(lease string, sb *pb.Sandbox) error {
	b, err := protojson.Marshal(sb)
	if err != nil {
		return err
	}
	return s.write(s.path(lease), b)
}

// write replaces path with b durably: temp file, fsync, rename, fsync of
// the directory (the rename is durable once the directory is).
func (s *store) write(path string, b []byte) error {
	tmp := path + ".tmp"
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *store) remove(lease string) {
	os.Remove(s.path(lease))
	os.Remove(s.movingPath(lease))
}

// A sandbox frozen for a move to another edge (spec §26.2) has a marker
// beside its record, so an edge restarted mid-move keeps it frozen: the
// edge it moves to may already run it.
func (s *store) movingPath(lease string) string { return filepath.Join(s.dir, lease+".moving") }

// setMoving records that lease's sandbox is frozen for a move since t; a
// zero t removes the marker.
func (s *store) setMoving(lease string, t time.Time) error {
	if t.IsZero() {
		if err := os.Remove(s.movingPath(lease)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return s.write(s.movingPath(lease), []byte(strconv.FormatInt(t.UnixNano(), 10)))
}

// moving returns since when lease's sandbox is frozen for a move (zero: it
// is not).
func (s *store) moving(lease string) time.Time {
	b, err := os.ReadFile(s.movingPath(lease))
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, n)
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
