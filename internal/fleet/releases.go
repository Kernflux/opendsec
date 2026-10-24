package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/release"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

const chunkSize = 1 << 20

// releaseStore keeps release tarballs on a replica's disk:
// <dir>/releases/<version>.tgz.
type releaseStore struct {
	dir string
	sem chan struct{} // concurrent downloads
}

func newReleaseStore(dataDir string, maxDownloads int) (*releaseStore, error) {
	dir := filepath.Join(dataDir, "releases")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &releaseStore{dir: dir, sem: make(chan struct{}, max(1, maxDownloads))}, nil
}

func (r *releaseStore) path(version string) string { return filepath.Join(r.dir, version+".tgz") }

func (r *releaseStore) has(version, sum string) bool {
	if !release.ValidVersion(version) {
		return false
	}
	got, err := fileSHA(r.path(version))
	return err == nil && got == sum
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// receive stores a tarball streamed as chunks (the first carries version,
// size and sha256), verifying the sum, the size and the release inside.
// accept runs just before the verified tarball replaces the stored one: an
// error from it leaves the stored tarball as it was.
func (r *releaseStore) receive(recv func() (*pb.ReleaseChunk, error), accept func(first *pb.ReleaseChunk) error) (*pb.ReleaseChunk, *release.Info, error) {
	first, err := recv()
	if err != nil {
		return nil, nil, err
	}
	if !release.ValidVersion(first.Version) || len(first.Sha256) != 64 || first.Size <= 0 {
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "the first chunk must name a valid version, its size and sha256")
	}
	tmp, err := os.CreateTemp(r.dir, "."+first.Version+".")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	w := io.MultiWriter(tmp, h)
	var n int64
	for c := first; ; {
		if n+int64(len(c.Data)) > first.Size {
			return nil, nil, rpcutil.Err(rpcutil.Invalid, "release %s is larger than its stated %d bytes", first.Version, first.Size)
		}
		if _, err := w.Write(c.Data); err != nil {
			return nil, nil, err
		}
		n += int64(len(c.Data))
		if c, err = recv(); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, err
		}
	}
	if n != first.Size || hex.EncodeToString(h.Sum(nil)) != first.Sha256 {
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "release %s: size or sha256 does not match", first.Version)
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return nil, nil, err
	}
	info, err := release.VerifyTarball(tmp)
	if err != nil {
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "release %s: %v", first.Version, err)
	}
	if info.Version != first.Version {
		return nil, nil, rpcutil.Err(rpcutil.Invalid, "tarball holds release %s, not %s", info.Version, first.Version)
	}
	if err := tmp.Sync(); err != nil {
		return nil, nil, err
	}
	if err := accept(first); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(tmp.Name(), r.path(first.Version)); err != nil {
		return nil, nil, err
	}
	return first, info, nil
}

// send streams version from offset.
func (r *releaseStore) send(version string, offset int64, send func(*pb.ReleaseChunk) error) error {
	if !release.ValidVersion(version) {
		return rpcutil.Err(rpcutil.Invalid, "bad version %q", version)
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return rpcutil.Err(rpcutil.Unavailable, "fleet replica busy: too many downloads, retry")
	}
	f, err := os.Open(r.path(version))
	if os.IsNotExist(err) {
		return rpcutil.Err(rpcutil.NotFound, "release %s is not on this replica", version)
	} else if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	for {
		k, err := f.Read(buf)
		if k > 0 {
			if serr := send(&pb.ReleaseChunk{Version: version, Data: buf[:k]}); serr != nil {
				return serr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// local lists the versions on disk.
func (r *releaseStore) local() []string {
	es, _ := os.ReadDir(r.dir)
	var out []string
	for _, e := range es {
		if v, ok := strings.CutSuffix(e.Name(), ".tgz"); ok && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, v)
		}
	}
	return out
}

// ---- RPCs ---------------------------------------------------------------------------

func (s *Server) FetchRelease(r *pb.FetchReleaseRequest, stream pb.Fleet_FetchReleaseServer) error {
	return s.releases.send(r.Version, r.Offset, stream.Send)
}

// PutRelease receives a copy from the replica that took a push.
func (s *Server) PutRelease(stream pb.Fleet_PutReleaseServer) error {
	if _, _, err := s.releases.receive(stream.Recv, s.immutable(stream.Context())); err != nil {
		return err
	}
	return stream.SendAndClose(&pb.Empty{})
}

// PushRelease stores a new release on this replica, copies it to every
// other replica, and only then records it, so whichever replica an agent
// downloads from has it.
func (s *Server) PushRelease(stream pb.FleetAdmin_PushReleaseServer) error {
	ctx := stream.Context()
	first, info, err := s.releases.receive(stream.Recv, s.immutable(ctx))
	if err != nil {
		return err
	}
	cur, exists, err := s.store.Release(ctx, first.Version)
	if err != nil {
		return err
	}
	if exists && cur.V.Sha256 != first.Sha256 { // recorded since the check above
		return rpcutil.Err(rpcutil.Conflict, "release %s exists with other contents: published versions are immutable", first.Version)
	}
	var replicas []string
	for _, id := range sortedKeys(s.peers) {
		if id == s.opt.ID {
			replicas = append(replicas, id)
			continue
		}
		if err := s.copyTo(ctx, id, first); err != nil {
			return rpcutil.Err(rpcutil.Unavailable, "copy release %s to fleet replica %s: %v", first.Version, id, err)
		}
		replicas = append(replicas, id)
	}
	rel := &pb.FleetRelease{Version: first.Version, Sha256: first.Sha256, Size: first.Size, CreatedAt: s.unix(),
		CreatedBy: actorOf(ctx), Notes: first.Notes, Deps: info.Deps, Replicas: replicas}
	if exists {
		rel = proto.Clone(cur.V).(*pb.FleetRelease)
		rel.Replicas = replicas
	}
	if _, err := s.store.PutRelease(ctx, rel, cur.Rev); err != nil {
		return err
	}
	s.log.Info("release pushed", "version", rel.Version, "by", rel.CreatedBy, "size", rel.Size, "deps", rel.Deps)
	return stream.SendAndClose(rel)
}

// immutable refuses a tarball whose version is recorded with other
// contents, before it can replace the recorded one on disk: agents check
// what they download against the record.
func (s *Server) immutable(ctx context.Context) func(*pb.ReleaseChunk) error {
	return func(first *pb.ReleaseChunk) error {
		cur, exists, err := s.store.Release(ctx, first.Version)
		if err != nil {
			return err
		}
		if exists && cur.V.Sha256 != first.Sha256 {
			return rpcutil.Err(rpcutil.Conflict, "release %s exists with other contents: published versions are immutable", first.Version)
		}
		return nil
	}
}

func (s *Server) copyTo(ctx context.Context, id string, first *pb.ReleaseChunk) error {
	conn, err := s.opt.Pool.Get(s.peers[id])
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	up, err := pb.NewFleetClient(conn).PutRelease(cctx)
	if err != nil {
		return err
	}
	sent := false
	err = s.releases.sendUnlimited(first.Version, func(c *pb.ReleaseChunk) error {
		if !sent {
			c.Size, c.Sha256 = first.Size, first.Sha256
			sent = true
		}
		return up.Send(c)
	})
	if err != nil {
		return err
	}
	_, err = up.CloseAndRecv()
	return err
}

// sendUnlimited is send without the download limit (replica copies).
func (r *releaseStore) sendUnlimited(version string, send func(*pb.ReleaseChunk) error) error {
	f, err := os.Open(r.path(version))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, chunkSize)
	for {
		k, err := f.Read(buf)
		if k > 0 {
			if serr := send(&pb.ReleaseChunk{Version: version, Data: append([]byte(nil), buf[:k]...)}); serr != nil {
				return serr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ---- garbage collection ---------------------------------------------------------------

func (s *Server) gcLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		if s.IsLeader() {
			if err := s.gcRecords(cctx); err != nil {
				s.log.Warn("release gc", "err", err)
			}
		}
		s.gcLocal(cctx)
		cancel()
	}
}

// gcRecords drops release records nothing uses: not a node's desired or
// current release, not part of an unfinished rollout, and not among the
// newest keep_releases.
func (s *Server) gcRecords(ctx context.Context) error {
	if !s.warm() {
		return nil
	}
	rels, err := s.store.Releases(ctx)
	if err != nil {
		return err
	}
	inUse, err := s.releasesInUse(ctx)
	if err != nil {
		return err
	}
	// newest first by creation time
	for i := 0; i < len(rels); i++ {
		for j := i + 1; j < len(rels); j++ {
			if rels[j].V.CreatedAt > rels[i].V.CreatedAt {
				rels[i], rels[j] = rels[j], rels[i]
			}
		}
	}
	for i, r := range rels {
		if i < s.opt.Cfg.KeepReleases || inUse[r.V.Version] {
			continue
		}
		if err := s.store.DeleteRelease(ctx, r.V.Version); err != nil {
			return err
		}
		s.log.Info("release record collected", "version", r.V.Version)
	}
	return nil
}

func (s *Server) releasesInUse(ctx context.Context) (map[string]bool, error) {
	use := map[string]bool{}
	ns, err := s.nodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range ns {
		use[n.V.Release] = true
		if st := s.statusOf(n.V.Name); st != nil {
			use[st.CurrentRelease] = true
		}
	}
	ros, err := s.store.Rollouts(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range ros {
		if active(r.V.State) {
			steps, err := s.store.Steps(ctx, r.V.Id)
			if err != nil {
				return nil, err
			}
			for _, st := range steps {
				use[st.V.FromRelease], use[st.V.ToRelease] = true, true
			}
		}
	}
	return use, nil
}

// gcLocal removes tarballs whose record is gone.
func (s *Server) gcLocal(ctx context.Context) {
	rels, err := s.store.Releases(ctx)
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, r := range rels {
		known[r.V.Version] = true
	}
	for _, v := range s.releases.local() {
		if !known[v] {
			if err := os.Remove(s.releases.path(v)); err == nil {
				s.log.Info("release tarball removed", "version", v)
			}
		}
	}
	tmp, _ := filepath.Glob(filepath.Join(s.releases.dir, ".*"))
	for _, p := range tmp {
		if fi, err := os.Stat(p); err == nil && time.Since(fi.ModTime()) > time.Hour {
			os.Remove(p)
		}
	}
}

var errNoRelease = errors.New("no such release")

func (s *Server) releaseRec(ctx context.Context, version string) (*pb.FleetRelease, error) {
	r, ok, err := s.store.Release(ctx, version)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcutil.Err(rpcutil.NotFound, "release %s: %v", version, errNoRelease)
	}
	return r.V, nil
}

func describeRelease(r *pb.FleetRelease) string {
	return fmt.Sprintf("%s (%d bytes, sha256 %s…)", r.Version, r.Size, r.Sha256[:12])
}
