package apiserver

import (
	"context"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Image limits per project (spec §43.2, admission.projects): how many
// images a project keeps, how much data they add, and how long an unused
// one stays.

// checkImageQuota refuses publishing image name when its project has its
// number of images or their data at the limit. An overwrite does not count
// the image it replaces. The data a publish adds is known only once it is
// written, so the last image may go past MaxImageMB by its own size.
func (s *Server) checkImageQuota(ctx context.Context, name string) error {
	_, err := s.imageRoom(ctx, name)
	return err
}

// imageRoom checks image name's quota (checkImageQuota) and returns the
// data its project may still add (-1: no limit).
func (s *Server) imageRoom(ctx context.Context, name string) (int64, error) {
	project, _, _, err := images.ParseName(name)
	if err != nil {
		return 0, err
	}
	lim := s.adm.For(project).Image
	if lim.MaxImages <= 0 && lim.MaxImageMB <= 0 {
		return -1, nil
	}
	ms, err := s.catalog().List(ctx, project)
	if err != nil {
		return 0, err
	}
	n, bytes := 0, int64(0)
	for _, m := range ms {
		if p, _, _, err := images.ParseName(m.Name); err != nil || p != project || m.Name == name {
			continue // a subproject's, or the one being replaced
		}
		n++
		bytes += m.Size
	}
	if lim.MaxImages > 0 && n >= lim.MaxImages {
		return 0, rpcutil.Err(rpcutil.QuotaExceeded, "project %s has %d images, its limit: delete one first", project, n)
	}
	if lim.MaxImageMB <= 0 {
		return -1, nil
	}
	if bytes >= lim.MaxImageMB<<20 {
		return 0, rpcutil.Err(rpcutil.QuotaExceeded, "the images of project %s hold %d MB, its limit is %d MB: delete one first",
			project, bytes>>20, lim.MaxImageMB)
	}
	return lim.MaxImageMB<<20 - bytes, nil
}

// publishImage writes m to the catalog within its project's quota, across
// apiservers: the quota is checked again, now that m's size is known, under
// a lock of the project that also guards the write. strict refuses an image
// bigger than the room left; otherwise the last image may go past MaxImageMB
// by its own size. The earlier checkImageQuota only spares doomed work.
func (s *Server) publishImage(ctx context.Context, m *images.Manifest, overwrite, strict bool) error {
	c := s.catalog()
	project := projectOf(m.Name)
	if lim := s.adm.For(project).Image; lim.MaxImages <= 0 && lim.MaxImageMB <= 0 {
		return c.Put(ctx, m, overwrite)
	}
	return c.locked(ctx, "img-quota/"+project, func(fence *pb.Fence) error {
		room, err := s.imageRoom(ctx, m.Name)
		if err != nil {
			return err
		}
		if strict && room >= 0 && m.Size > room {
			return rpcutil.Err(rpcutil.QuotaExceeded, "image %s holds %d MB, but its project has %d MB left", m.Name, m.Size>>20, room>>20)
		}
		return c.put(ctx, m, overwrite, fence)
	})
}

// inheritedSize is what an image made from parent in project inherits of
// its data: the parent's size when the parent is an image of the same
// project (else 0: a shared base is not the project's). Without it, an
// import overwritten by a pack_diff of itself (as Template builds do)
// would leave its layers in the store but count only the diff. Keeping
// both counts the parent twice: quotas err on the high side.
func (s *Server) inheritedSize(ctx context.Context, parent, project string) int64 {
	if parent == "" {
		return 0
	}
	if p, _, _, err := images.ParseName(parent); err != nil || p != project {
		return 0
	}
	m, err := s.catalog().Get(ctx, parent)
	if err != nil {
		return 0
	}
	return m.Size
}

// touchEvery is how stale an image's UsedAt may get before a start records
// a new one (one catalog write per image per period, not per sandbox): a
// quarter of its project's ttl, so that an image in use never looks unused
// and the write has time to land, at most an hour, at least 5 seconds.
func touchEvery(ttl float64) float64 { return min(max(ttl/4, 5), 3600) }

// noteImageUse records that a sandbox starts from m, if m's project has
// expiring images and its record is stale. In the background: creation
// does not wait for it.
func (s *Server) noteImageUse(m *images.Manifest) {
	project, _, _, err := images.ParseName(m.Name)
	if err != nil {
		return
	}
	ttl := s.adm.For(project).Image.ImageTTL
	if ttl <= 0 {
		return
	}
	now := float64(time.Now().UnixNano()) / 1e9
	if now-max(m.UsedAt, m.CreatedAt) < touchEvery(ttl) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.catalog().Touch(ctx, m.Name, now); err != nil {
			s.log.Warn("recording an image's use failed", "image", m.Name, "err", err)
		}
	}()
}

// expireImages deletes the images unused for their project's ImageTTL,
// every ten minutes or so. Every apiserver runs it; Expire deletes an entry
// only as listed, so they cannot delete one that was used meanwhile.
func (s *Server) expireImages(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(9*time.Minute + rand.N(2*time.Minute)):
		}
		s.expireImagesOnce(ctx)
	}
}

func (s *Server) expireImagesOnce(ctx context.Context) {
	now := float64(time.Now().UnixNano()) / 1e9
	for p, lim := range s.adm.Projects {
		if lim.ImageTTL <= 0 {
			continue
		}
		ms, err := s.catalog().List(ctx, p)
		if err != nil {
			s.log.Warn("image expiry: listing failed", "project", p, "err", err)
			continue
		}
		for _, m := range ms {
			project, _, _, err := images.ParseName(m.Name)
			if err != nil {
				continue
			}
			ttl := s.adm.For(project).Image.ImageTTL
			if ttl <= 0 || now-max(m.UsedAt, m.CreatedAt) < ttl {
				continue
			}
			gone, err := s.catalog().Expire(ctx, m)
			switch {
			case err != nil:
				s.log.Warn("image expiry: deleting failed", "image", m.Name, "err", err)
			case gone:
				s.log.Info("image expired: unused", "image", m.Name, "since", time.Unix(int64(max(m.UsedAt, m.CreatedAt)), 0).UTC())
			}
		}
	}
}

// SetImageImport sets the bounds of users' pulls from registries.
func (s *Server) SetImageImport(c config.ImageImport) { s.imp = c }

// ImportImage pulls a registry's image into the store as r.Image (spec
// §43.3): an edge pulls it, reaching only public addresses, within the
// cluster's image_import bounds and the room left in the project's image
// quota. Its size counts all its layers, shared ones included: what the
// image keeps in the store.
func (s *Server) ImportImage(ctx context.Context, r *pb.ImportImageRequest) (*pb.ImageInfo, error) {
	if s.imp.Disabled {
		return nil, rpcutil.Err(rpcutil.Invalid, "importing images is turned off in this cluster")
	}
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	name, err := s.authorizeImage(ctx, p, r.Image, iam.LayerPublish)
	if err != nil {
		return nil, err
	}
	if _, err := images.ParseReference(r.Ref); err != nil {
		return nil, rpcutil.Err(rpcutil.Invalid, "image reference %q: %v", r.Ref, err)
	}
	room, err := s.imageRoom(ctx, name)
	if err != nil {
		return nil, err
	}
	if !r.Overwrite {
		if _, err := st.Fresh(ctx, name); err == nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
	}
	maxBytes := s.imp.MaxMB << 20
	if room >= 0 && (maxBytes <= 0 || room < maxBytes) {
		maxBytes = room
	}
	timeout := time.Duration(s.imp.Timeout * float64(time.Second))
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := &pb.EdgeImportRequest{Ref: r.Ref, Username: r.Username, Password: r.Password, MaxBytes: maxBytes,
		MaxEntries: int32(s.imp.MaxFiles), AllowRegistries: s.imp.AllowRegistries}
	var res *pb.EdgeImportResponse
	err = rpcutil.Err(rpcutil.Unavailable, "no healthy edge")
	for i, id := range s.storeEdgeIDs("") {
		if i == 3 {
			break
		}
		ec, cerr := s.edgeClient(id)
		if cerr != nil {
			err = cerr
			continue
		}
		if res, err = ec.ImportImage(ctx, req); err == nil {
			break
		}
		if status.Code(err) == codes.Unimplemented {
			err = rpcutil.Err(rpcutil.Unavailable, "edge %s is too old to import images", id)
			continue
		}
		if rpcutil.Reason(err) != rpcutil.Unavailable { // busy: try another; else an answer
			break
		}
	}
	if err != nil {
		return nil, err
	}
	m := &images.Manifest{Name: name, Layers: res.Layers, Env: res.Env, Workdir: res.Workdir, User: res.User,
		Source: res.Source, CreatedBy: p, Size: res.SizeBytes}
	if err := s.publishImage(ctx, m, r.Overwrite, true); err != nil {
		return nil, err
	}
	s.log.Info("image imported", "image", name, "ref", r.Ref, "by", p, "mb", res.SizeBytes>>20, "pulled", res.Pulled)
	return infoPB(m), nil
}
