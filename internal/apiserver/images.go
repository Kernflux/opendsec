package apiserver

import (
	"context"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Image store API (spec §17). Writes need layer.publish and use needs
// layer.use on the image's project: runtime accounts that only hold
// layer.use cannot publish (builder/runtime separation, paper §5).

func (s *Server) imageStore() (*catalog, error) {
	if c := s.catalog(); c != nil {
		return c, nil
	}
	return nil, rpcutil.Err(rpcutil.Unavailable, "no image store configured (image_store.root)")
}

// EnableImages turns on store images (spec §17), kept in the image catalog
// (spec §42). files is the store as this apiserver mounts it, for edges and
// apiservers older than the catalog (image_store.manifest_files); nil when
// the apiserver does not access the store. Call before Run.
func (s *Server) EnableImages(files *images.Store) {
	s.imagesOn, s.filesStore = true, files
}

// catalog is the image catalog, nil without an image store.
func (s *Server) catalog() *catalog {
	if !s.imagesOn {
		return nil
	}
	s.catOnce.Do(func() { s.cat = newCatalog(s.filesStore, s.iam, s, s.log) })
	return s.cat
}

// storeEdgeIDs lists the healthy edges, prefer first if among them.
func (s *Server) storeEdgeIDs(prefer string) []string {
	var ids []string
	for _, e := range s.Engine.Snapshot().Edges {
		if e.Healthy {
			ids = append(ids, e.Id)
		}
	}
	return shuffled(ids, prefer)
}

// ListCatalog returns every image manifest and snapshot record, for the
// image store's garbage collection. Cluster admins only.
func (s *Server) ListCatalog(ctx context.Context, _ *pb.Empty) (*pb.Catalog, error) {
	c, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	if _, err := s.clusterAdmin(ctx); err != nil {
		return nil, err
	}
	refs, err := c.Refs(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.Catalog{}
	for _, m := range refs.Images {
		out.Images = append(out.Images, infoPB(m))
	}
	for _, snap := range refs.Snapshots {
		out.Snapshots = append(out.Snapshots, &pb.SnapshotRecord{Id: snap.ID, Layers: snap.Layers, CreatedAt: snap.CreatedAt,
			Memory: snap.Memory, Holder: snap.Holder})
	}
	return out, nil
}

// ForgetSnapshots drops snapshot records: garbage collection removes
// their files. Cluster admins only.
func (s *Server) ForgetSnapshots(ctx context.Context, r *pb.ForgetSnapshotsRequest) (*pb.Empty, error) {
	c, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	if _, err := s.clusterAdmin(ctx); err != nil {
		return nil, err
	}
	return &pb.Empty{}, c.ForgetSnapshots(ctx, r.SnapshotIds)
}

// authorizeImage checks perm on the project that owns image name.
func (s *Server) authorizeImage(ctx context.Context, principal, name, perm string) (string, error) {
	canon, err := images.Canonical(name)
	if err != nil {
		return "", err
	}
	project, _, _, _ := images.ParseName(canon)
	if err := s.authorize(ctx, principal, project, perm); err != nil {
		return "", err
	}
	return canon, nil
}

// checkImageUse validates the image of a new sandbox: with a store, store
// images need layer.use and must exist. Without a store, every name is an
// edge-local (static or simulated) image, as before the store existed.
func (s *Server) checkImageUse(ctx context.Context, image string) error {
	if !s.imagesOn || !images.IsStoreName(image) {
		return nil
	}
	st := s.catalog()
	p, err := s.principal(ctx)
	if err != nil {
		return err
	}
	canon, err := s.authorizeImage(ctx, p, image, iam.LayerUse)
	if err != nil {
		return err
	}
	m, err := st.Get(ctx, canon)
	if err == nil {
		s.noteImageUse(m)
	}
	return err
}

func infoPB(m *images.Manifest) *pb.ImageInfo {
	return &pb.ImageInfo{Name: m.Name, Layers: m.Layers, Env: m.Env, Workdir: m.Workdir, User: m.User,
		Parent: m.Parent, Source: m.Source, CreatedAt: m.CreatedAt, CreatedBy: m.CreatedBy,
		Snapshot: m.Snapshot, Memory: m.Memory, SizeBytes: m.Size, UsedAt: m.UsedAt}
}

func (s *Server) RegisterImage(ctx context.Context, r *pb.RegisterImageRequest) (*pb.ImageInfo, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	img := r.GetImage()
	name, err := s.authorizeImage(ctx, p, img.GetName(), iam.LayerPublish)
	if err != nil {
		return nil, err
	}
	if err := s.checkImageQuota(ctx, name); err != nil {
		return nil, err
	}
	m := &images.Manifest{Name: name, Layers: img.Layers, Env: img.Env, Workdir: img.Workdir, User: img.User,
		Source: img.Source, CreatedBy: p}
	if err := st.Put(ctx, m, r.Overwrite); err != nil {
		return nil, err
	}
	return infoPB(m), nil
}

func (s *Server) ComposeImage(ctx context.Context, r *pb.ComposeImageRequest) (*pb.ImageInfo, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	name, err := s.authorizeImage(ctx, p, r.Name, iam.LayerPublish)
	if err != nil {
		return nil, err
	}
	if err := s.checkImageQuota(ctx, name); err != nil {
		return nil, err
	}
	if len(r.Parts) == 0 {
		return nil, rpcutil.Err(rpcutil.Invalid, "compose needs at least one part")
	}
	m := &images.Manifest{Name: name, Env: map[string]string{}, CreatedBy: p, Source: "compose"}
	seen := map[string]bool{}
	for _, part := range r.Parts {
		pn, err := s.authorizeImage(ctx, p, part, iam.LayerUse)
		if err != nil {
			return nil, err
		}
		pm, err := st.Get(ctx, pn)
		if err != nil {
			return nil, err
		}
		m.Size += s.inheritedSize(ctx, pm.Name, projectOf(name))
		for _, l := range pm.Layers {
			if !seen[l] { // a shared base layer appears once, at its lowest position
				seen[l] = true
				m.Layers = append(m.Layers, l)
			}
		}
		for k, v := range pm.Env {
			m.Env[k] = v
		}
		if pm.Workdir != "" {
			m.Workdir = pm.Workdir
		}
		if pm.User != "" {
			m.User = pm.User
		}
	}
	for k, v := range r.Env {
		m.Env[k] = v
	}
	if r.Workdir != "" {
		m.Workdir = r.Workdir
	}
	if r.User != "" {
		m.User = r.User
	}
	if err := st.Put(ctx, m, r.Overwrite); err != nil {
		return nil, err
	}
	return infoPB(m), nil
}

func (s *Server) GetImage(ctx context.Context, r *pb.ImageRef) (*pb.ImageInfo, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	name, err := s.authorizeImage(ctx, p, r.Name, iam.LayerUse)
	if err != nil {
		return nil, err
	}
	m, err := st.Fresh(ctx, name) // another apiserver may have overwritten it
	if err != nil {
		return nil, err
	}
	return infoPB(m), nil
}

func (s *Server) ListImages(ctx context.Context, r *pb.ListImagesRequest) (*pb.ImageInfoList, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if r.Project == "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "project required")
	}
	if err := s.authorize(ctx, p, r.Project, iam.LayerUse); err != nil {
		return nil, err
	}
	ms, err := st.List(ctx, r.Project)
	if err != nil {
		return nil, err
	}
	out := &pb.ImageInfoList{}
	for _, m := range ms {
		out.Images = append(out.Images, infoPB(m))
	}
	return out, nil
}

func (s *Server) DeleteImage(ctx context.Context, r *pb.ImageRef) (*pb.Empty, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	name, err := s.authorizeImage(ctx, p, r.Name, iam.LayerPublish)
	if err != nil {
		return nil, err
	}
	return &pb.Empty{}, st.Delete(ctx, name)
}

// PackDiff snapshots a sandbox's writable layer as a new image stacked on the
// sandbox's own image (spec §17.4). Needs sandbox.operate on the sandbox and
// layer.publish on the new image's project.
func (s *Server) PackDiff(ctx context.Context, r *pb.PackDiffRequest) (*pb.ImageInfo, error) {
	st, err := s.imageStore()
	if err != nil {
		return nil, err
	}
	sb, ec, err := s.sandboxAt(ctx, r.SandboxId) // authenticates; checks sandbox.operate
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
	if err := s.checkImageQuota(ctx, name); err != nil {
		return nil, err
	}
	for _, pat := range r.Scrub {
		if err := images.ValidScrub(pat); err != nil {
			return nil, err
		}
	}
	parent, err := s.runningImage(ctx, sb)
	if err != nil {
		return nil, err
	}
	if !r.Overwrite {
		if _, err := st.Fresh(ctx, name); err == nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
	}
	res, err := ec.PackDiff(ctx, &pb.EdgePackDiffRequest{SandboxId: r.SandboxId, LayerId: images.NewDiffLayerID(), Scrub: r.Scrub})
	if err != nil {
		return nil, err
	}
	m := &images.Manifest{Name: name, Layers: append(append([]string{}, parent.Layers...), res.LayerId),
		Env: parent.Env, Workdir: parent.Workdir, User: parent.User, Parent: parent.Name,
		Source: "pack_diff " + r.SandboxId, CreatedBy: p, Size: res.SizeBytes + s.inheritedSize(ctx, parent.Name, projectOf(name))}
	if err := st.Put(ctx, m, r.Overwrite); err != nil {
		return nil, err
	}
	return infoPB(m), nil
}

// projectOf is image name's project ("" if it is not a store name).
func projectOf(name string) string {
	p, _, _, err := images.ParseName(name)
	if err != nil {
		return ""
	}
	return p
}
