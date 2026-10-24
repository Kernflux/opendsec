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

func (s *Server) imageStore() (*images.Store, error) {
	if s.Images == nil {
		return nil, rpcutil.Err(rpcutil.Unavailable, "no image store configured (image_store.root)")
	}
	return s.Images, nil
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
	if s.Images == nil || !images.IsStoreName(image) {
		return nil
	}
	st := s.Images
	p, err := s.principal(ctx)
	if err != nil {
		return err
	}
	canon, err := s.authorizeImage(ctx, p, image, iam.LayerUse)
	if err != nil {
		return err
	}
	_, err = st.GetManifest(canon)
	return err
}

func infoPB(m *images.Manifest) *pb.ImageInfo {
	return &pb.ImageInfo{Name: m.Name, Layers: m.Layers, Env: m.Env, Workdir: m.Workdir, User: m.User,
		Parent: m.Parent, Source: m.Source, CreatedAt: m.CreatedAt, CreatedBy: m.CreatedBy,
		Snapshot: m.Snapshot, Memory: m.Memory}
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
	m := &images.Manifest{Name: name, Layers: img.Layers, Env: img.Env, Workdir: img.Workdir, User: img.User,
		Source: img.Source, CreatedBy: p}
	if err := st.PutManifest(m, r.Overwrite); err != nil {
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
		pm, err := st.GetManifest(pn)
		if err != nil {
			return nil, err
		}
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
	if err := st.PutManifest(m, r.Overwrite); err != nil {
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
	st.Refresh(name) // another apiserver may have overwritten it
	m, err := st.GetManifest(name)
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
	ms, err := st.List(r.Project)
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
	return &pb.Empty{}, st.DeleteManifest(name)
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
	parent, err := runningImage(st, sb)
	if err != nil {
		return nil, err
	}
	if !r.Overwrite {
		if _, err := st.GetManifest(name); err == nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
	}
	res, err := ec.PackDiff(ctx, &pb.EdgePackDiffRequest{SandboxId: r.SandboxId, LayerId: images.NewDiffLayerID(), Scrub: r.Scrub})
	if err != nil {
		return nil, err
	}
	m := &images.Manifest{Name: name, Layers: append(append([]string{}, parent.Layers...), res.LayerId),
		Env: parent.Env, Workdir: parent.Workdir, User: parent.User, Parent: parent.Name,
		Source: "pack_diff " + r.SandboxId, CreatedBy: p}
	if err := st.PutManifest(m, r.Overwrite); err != nil {
		return nil, err
	}
	return infoPB(m), nil
}
