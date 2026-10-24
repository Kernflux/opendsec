package apiserver

import (
	"context"
	"maps"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// MaxFork bounds the copies of one ForkSandbox call (spec §19.2).
const MaxFork = 256

// ForkSandbox snapshots a running sandbox once and starts count copies of it
// (spec §19.4). Needs sandbox.operate on the source; each copy is a normal
// creation in the source's project (sandbox.create, quota, creation rate),
// placed on the source's edge when it fits.
func (s *Server) ForkSandbox(r *pb.ForkSandboxRequest, stream pb.DSec_ForkSandboxServer) error {
	ctx := stream.Context()
	if r.Count <= 0 || r.Count > MaxFork {
		return rpcutil.Err(rpcutil.Invalid, "count must be in [1, %d]", MaxFork)
	}
	if r.TtlRunningStopS < 0 || r.TtlMaxS < 0 {
		return rpcutil.Err(rpcutil.Invalid, "ttls must be >= 0")
	}
	src, ec, err := s.sandboxAt(ctx, r.SandboxId) // authenticates; checks sandbox.operate
	if err != nil {
		return err
	}
	switch src.State {
	case pb.SandboxState_RUNNING, pb.SandboxState_PAUSED:
	default:
		return rpcutil.Err(rpcutil.Invalid, "sandbox %s is %s", src.Id, src.State)
	}
	spec := proto.Clone(src.Spec).(*pb.SandboxSpec)
	spec.TtlRunningStopS, spec.TtlMaxS = r.TtlRunningStopS, r.TtlMaxS
	if err := s.applyTTLs(spec); err != nil {
		return err
	}
	if len(r.Labels) > 0 {
		if spec.Labels == nil {
			spec.Labels = map[string]string{}
		}
		maps.Copy(spec.Labels, r.Labels)
	}
	if r.TaskId != "" {
		spec.TaskId = r.TaskId
	}
	// The copies carry the source's image: the caller needs layer.use on it
	// as for any creation (the image itself may since have been deleted).
	if s.Images != nil && images.IsStoreName(spec.Image) {
		p, err := s.principal(ctx)
		if err != nil {
			return err
		}
		if _, err := s.authorizeImage(ctx, p, spec.Image, iam.LayerUse); err != nil {
			return err
		}
	}
	// Fail before pausing the source if the caller cannot create at all.
	if _, err := s.admit(ctx, rpcutil.BearerToken(ctx), &pb.AdmitRequest{Project: src.Project,
		Perms: []string{iam.SandboxCreate}}); err != nil {
		return err
	}
	b, err := s.newBatch(ctx, src.Project, r.RequestId, r.Retry, r.Count)
	if err != nil {
		return err
	}
	if b.remaining() == 0 { // a retry: every copy was made
		return s.createMany(ctx, stream.Send, src.Project, spec, b, "", nil)
	}
	// A memory snapshot is only needed to start the copies: it stays on the
	// source's edge, which copies elsewhere fetch it from (spec §26.1).
	t0 := time.Now()
	snap, err := ec.Snapshot(ctx, &pb.EdgeSnapshotRequest{SandboxId: src.Id, SnapshotId: images.NewSnapshotID(),
		PreferMemory: true, Ephemeral: true})
	if err != nil {
		return err
	}
	spec.Snapshot = snap.SnapshotId
	var peer *pb.EdgePeer
	if snap.Held {
		peer = &pb.EdgePeer{Id: src.EdgeId, Addr: (*s.addrs.Load())[src.EdgeId]}
	}
	s.log.Info("fork", "source", src.Id, "snapshot", snap.SnapshotId, "memory", snap.Memory, "held", snap.Held,
		"count", r.Count, "retried", len(b.done), "bytes", snap.SizeBytes)
	err = s.createMany(ctx, stream.Send, src.Project, spec, b, src.EdgeId, peer)
	metrics.Fork(snap.Held, time.Since(t0))
	// A memory snapshot is only needed to start the copies (they hold their
	// own links and mappings); filesystem snapshots stay, as copies stack on
	// their layers.
	if snap.Memory && s.Images != nil {
		if rec, gerr := s.Images.GetSnapshot(snap.SnapshotId); gerr == nil && rec.VM != nil {
			s.Images.DeleteSnapshot(snap.SnapshotId)
		}
	}
	return err
}

// CreateSnapshot saves a sandbox as image r.Image (spec §19.2): its
// filesystem as it is (unlike pack_diff, nothing is scrubbed) and, with
// memory, its memory. Needs sandbox.operate on the sandbox and layer.publish
// on the image's project.
func (s *Server) CreateSnapshot(ctx context.Context, r *pb.CreateSnapshotRequest) (*pb.ImageInfo, error) {
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
	if sb.Spec.GetSnapshot() == "" && !images.IsStoreName(sb.Spec.GetImage()) {
		return nil, rpcutil.Err(rpcutil.Invalid, "snapshot images need a sandbox started from a store image, not %q", sb.Spec.GetImage())
	}
	if !r.Overwrite {
		if _, err := st.GetManifest(name); err == nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "image %s already exists", name)
		}
	}
	res, err := ec.Snapshot(ctx, &pb.EdgeSnapshotRequest{SandboxId: r.SandboxId, SnapshotId: images.NewSnapshotID(), Memory: r.Memory})
	if err != nil {
		return nil, err
	}
	snap, err := st.GetSnapshot(res.SnapshotId)
	if err != nil {
		if rpcutil.Reason(err) == rpcutil.NotFound {
			return nil, rpcutil.Err(rpcutil.Invalid, "backend %s does not keep snapshots in the image store", sb.Spec.GetBackend())
		}
		return nil, err
	}
	if snap.Base != "" {
		return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s runs on the edge-local image %q, which the store cannot hold", sb.Id, snap.Base)
	}
	m := &images.Manifest{Name: name, Layers: snap.Layers, Env: snap.Env, Workdir: snap.Workdir, User: snap.User,
		Parent: sb.Spec.GetImage(), Source: "snapshot " + sb.Id, CreatedBy: p, Snapshot: snap.ID, Memory: snap.Memory}
	if err := st.PutManifest(m, r.Overwrite); err != nil {
		return nil, err
	}
	return infoPB(m), nil
}

// runningImage describes the layers sandbox sb runs on, as a manifest: its
// snapshot's for a fork copy, else its image's.
func runningImage(st *images.Store, sb *pb.Sandbox) (*images.Manifest, error) {
	if id := sb.Spec.GetSnapshot(); id != "" {
		snap, err := st.GetSnapshot(id)
		if err != nil {
			return nil, err
		}
		if snap.Base != "" {
			return nil, rpcutil.Err(rpcutil.Invalid, "sandbox %s runs on the edge-local image %q, which the store cannot hold", sb.Id, snap.Base)
		}
		return &images.Manifest{Name: sb.Spec.GetImage(), Layers: snap.Layers, Env: snap.Env, Workdir: snap.Workdir, User: snap.User}, nil
	}
	if !images.IsStoreName(sb.Spec.GetImage()) {
		return nil, rpcutil.Err(rpcutil.Invalid, "pack_diff needs a sandbox started from a store image, not %q", sb.Spec.GetImage())
	}
	return st.GetManifest(sb.Spec.GetImage())
}
