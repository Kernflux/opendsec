package e2b

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/ids"
)

// Fork and snapshots (spec §37.10). E2B's fork is ForkSandbox; a snapshot
// is an image made by CreateSnapshot in the gateway's project, its
// snapshotID the image's name, so Sandbox.create(snapshot_id) creates from
// that image like any OpenDsec image name.

// maxForks is E2B's bound on one fork call.
const maxForks = 100

type forkResult struct {
	Sandbox *sandboxResp   `json:"sandbox,omitempty"`
	Error   map[string]any `json:"error,omitempty"`
}

func (g *Gateway) fork(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := struct {
		Timeout *int64 `json:"timeout"`
		Count   int32  `json:"count"`
	}{Count: 1}
	if !decode(w, r, &req) {
		return
	}
	if req.Count < 1 || req.Count > maxForks {
		writeErr(w, http.StatusBadRequest, "count must be between 1 and 100")
		return
	}
	timeout := int64(15) // E2B's default
	if req.Timeout != nil {
		timeout = *req.Timeout
	}
	timeout = max(g.timeout(timeout), 1)
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	st, err := g.api.ForkSandbox(ctx, &pb.ForkSandboxRequest{SandboxId: sb.Id, Count: req.Count,
		TtlMaxS: timeout, TtlRunningStopS: timeout})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	out := make([]forkResult, req.Count)
	got := 0
	for {
		res, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if got == 0 { // the source could not be snapshotted: the whole call fails
				writeAPIErr(w, err)
				return
			}
			for i := range out { // copies not reported share the stream's error
				if out[i].Sandbox == nil && out[i].Error == nil {
					out[i].Error = errBody(httpStatus(err), err.Error())
				}
			}
			break
		}
		got++
		if res.Index < 0 || res.Index >= req.Count {
			continue
		}
		if res.Sandbox != nil {
			sr := g.sandboxResp(res.Sandbox, apiKey(r))
			out[res.Index].Sandbox = &sr
		} else {
			out[res.Index].Error = errBody(reasonStatus(res.ErrorReason), res.ErrorMessage)
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

// snapshotInfo is E2B's SnapshotInfo.
type snapshotInfo struct {
	SnapshotID string   `json:"snapshotID"`
	Names      []string `json:"names"`
}

// snapshotImage is the image name for E2B snapshot name in project: "name"
// and "name:tag" are in the project, a name with a "/" is an OpenDsec image
// name; the tag defaults to E2B's "default". No name: a new one.
func snapshotImage(project, name string) string {
	switch {
	case name == "":
		name = project + "/snapshot-" + ids.NewLease()[:16]
	case !strings.Contains(name, "/"):
		name = project + "/" + name
	}
	if !strings.Contains(name[strings.LastIndexByte(name, '/'):], ":") {
		name += ":default"
	}
	return name
}

func (g *Gateway) createSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Memory *bool  `json:"memory"`
	}
	if !decode(w, r, &req) {
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	// E2B snapshots keep memory unless asked not to; a container has none.
	memory := sb.GetSpec().GetBackend() != "container"
	if req.Memory != nil {
		memory = *req.Memory
	}
	// A name that exists gets the new snapshot, as in E2B.
	img, err := g.api.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{SandboxId: sb.Id,
		Image: snapshotImage(g.project(r), req.Name), Memory: memory, Overwrite: req.Name != ""})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshotInfo{SnapshotID: img.Name, Names: []string{img.Name}})
}

// sourcePrefix starts the source of images CreateSnapshot makes.
const sourcePrefix = "snapshot "

func (g *Gateway) listSnapshots(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := ""
	if e := q.Get("sandboxID"); e != "" {
		id, err := fromE2B(e)
		if err != nil {
			writeJSON(w, http.StatusOK, []snapshotInfo{})
			return
		}
		source = sourcePrefix + id
	}
	var names []string
	if n := q.Get("name"); n != "" {
		names = []string{n, snapshotImage(g.project(r), n)}
	}
	l, err := g.api.ListImages(ctx, &pb.ListImagesRequest{Project: g.project(r)})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	out := []snapshotInfo{}
	for _, img := range l.Images {
		if img.Snapshot == "" || !strings.HasPrefix(img.Source, sourcePrefix) ||
			source != "" && img.Source != source || names != nil && !slices.Contains(names, img.Name) {
			continue
		}
		out = append(out, snapshotInfo{SnapshotID: img.Name, Names: []string{img.Name}})
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteSnapshot is E2B's template deletion, which its SDKs use to delete
// snapshots; other images are not deleted through the gateway.
func (g *Gateway) deleteSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("id")
	img, err := g.api.GetImage(ctx, &pb.ImageRef{Name: name})
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	if img.Snapshot == "" || !strings.HasPrefix(img.Source, sourcePrefix) {
		writeErr(w, http.StatusBadRequest, name+" is not a snapshot: the E2B gateway deletes only snapshots")
		return
	}
	if _, err := g.api.DeleteImage(ctx, &pb.ImageRef{Name: name}); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
