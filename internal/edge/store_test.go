package edge

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// A record must stay readable by the release before pause_deadline, which
// drops records with a field it does not know: the flag goes in a marker
// beside the record.
func TestStorePauseDeadline(t *testing.T) {
	st, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sb := &pb.Sandbox{Id: "e1.kept", State: pb.SandboxState_PAUSED, PauseDeadline: true,
		Spec: &pb.SandboxSpec{Backend: "sim", TtlMaxS: 100, TtlPausedS: 50}}
	if err := st.save("kept", sb); err != nil {
		t.Fatal(err)
	}
	if !sb.PauseDeadline {
		t.Fatal("save changed its argument")
	}
	b, _ := os.ReadFile(st.path("kept"))
	if strings.Contains(string(b), "ause") && strings.Contains(string(b), "eadline") {
		t.Fatalf("the flag is in the record: %s", b)
	}
	if err := protojson.Unmarshal(b, &pb.Sandbox{}); err != nil { // as that release reads it
		t.Fatal(err)
	}
	got, errs := st.load()
	if len(errs) != 0 || !got["kept"].GetPauseDeadline() || got["kept"].Spec.TtlMaxS != 100 {
		t.Fatalf("load: %v %v", got, errs)
	}
	// Cleared, the marker goes.
	sb.PauseDeadline = false
	st.save("kept", sb)
	if got, _ := st.load(); got["kept"].GetPauseDeadline() {
		t.Fatal("the marker outlived the flag")
	}
	// A marker without its record (removed by a release that does not know
	// markers) is cleaned up; remove takes the marker along.
	sb.PauseDeadline = true
	st.save("kept", sb)
	os.Remove(st.path("kept"))
	if got, errs := st.load(); len(got) != 0 || len(errs) != 0 {
		t.Fatalf("load: %v %v", got, errs)
	}
	if _, err := os.Stat(st.deadlinePath("kept")); !os.IsNotExist(err) {
		t.Fatalf("orphan marker: %v", err)
	}
	st.save("kept", sb)
	st.remove("kept")
	if ents, _ := os.ReadDir(st.dir); len(ents) != 0 {
		t.Fatalf("left behind: %v", ents)
	}
	// A record with a field of a later release is kept.
	os.WriteFile(st.path("later"), []byte(`{"id":"e1.later","state":"RUNNING","fieldOfALaterRelease":true}`), 0o600)
	if got, errs := st.load(); len(errs) != 0 || got["later"].GetId() != "e1.later" {
		t.Fatalf("load: %v %v", got, errs)
	}
}

// recordFields are the fields of a sandbox record that every release an
// edge may be rolled back to reads. Releases up to 0.11.0-202611100613
// drop a record holding any other field, and clean up its sandbox; from
// 0.11.0-202611150433 on, unknown fields are ignored.
//
// A field added to pb.Sandbox or pb.SandboxSpec fails the test below. As
// long as a cluster may roll back to a release before 0.11.0-202611150433,
// keep it out of the record (a marker file, as for pause_deadline: see
// store.save); after that, add it here.
var recordFields = map[string][]string{
	"Sandbox": {"id", "project", "principal", "edgeId", "spec", "state", "createdAt", "lastActiveAt", "endedAt", "message"},
	"SandboxSpec": {"backend", "image", "resources", "ttlRunningStopS", "ttlMaxS", "networkRules", "initUser", "taskId",
		"qos", "gpuMode", "labels", "snapshot", "readonlyPaths", "maskedPaths", "ttlPausedS"},
	"Resources": {"cpuCores", "memoryMb", "gpus", "diskMb"},
}

// fill sets every field of m, messages in it included, to something that
// is written out.
func fill(m protoreflect.Message) {
	fds := m.Descriptor().Fields()
	for i := 0; i < fds.Len(); i++ {
		fd := fds.Get(i)
		scalar := func(fd protoreflect.FieldDescriptor) protoreflect.Value {
			switch fd.Kind() {
			case protoreflect.BoolKind:
				return protoreflect.ValueOfBool(true)
			case protoreflect.StringKind:
				return protoreflect.ValueOfString("x")
			case protoreflect.BytesKind:
				return protoreflect.ValueOfBytes([]byte("x"))
			case protoreflect.EnumKind:
				return protoreflect.ValueOfEnum(1)
			case protoreflect.DoubleKind:
				return protoreflect.ValueOfFloat64(1)
			case protoreflect.FloatKind:
				return protoreflect.ValueOfFloat32(1)
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
				return protoreflect.ValueOfInt32(1)
			case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
				return protoreflect.ValueOfUint32(1)
			case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				return protoreflect.ValueOfUint64(1)
			default:
				return protoreflect.ValueOfInt64(1)
			}
		}
		switch {
		case fd.IsMap():
			mv := m.Mutable(fd).Map()
			v := scalar(fd.MapValue())
			if fd.MapValue().Message() != nil {
				v = mv.NewValue()
				fill(v.Message())
			}
			mv.Set(scalar(fd.MapKey()).MapKey(), v)
		case fd.IsList():
			l := m.Mutable(fd).List()
			if fd.Message() != nil {
				fill(l.AppendMutable().Message())
			} else {
				l.Append(scalar(fd))
			}
		case fd.Message() != nil:
			fill(m.Mutable(fd).Message())
		default:
			m.Set(fd, scalar(fd))
		}
	}
}

func TestRecordReadableByEarlierReleases(t *testing.T) {
	st, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sb := &pb.Sandbox{}
	fill(sb.ProtoReflect())
	if err := st.save("full", sb); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(st.path("full"))
	var rec map[string]any
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	check := func(msg string, got map[string]any) {
		for k := range got {
			if !slices.Contains(recordFields[msg], k) {
				t.Errorf("%s.%s is written to the sandbox record: releases an edge may be rolled back to would drop the record and its sandbox (see recordFields)", msg, k)
			}
		}
		for _, k := range recordFields[msg] {
			if _, ok := got[k]; !ok {
				t.Errorf("%s.%s was not written: fill does not set it?", msg, k)
			}
		}
	}
	check("Sandbox", rec)
	spec, _ := rec["spec"].(map[string]any)
	check("SandboxSpec", spec)
	res, _ := spec["resources"].(map[string]any)
	check("Resources", res)
	// And it comes back whole.
	got, errs := st.load()
	if len(errs) != 0 || !proto.Equal(got["full"], sb) {
		t.Fatalf("read back: %v %v", got["full"], errs)
	}
}
