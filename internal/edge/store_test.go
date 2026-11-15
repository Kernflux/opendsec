package edge

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

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
