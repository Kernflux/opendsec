package cmdutil

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestJournalHandler(t *testing.T) {
	var buf bytes.Buffer
	var h journalHandler
	for i, p := range []string{"<3>", "<4>", "<6>", "<7>"} {
		h[i] = slog.NewTextHandler(prefixWriter{p, &buf}, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	log := slog.New(h).With("ext", "x").WithGroup("g")
	log.Error("e", "k", 1)
	log.Warn("w")
	log.Info("i")
	log.Debug("d") // below the level: not written
	log.Log(nil, slog.LevelWarn+2, "w2")
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	want := []string{"<3>", "<4>", "<6>", "<4>"}
	if len(lines) != len(want) {
		t.Fatalf("lines %q", lines)
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, want[i]+"time=") || !strings.Contains(l, "ext=x") {
			t.Errorf("line %d: %q, want prefix %s and ext=x", i, l, want[i])
		}
	}
	if !strings.Contains(lines[0], "g.k=1") {
		t.Errorf("group lost: %q", lines[0])
	}
}

func TestToJournal(t *testing.T) {
	t.Setenv("JOURNAL_STREAM", "")
	if toJournal() {
		t.Fatal("no JOURNAL_STREAM")
	}
	t.Setenv("JOURNAL_STREAM", "1:2") // another stream: a shell started from a unit
	if toJournal() {
		t.Fatal("JOURNAL_STREAM of another stream")
	}
}
