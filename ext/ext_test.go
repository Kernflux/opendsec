package ext

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type fake struct {
	name string
	got  []json.RawMessage
	err  error
}

func (f *fake) Name() string { return f.name }

func (f *fake) Setup(env Env, conf json.RawMessage) error {
	f.got = append(f.got, conf)
	return f.err
}

func reset() {
	mu.Lock()
	defer mu.Unlock()
	exts, authns, sinks, setupFor = map[string]Extension{}, nil, nil, map[string]bool{}
}

func TestSetup(t *testing.T) {
	reset()
	defer reset()
	log := slog.New(slog.DiscardHandler)

	// The open build: no extensions, and no config for any.
	if err := Setup("apiserver", nil, log); err != nil {
		t.Fatal(err)
	}
	if err := Setup("watcher", map[string]json.RawMessage{"sso": json.RawMessage(`{}`)}, log); err == nil ||
		!strings.Contains(err.Error(), "not in this build") {
		t.Fatalf("config for a missing extension: %v", err)
	}

	reset()
	a, b := &fake{name: "a"}, &fake{name: "b"}
	Register(a)
	Register(b)
	conf := map[string]json.RawMessage{"a": json.RawMessage(`{"x":1}`)}
	if err := Setup("apiserver", conf, log); err != nil {
		t.Fatal(err)
	}
	if len(a.got) != 1 || string(a.got[0]) != `{"x":1}` || len(b.got) != 1 || b.got[0] != nil {
		t.Fatalf("a got %q, b got %q", a.got, b.got)
	}
	// Once per component and process.
	Setup("apiserver", conf, log)
	if len(a.got) != 1 {
		t.Fatal("set up twice")
	}
	b.err = errors.New("boom")
	if err := Setup("edge", conf, log); err == nil || !strings.Contains(err.Error(), "extensions.b: boom") {
		t.Fatalf("failing setup: %v", err)
	}
}
