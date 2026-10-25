package ext

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type fake struct {
	name  string
	got   []json.RawMessage
	err   error
	after func()
}

func (f *fake) Name() string { return f.name }

func (f *fake) Setup(env Env, conf json.RawMessage) error {
	f.got = append(f.got, conf)
	if f.after != nil {
		AfterSetup(f.after)
	}
	return f.err
}

func reset() {
	mu.Lock()
	defer mu.Unlock()
	exts, authns, sinks, after, setupFor = map[string]Extension{}, nil, nil, nil, map[string]bool{}
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

// AfterSetup's functions run once every extension is set up, so an
// extension sees one that comes later in name order (the license).
func TestAfterSetup(t *testing.T) {
	reset()
	defer reset()
	log := slog.New(slog.DiscardHandler)
	z := &fake{name: "z"}
	var zSetUp bool
	a := &fake{name: "a", after: func() { zSetUp = len(z.got) == 1 }}
	Register(a)
	Register(z)
	if err := Setup("apiserver", nil, log); err != nil {
		t.Fatal(err)
	}
	if !zSetUp {
		t.Fatal("a's AfterSetup ran before z was set up")
	}

	// A failed setup runs none of them, nor leaves them to the next one.
	reset()
	ran := 0
	a, z = &fake{name: "a", after: func() { ran++ }}, &fake{name: "z", err: errors.New("boom")}
	Register(a)
	Register(z)
	if err := Setup("apiserver", nil, log); err == nil {
		t.Fatal("no error")
	}
	z.err = nil
	a.after = nil
	if err := Setup("edge", nil, log); err != nil || ran != 0 {
		t.Fatalf("err %v, ran %d", err, ran)
	}
}
