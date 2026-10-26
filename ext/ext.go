// Package ext is where code built outside the open-source edition (the
// enterprise edition's ee/ packages) plugs into the components. Extensions
// register themselves from init(); the open-source build links none, and
// every hook is then a no-op.
package ext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"
)

// Extension is one pluggable feature.
type Extension interface {
	Name() string
	// Setup is called once in each component process (env.Component:
	// "apiserver", ...) with the extension's section of the cluster config,
	// "extensions": {"<name>": ...}, or nil when there is none. It installs
	// the extension's hooks (AddAuthenticator, AddAuditSink). An error stops
	// the component from starting.
	Setup(env Env, conf json.RawMessage) error
}

// Env is what an extension's Setup gets to know about its process.
type Env struct {
	Component string
	Log       *slog.Logger
	// An apiserver's audit log (spec §14.4): its directory ("" when it
	// keeps none) and its files' name, audit-<AuditName>-<time>.log.
	AuditDir, AuditName string
}

// Authenticator resolves bearer tokens IAM does not issue (an SSO
// provider's, for one) to an IAM principal, which IAM then authorizes as
// usual. ok is false for a token that is not one of its own.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (principal string, expires time.Time, ok bool, err error)
}

// AuditSink receives every audit log line (one JSON object, with its
// newline) after it is written to the local log. Write must not block: it
// runs on the audit log's writer.
type AuditSink interface {
	Write(line []byte)
}

// Directory is how an extension keeps IAM principals in step with an
// outside directory (an SSO provider's users and groups): IAM operations
// made as actor, which IAM authorizes as usual. The apiserver installs it.
type Directory interface {
	// CreatePrincipal creates principal id in project, with no usable
	// token of its own; ErrExists if a principal of that name exists
	// (one the extension made is one it recorded in its state).
	CreatePrincipal(ctx context.Context, actor, project, id, kind string) error
	// SetGrants makes principal's permissions on project exactly perms.
	SetGrants(ctx context.Context, actor, project, principal string, perms []string) error
	// GetState reads key of the extensions' area of IAM's key-value store,
	// shared by every apiserver: nil and revision 0 when it is not there.
	GetState(ctx context.Context, key string) ([]byte, uint64, error)
	// PutState writes key if its revision is still rev (0: it must not
	// exist yet); ErrConflict otherwise.
	PutState(ctx context.Context, key string, value []byte, rev uint64) error
}

var (
	ErrExists   = errors.New("exists")
	ErrConflict = errors.New("changed meanwhile")
)

var (
	mu          sync.Mutex
	dir         Directory
	exts        = map[string]Extension{}
	authns      []Authenticator
	sinks       []AuditSink
	after       []func() // AfterSetup's, for the component being set up
	notices     []func() string
	clusterCPUs func() int
	setupFor    = map[string]bool{}
)

// Register adds an extension to the build; call it from init().
func Register(e Extension) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := exts[e.Name()]; dup {
		panic("ext: " + e.Name() + " registered twice")
	}
	exts[e.Name()] = e
}

// Names lists the extensions linked into this build.
func Names() []string {
	mu.Lock()
	defer mu.Unlock()
	var n []string
	for k := range exts {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Setup sets up every linked extension for component, with its section of
// conf (the cluster config's "extensions"). A section naming an extension
// this build does not have is an error: its feature would silently be off.
func Setup(component string, conf map[string]json.RawMessage, log *slog.Logger) error {
	return SetupWith(Env{Component: component, Log: log}, conf)
}

// SetupWith is Setup with what env tells of the process.
func SetupWith(env Env, conf map[string]json.RawMessage) error {
	component, log := env.Component, env.Log
	names := Names()
	for name := range conf {
		if !slices.Contains(names, name) {
			return fmt.Errorf("extensions.%s: not in this build (an enterprise edition feature?)", name)
		}
	}
	mu.Lock()
	if setupFor[component] {
		mu.Unlock()
		return nil // several components in one process (tests, dev clusters)
	}
	setupFor[component] = true
	mu.Unlock()
	for _, name := range names {
		mu.Lock()
		e := exts[name]
		mu.Unlock()
		ee := env
		ee.Log = log.With("ext", name)
		if err := e.Setup(ee, conf[name]); err != nil {
			mu.Lock()
			after = nil
			mu.Unlock()
			return fmt.Errorf("extensions.%s: %w", name, err)
		}
	}
	mu.Lock()
	fs := after
	after = nil
	mu.Unlock()
	for _, f := range fs {
		f()
	}
	return nil
}

// AfterSetup runs f once every extension of the component is set up (call
// it from Setup): work that needs another extension, such as a check of
// the license, which extensions set up earlier in name order lack.
func AfterSetup(f func()) {
	mu.Lock()
	defer mu.Unlock()
	after = append(after, f)
}

// AddNotice adds a line the apiserver's ClusterStatus reports (from
// Setup): f is called each time; "" adds nothing.
func AddNotice(f func() string) {
	mu.Lock()
	defer mu.Unlock()
	notices = append(notices, f)
}

// Notices returns the extensions' lines, for ClusterStatus.
func Notices() []string {
	mu.Lock()
	fs := notices
	mu.Unlock()
	var out []string
	for _, f := range fs {
		if s := f(); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// SetClusterCPUs installs how to count the cluster's CPU threads (the
// apiserver does: its edges' hosts, each counted once).
func SetClusterCPUs(f func() int) {
	mu.Lock()
	defer mu.Unlock()
	clusterCPUs = f
}

// ClusterCPUs counts the cluster's CPU threads; false in a process with
// no apiserver, or before any edge has reported.
func ClusterCPUs() (int, bool) {
	mu.Lock()
	f := clusterCPUs
	mu.Unlock()
	if f == nil {
		return 0, false
	}
	n := f()
	return n, n > 0
}

// AddAuthenticator installs an authenticator (from Setup).
func AddAuthenticator(a Authenticator) {
	mu.Lock()
	defer mu.Unlock()
	authns = append(authns, a)
}

// Authenticators returns the installed authenticators.
func Authenticators() []Authenticator {
	mu.Lock()
	defer mu.Unlock()
	return authns
}

// AddAuditSink installs an audit sink (from Setup).
func AddAuditSink(s AuditSink) {
	mu.Lock()
	defer mu.Unlock()
	sinks = append(sinks, s)
}

// AuditSinks returns the installed audit sinks.
func AuditSinks() []AuditSink {
	mu.Lock()
	defer mu.Unlock()
	return sinks
}

// SetDirectory installs the directory (the apiserver does, once it has
// its IAM connection).
func SetDirectory(d Directory) {
	mu.Lock()
	defer mu.Unlock()
	dir = d
}

// Dir returns the installed directory, or nil.
func Dir() Directory {
	mu.Lock()
	defer mu.Unlock()
	return dir
}
