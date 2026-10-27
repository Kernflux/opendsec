// Package nodeagent is the agent on every machine (spec §28.4). It reports
// the machine's state to the fleet service and carries out the operations
// it hands back: download a release, switch to it, write the config, restart
// units. It makes no decisions of its own, accepts only those operations,
// and only touches /opt/opendsec, /etc/opendsec and OpenDsec's units.
package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/release"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Options configure an agent. Paths default to the production layout
// (spec §27.4); tests point them into a temporary directory.
type Options struct {
	Name, Addr string
	Fleet      pb.FleetClient
	Version    string

	Root      string // /opt/opendsec: releases/<v>, current -> releases/<v>
	BinDir    string // /usr/local/bin: links to current/bin/*
	Etc       string // /etc/opendsec
	UnitDir   string // /etc/systemd/system
	StateFile string // /var/lib/opendsec/nodeagent.json
	Store     string // /mnt/opendsec-images, reported as mounted or not
	// AgentPath is the binary the agent's unit runs, outside any release
	// (/opt/opendsec/agent/opendsec-nodeagent): a release's agent replaces
	// it only after passing its own -check, so a broken agent never takes
	// the node out of reach.
	AgentPath string
	Group     string // owner group of config files, default opendsec

	Systemd Systemd
	// Ready probes a /readyz URL; default: HTTP GET answering 200.
	Ready func(ctx context.Context, url string) error
	// IAMLeader reports whether the IAM replica with the given readiness URL
	// leads; default: read opendsec_iam_leader from its /metrics.
	IAMLeader func(ctx context.Context, readyz string) bool

	Interval     time.Duration // until the fleet says otherwise; default 10s
	KeepReleases int           // releases kept on the node besides current; default 2
	Log          *slog.Logger
}

func (o *Options) defaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&o.Root, "/opt/opendsec")
	def(&o.BinDir, "/usr/local/bin")
	def(&o.Etc, "/etc/opendsec")
	def(&o.UnitDir, "/etc/systemd/system")
	def(&o.StateFile, "/var/lib/opendsec/nodeagent.json")
	def(&o.Store, "/mnt/opendsec-images")
	def(&o.Group, "opendsec")
	def(&o.AgentPath, filepath.Join(o.Root, "agent", "opendsec-nodeagent"))
	if o.Systemd == nil {
		o.Systemd = Systemctl{}
	}
	if o.Ready == nil {
		o.Ready = httpReady
	}
	if o.IAMLeader == nil {
		o.IAMLeader = iamLeaderFromMetrics
	}
	if o.Interval == 0 {
		o.Interval = 10 * time.Second
	}
	if o.KeepReleases == 0 {
		o.KeepReleases = 2
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
}

// Agent runs the heartbeat loop and one operation at a time.
type Agent struct {
	o     Options
	start time.Time

	mu       sync.Mutex
	op       *pb.OpStatus // running or last operation (persisted)
	gen      uint64       // config generation last written (persisted)
	running  bool
	units    []*pb.NodeUnit // what the fleet says this node runs
	applied  []string       // the units of the last apply that succeeded (persisted; nil: not known)
	retired  bool
	interval time.Duration
	kick     chan struct{}
	versions map[string]map[string]string // release -> runtime versions
}

type persisted struct {
	Op      *pb.OpStatus `json:"op"`
	Gen     uint64       `json:"config_gen"`
	Applied []string     `json:"applied_units,omitempty"`
}

func New(o Options) *Agent {
	o.defaults()
	a := &Agent{o: o, start: time.Now(), interval: o.Interval, kick: make(chan struct{}, 1),
		versions: map[string]map[string]string{}}
	if b, err := os.ReadFile(o.StateFile); err == nil {
		var p persisted
		if json.Unmarshal(b, &p) == nil {
			a.op, a.gen, a.applied = p.Op, p.Gen, p.Applied
			if a.op != nil && a.op.State == "running" { // the agent died mid-operation
				a.op.State, a.op.Message, a.op.Finished = "failed", "agent restarted during the operation", now()
			}
		}
	}
	return a
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (a *Agent) save() {
	a.mu.Lock()
	b, _ := json.Marshal(persisted{Op: a.op, Gen: a.gen, Applied: a.applied})
	a.mu.Unlock()
	os.MkdirAll(filepath.Dir(a.o.StateFile), 0o755)
	tmp := a.o.StateFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, a.o.StateFile)
	}
}

// Run heartbeats until ctx ends. Without the fleet, nothing on the node
// changes and every component keeps running (spec §28.4).
func (a *Agent) Run(ctx context.Context) {
	for {
		a.beat(ctx)
		a.mu.Lock()
		iv := a.interval
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		case <-a.kick:
		}
	}
}

func (a *Agent) beat(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	st := a.Status(cctx)
	resp, err := a.o.Fleet.Heartbeat(cctx, &pb.HeartbeatRequest{Node: a.o.Name, Addr: a.o.Addr, Status: st})
	if err != nil {
		if ctx.Err() == nil {
			a.o.Log.Warn("heartbeat", "err", err)
		}
		return
	}
	a.mu.Lock()
	if resp.IntervalS > 0 {
		a.interval = time.Duration(resp.IntervalS * float64(time.Second))
	}
	if len(resp.Units) > 0 {
		a.units = resp.Units
	}
	retire := resp.State == "retired" && !a.retired
	a.retired = resp.State == "retired"
	applied := a.applied
	a.mu.Unlock()
	if retire {
		go a.retire(ctx, resp.Units, applied)
		return
	}
	if resp.Op != nil && resp.State != "retired" { // a retired node runs nothing again
		a.maybeStart(ctx, resp.Op)
	}
}

func (a *Agent) maybeStart(ctx context.Context, op *pb.NodeOp) {
	a.mu.Lock()
	if a.running || (a.op != nil && a.op.OpId == op.OpId) {
		a.mu.Unlock()
		return // one at a time; an operation handed out again is not redone
	}
	a.running = true
	a.op = &pb.OpStatus{OpId: op.OpId, Kind: op.Kind, State: "running", Started: now()}
	a.mu.Unlock()
	a.save()
	go func() {
		a.o.Log.Info("operation", "op", op.OpId, "kind", op.Kind, "release", op.Release, "config_gen", op.ConfigGen)
		restartSelf, err := a.execute(ctx, op)
		a.mu.Lock()
		a.running = false
		a.op.Finished = now()
		if err != nil {
			a.op.State, a.op.Message = "failed", err.Error()
		} else {
			a.op.State = "ok"
		}
		a.mu.Unlock()
		a.save()
		if err != nil {
			a.o.Log.Warn("operation failed", "op", op.OpId, "err", err)
		} else {
			a.o.Log.Info("operation done", "op", op.OpId)
		}
		if restartSelf {
			a.o.Log.Info("restarting into the new release's node agent")
			if err := a.o.Systemd.RestartSelf(context.Background()); err != nil {
				a.o.Log.Warn("restart self", "err", err)
			}
		}
		select {
		case a.kick <- struct{}{}: // report at once
		default:
		}
	}()
}

// retire stops the node's units: those of its roles, and those last
// applied (roles changed since run until the next apply).
func (a *Agent) retire(ctx context.Context, units []*pb.NodeUnit, applied []string) {
	a.o.Log.Info("node retired: stopping its components")
	var names []string
	for _, u := range units {
		names = append(names, u.Unit)
	}
	for _, u := range applied {
		if !slices.Contains(names, u) {
			names = append(names, u)
		}
	}
	for i := len(names) - 1; i >= 0; i-- {
		a.stopUnit(ctx, names[i])
	}
}

// stopUnit disables and stops u (failures are logged: the unit is not
// wanted either way).
func (a *Agent) stopUnit(ctx context.Context, u string) {
	if !allowedUnit(u) {
		return
	}
	if err := a.o.Systemd.Run(ctx, "disable", u); err != nil {
		a.o.Log.Warn("disable", "unit", u, "err", err)
	}
	if err := a.o.Systemd.Run(ctx, "stop", u); err != nil {
		a.o.Log.Warn("stop", "unit", u, "err", err)
	}
}

// unitNames is the units of op.
func unitNames(units []*pb.NodeUnit) []string {
	out := make([]string, 0, len(units))
	for _, u := range units {
		out = append(out, u.Unit)
	}
	return out
}

// ---- status -----------------------------------------------------------------------

// Status describes the node for a heartbeat.
func (a *Agent) Status(ctx context.Context) *pb.NodeStatus {
	st := &pb.NodeStatus{AgentVersion: a.o.Version, DiskFreeMb: map[string]int64{}}
	st.Hostname, _ = os.Hostname()
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		st.Kernel = cstr(u.Release[:])
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			st.UptimeS, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	st.CurrentRelease = a.current()
	if es, err := os.ReadDir(filepath.Join(a.o.Root, "releases")); err == nil {
		for _, e := range es {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				st.Releases = append(st.Releases, e.Name())
			}
		}
	}
	for _, p := range []string{"/", "/data", a.o.Root} {
		var fs syscall.Statfs_t
		if syscall.Statfs(p, &fs) == nil {
			st.DiskFreeMb[p] = int64(fs.Bavail) * fs.Bsize >> 20
		}
	}
	st.StoreMounted = mounted(a.o.Store)
	a.mu.Lock()
	units := a.units
	st.ConfigGen = a.gen
	if a.op != nil {
		st.Op = proto.Clone(a.op).(*pb.OpStatus)
	}
	a.mu.Unlock()
	for _, nu := range units {
		us := &pb.UnitStatus{Unit: nu.Unit, ActiveState: a.o.Systemd.ActiveState(ctx, nu.Unit)}
		if us.ActiveState != "active" {
			us.Reason = "unit " + us.ActiveState
		} else if nu.Readyz == "" {
			us.Ready = true
		} else if err := a.o.Ready(ctx, nu.Readyz); err != nil {
			us.Reason = err.Error()
		} else {
			us.Ready = true
		}
		if strings.HasPrefix(nu.Unit, "opendsec-iam@") && us.Ready && nu.Readyz != "" {
			us.IamLeader = a.o.IAMLeader(ctx, nu.Readyz)
		}
		st.Units = append(st.Units, us)
	}
	st.RuntimeVersions = a.runtimeVersions(ctx, st.CurrentRelease)
	return st
}

func cstr(b []int8) string {
	var s []byte
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

func mounted(p string) bool {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 1 && fs[1] == p {
			return true
		}
	}
	return false
}

// current is the release /opt/opendsec/current points at ("" if none).
func (a *Agent) current() string {
	t, err := os.Readlink(filepath.Join(a.o.Root, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// runtimeVersions reports the versions of the release's runtime binaries
// (spec §28.12), probed once per release.
func (a *Agent) runtimeVersions(ctx context.Context, rel string) map[string]string {
	if rel == "" {
		return nil
	}
	a.mu.Lock()
	v, ok := a.versions[rel]
	a.mu.Unlock()
	if ok {
		return v
	}
	v = map[string]string{}
	fc := filepath.Join(a.o.Root, "releases", rel, "bin", "firecracker")
	if _, err := os.Stat(fc); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		out, err := exec.CommandContext(cctx, fc, "--version").Output()
		cancel()
		if err == nil {
			v["firecracker"] = FirecrackerVersion(string(out))
		}
	}
	a.mu.Lock()
	a.versions[rel] = v
	a.mu.Unlock()
	return v
}

// FirecrackerVersion extracts "1.17.0" from `firecracker --version` output
// ("Firecracker v1.17.0\n...").
func FirecrackerVersion(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return strings.TrimPrefix(f[len(f)-1], "v")
}

func httpReady(ctx context.Context, url string) error {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("readyz %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func iamLeaderFromMetrics(ctx context.Context, readyz string) bool {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", strings.TrimSuffix(readyz, "/readyz")+"/metrics", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "opendsec_iam_leader{") && strings.HasSuffix(l, " 1") {
			return true
		}
	}
	return false
}

// ---- operations ---------------------------------------------------------------------

// execute runs op; it reports whether the agent should restart itself into
// a new release's binary afterwards.
func (a *Agent) execute(ctx context.Context, op *pb.NodeOp) (bool, error) {
	timeout := time.Duration(op.TimeoutS * float64(time.Second))
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	for _, u := range op.Units {
		if !allowedUnit(u.Unit) {
			return false, fmt.Errorf("unit %q is not an OpenDsec unit", u.Unit)
		}
	}
	for _, f := range op.Files {
		if !allowedFile(f.Name) {
			return false, fmt.Errorf("file %q may not be written by the agent", f.Name)
		}
	}
	switch op.Kind {
	case "stage":
		return false, a.stage(ctx, op)
	case "apply":
		return a.apply(ctx, op, timeout)
	case "restart", "start", "stop":
		for _, u := range op.Units {
			if err := a.o.Systemd.Run(ctx, op.Kind, u.Unit); err != nil {
				return false, err
			}
			if op.Kind != "stop" {
				if err := a.waitReady(ctx, u, timeout); err != nil {
					return false, err
				}
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("unknown operation %q", op.Kind)
}

// stage makes release op.Release present and verified under releases/.
func (a *Agent) stage(ctx context.Context, op *pb.NodeOp) error {
	if !release.ValidVersion(op.Release) {
		return fmt.Errorf("bad release %q", op.Release)
	}
	rels := filepath.Join(a.o.Root, "releases")
	if err := os.MkdirAll(rels, 0o755); err != nil {
		return err
	}
	if release.VerifyDir(filepath.Join(rels, op.Release)) == nil {
		return nil // already here (shipped by opendsecops, or staged before)
	}
	part := filepath.Join(rels, "."+op.Release+".tgz.part")
	var err error
	mismatches := 0
	for try := 0; try < 20; try++ {
		if err = a.download(ctx, op, part); err == nil {
			break
		}
		if errors.Is(err, errMismatch) {
			mismatches++
		}
		if rpcutil.Reason(err) == rpcutil.Invalid || rpcutil.Reason(err) == rpcutil.NotFound && try >= 4 ||
			mismatches >= 3 || ctx.Err() != nil {
			break
		}
		a.o.Log.Warn("download", "release", op.Release, "try", try, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(min(try+1, 10)) * time.Second):
		}
	}
	if err != nil {
		return err
	}
	f, err := os.Open(part)
	if err != nil {
		return err
	}
	defer os.Remove(part)
	defer f.Close()
	return release.Unpack(f, rels, op.Release)
}

// download fetches the tarball into part, resuming what is there, and
// checks its size and sha256.
func (a *Agent) download(ctx context.Context, op *pb.NodeOp, part string) error {
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if off > op.Size {
		f.Truncate(0)
		off, _ = f.Seek(0, 0)
	}
	if off < op.Size {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		stream, err := a.o.Fleet.FetchRelease(cctx, &pb.FetchReleaseRequest{Version: op.Release, Offset: off})
		if err != nil {
			return err
		}
		for {
			c, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if _, err := f.Write(c.Data); err != nil {
				return err
			}
		}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != op.Size || hex.EncodeToString(h.Sum(nil)) != op.Sha256 {
		f.Truncate(0)
		return fmt.Errorf("release %s: downloaded %d bytes (want %d): %w", op.Release, n, op.Size, errMismatch)
	}
	return nil
}

var errMismatch = errors.New("size or sha256 differs from the release record")

// undo is what apply restores on failure.
type undo struct {
	current string            // previous target of current ("" none)
	files   map[string][]byte // previous contents (nil: did not exist)
}

// apply stages, switches, writes the config and restarts the units in
// order, each until ready; on any failure it puts the previous release,
// config and units back and restarts them again.
func (a *Agent) apply(ctx context.Context, op *pb.NodeOp, timeout time.Duration) (bool, error) {
	prev := a.current()
	a.mu.Lock()
	prevUnits := a.applied
	a.mu.Unlock()
	if op.Release != "" {
		if err := a.stage(ctx, op); err != nil {
			return false, err
		}
	}
	u := undo{files: map[string][]byte{}}
	if t, err := os.Readlink(filepath.Join(a.o.Root, "current")); err == nil {
		u.current = t
	}
	for _, f := range op.Files {
		if !allowedFile(f.Name) {
			return false, fmt.Errorf("file %q may not be written by the agent", f.Name)
		}
		b, err := os.ReadFile(filepath.Join(a.o.Etc, f.Name))
		if err == nil {
			u.files[f.Name] = b
		} else {
			u.files[f.Name] = nil
		}
	}
	err := a.applySteps(ctx, op, prevUnits, timeout)
	if err == nil {
		a.mu.Lock()
		if op.ConfigGen != 0 {
			a.gen = op.ConfigGen
		}
		a.applied = unitNames(op.Units)
		a.mu.Unlock()
		a.prune()
		if op.Release == "" || op.Release == prev {
			return false, nil
		}
		restart, err := a.installAgent(ctx, op.Release)
		if err != nil { // the release runs; only the agent stays as it is
			a.o.Log.Warn("keeping the running node agent", "err", err)
		}
		return restart, nil
	}
	a.o.Log.Warn("apply failed: putting the previous release and config back", "err", err)
	if rerr := a.restore(ctx, op, u, prevUnits, timeout); rerr != nil {
		return false, fmt.Errorf("%v; restoring the previous state also failed: %v", err, rerr)
	}
	return false, err
}

// applySteps switches, writes the files and runs op's units. Units applied
// before and not in op (a role removed, or its instance renumbered) are
// stopped first: the new ones may need their ports.
func (a *Agent) applySteps(ctx context.Context, op *pb.NodeOp, prevUnits []string, timeout time.Duration) error {
	if op.Release != "" {
		if err := a.switchTo("releases/" + op.Release); err != nil {
			return err
		}
	}
	for _, f := range op.Files {
		if err := a.writeFile(f.Name, f.Content, os.FileMode(f.Mode)); err != nil {
			return err
		}
	}
	if err := a.installUnits(ctx); err != nil {
		return err
	}
	want := unitNames(op.Units)
	for _, u := range prevUnits {
		if !slices.Contains(want, u) {
			a.stopUnit(ctx, u)
		}
	}
	for _, nu := range op.Units {
		if err := a.o.Systemd.Run(ctx, "enable", nu.Unit); err != nil {
			return err
		}
		if err := a.o.Systemd.Run(ctx, "restart", nu.Unit); err != nil {
			return err
		}
		if err := a.waitReady(ctx, nu, timeout); err != nil {
			return err
		}
	}
	return nil
}

// restore puts back the release, files and units from before op: the
// units applied before (when known; else op's), with op's others stopped.
func (a *Agent) restore(ctx context.Context, op *pb.NodeOp, u undo, prevUnits []string, timeout time.Duration) error {
	if u.current != "" {
		if err := a.switchTo(u.current); err != nil {
			return err
		}
	}
	for name, b := range u.files {
		if b == nil {
			os.Remove(filepath.Join(a.o.Etc, name))
			continue
		}
		if err := a.writeFile(name, b, 0o640); err != nil {
			return err
		}
	}
	if err := a.installUnits(ctx); err != nil {
		return err
	}
	units := op.Units
	if prevUnits != nil {
		units = nil
		for _, nu := range op.Units {
			if slices.Contains(prevUnits, nu.Unit) {
				units = append(units, nu)
			} else {
				a.stopUnit(ctx, nu.Unit)
			}
		}
		for _, name := range prevUnits {
			if !slices.Contains(unitNames(op.Units), name) {
				units = append(units, &pb.NodeUnit{Unit: name}) // stopped by applySteps; no /readyz known
			}
		}
	}
	var errs []error
	for _, nu := range units {
		if err := a.o.Systemd.Run(ctx, "enable", nu.Unit); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := a.o.Systemd.Run(ctx, "restart", nu.Unit); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := a.waitReady(ctx, nu, timeout); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func allowedFile(name string) bool { return name == "opendsec.json" || name == "edge.env" }

// switchTo points current at target (relative to Root) and the bin links at it.
func (a *Agent) switchTo(target string) error {
	if _, err := os.Stat(filepath.Join(a.o.Root, target)); err != nil {
		return err
	}
	tmp := filepath.Join(a.o.Root, "current.new")
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(a.o.Root, "current")); err != nil {
		return err
	}
	bins, _ := filepath.Glob(filepath.Join(a.o.Root, "current", "bin", "*"))
	if err := os.MkdirAll(a.o.BinDir, 0o755); err != nil {
		return err
	}
	for _, b := range bins {
		link := filepath.Join(a.o.BinDir, filepath.Base(b))
		want := filepath.Join(a.o.Root, "current", "bin", filepath.Base(b))
		if t, err := os.Readlink(link); err == nil && t == want {
			continue
		}
		tmp := link + ".new"
		os.Remove(tmp)
		if err := os.Symlink(want, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, link); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) writeFile(name string, b []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o640
	}
	if err := os.MkdirAll(a.o.Etc, 0o755); err != nil {
		return err
	}
	p := filepath.Join(a.o.Etc, name)
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if g, err := user.LookupGroup(a.o.Group); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			os.Chown(tmp, 0, gid)
		}
	}
	os.Chmod(tmp, mode)
	return os.Rename(tmp, p)
}

// installUnits copies the current release's unit files into place.
func (a *Agent) installUnits(ctx context.Context) error {
	units, _ := filepath.Glob(filepath.Join(a.o.Root, "current", "units", "opendsec-*.service"))
	if len(units) == 0 {
		return nil // a release without units: keep the installed ones
	}
	if err := os.MkdirAll(a.o.UnitDir, 0o755); err != nil {
		return err
	}
	for _, src := range units {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		dst := filepath.Join(a.o.UnitDir, filepath.Base(src))
		if cur, err := os.ReadFile(dst); err == nil && string(cur) == string(b) {
			continue
		}
		if err := os.WriteFile(dst+".new", b, 0o644); err != nil {
			return err
		}
		if err := os.Rename(dst+".new", dst); err != nil {
			return err
		}
	}
	return a.o.Systemd.DaemonReload(ctx)
}

// waitReady waits until unit is active and its /readyz answers.
func (a *Agent) waitReady(ctx context.Context, nu *pb.NodeUnit, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		state := a.o.Systemd.ActiveState(ctx, nu.Unit)
		if state == "failed" { // systemd gave up restarting it
			return fmt.Errorf("%s failed", nu.Unit)
		}
		if state == "active" {
			if nu.Readyz == "" {
				return nil
			}
			err := a.o.Ready(ctx, nu.Readyz)
			if err == nil {
				return nil
			}
			last = err.Error()
		} else {
			last = "unit " + state
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not ready after %v: %s", nu.Unit, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// installAgent puts release rel's agent at AgentPath if it differs from
// the one there and passes `-check`; it reports whether to restart into it.
// The replaced binary stays as AgentPath.prev.
func (a *Agent) installAgent(ctx context.Context, rel string) (bool, error) {
	src := filepath.Join(a.o.Root, "releases", rel, "bin", "opendsec-nodeagent")
	nb, err := os.ReadFile(src)
	if err != nil {
		return false, nil // a release without an agent
	}
	if cur, err := os.ReadFile(a.o.AgentPath); err == nil && bytes.Equal(cur, nb) {
		return false, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, src, "-check").CombinedOutput(); err != nil {
		return false, fmt.Errorf("release %s's node agent fails its check: %v: %s", rel, err, strings.TrimSpace(string(out)))
	}
	if err := os.MkdirAll(filepath.Dir(a.o.AgentPath), 0o755); err != nil {
		return false, err
	}
	tmp := a.o.AgentPath + ".new"
	if err := os.WriteFile(tmp, nb, 0o755); err != nil {
		return false, err
	}
	if _, err := os.Stat(a.o.AgentPath); err == nil {
		os.Remove(a.o.AgentPath + ".prev")
		if err := os.Link(a.o.AgentPath, a.o.AgentPath+".prev"); err != nil {
			return false, err
		}
	}
	return true, os.Rename(tmp, a.o.AgentPath)
}

// prune keeps the current release and the newest KeepReleases others:
// sandboxes already running mount agents from the release they started on.
func (a *Agent) prune() {
	dir := filepath.Join(a.o.Root, "releases")
	es, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cur := a.current()
	type rel struct {
		name string
		mod  time.Time
	}
	var rs []rel
	for _, e := range es {
		if !e.IsDir() || e.Name() == cur || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			rs = append(rs, rel{e.Name(), fi.ModTime()})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].mod.After(rs[j].mod) })
	for i, r := range rs {
		if i >= a.o.KeepReleases {
			os.RemoveAll(filepath.Join(dir, r.name))
			a.o.Log.Info("old release removed", "release", r.name)
		}
	}
}
