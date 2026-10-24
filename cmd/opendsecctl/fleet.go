package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/release"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

const fleetUsage = `usage: opendsecctl fleet <command> [flags]   (cluster management, spec §28)

nodes            [-state S] [-role R] [-domain D]      list machines with their last heartbeat
node get         <name>
node accept      <name> -roles edge=<id>[,...] [-domain D] [-addr-ip IP] [-labels k=v,...]
node cordon|uncordon|retire|sync|unpin <name>
node pin         <name> [-reason R]
node set         <name> [-roles ...] [-domain D] [-addr-ip IP] [-labels k=v,k=]   ("k=" removes a label)
node evacuate    <name> [-deadline 1h]                cordon, then wait for its sandboxes to end
import           -inventory FILE -release V [-config-gen G] [-domain D]   machines already running V
releases
release pack     -bin BIN_DIR -units DIR [-deps DIR] -out DIR   build a release directory
release push     <release-dir> [-notes N]
config put       <cluster.json> [-note N]
config get       [-gen N] [-out FILE]
rollout create   [-release V] [-config-gen G] [-roles r,..] [-domains d,..] [-nodes n,..] [-labels k=v,..]
                 [-canary N] [-bake S] [-batch N] [-max-per-domain N] [-pause S] [-max-failures N] [-step-timeout S] [-note N]
rollout status   [<id>] [-steps]                       (default: the newest)
rollout pause|resume|abort|rollback <id>
rollouts

connection: -addr/-token/-ca as for other commands (through an apiserver), or
  -direct -fleet host:port,... -pki DIR -ops-id ID   (an ops certificate, when no apiserver is up)
`

type fleetFlags struct {
	cn                                 *conn
	direct                             bool
	fleetAddr, pkiDir, opsID           string
	state, role, domain, roles, labels string
	addr, reason, inventory, rel, note string
	gen                                uint64
	deadline                           time.Duration
	bin, units, deps, out              string
	domains, nodes                     string
	canary, batch, perDomain, maxFail  int
	bake, pause, stepTimeout           float64
	steps                              bool
}

func fleetCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, fleetUsage)
		os.Exit(2)
	}
	cmd, args := args[0], args[1:]
	if (cmd == "node" || cmd == "release" || cmd == "config" || cmd == "rollout") && len(args) > 0 {
		cmd, args = cmd+" "+args[0], args[1:]
	}
	fs := flag.NewFlagSet("fleet "+cmd, flag.ExitOnError)
	f := &fleetFlags{cn: connFlags(fs)}
	fs.BoolVar(&f.direct, "direct", false, "talk to the fleet replicas with an ops certificate")
	fs.StringVar(&f.fleetAddr, "fleet", os.Getenv("OPENDSEC_FLEET"), "fleet replicas, with -direct")
	fs.StringVar(&f.pkiDir, "pki", "", "directory with ca.crt and ops-<id>.crt/.key, with -direct")
	fs.StringVar(&f.opsID, "ops-id", "", "the ops certificate's id, with -direct")
	fs.StringVar(&f.state, "state", "", "filter by state")
	fs.StringVar(&f.role, "role", "", "filter by role")
	fs.StringVar(&f.domain, "domain", "", "failure domain")
	fs.StringVar(&f.roles, "roles", "", "roles, e.g. edge=n17 or iam=0,watcher=0,apiserver=0,fleet=0")
	fs.StringVar(&f.labels, "labels", "", "labels k=v,...")
	fs.StringVar(&f.addr, "addr-ip", "", "the node's private address")
	fs.StringVar(&f.reason, "reason", "", "why (pin)")
	fs.StringVar(&f.inventory, "inventory", "", "opendsecops inventory file")
	fs.StringVar(&f.rel, "release", "", "release version")
	fs.StringVar(&f.note, "note", "", "note")
	fs.StringVar(&f.note, "notes", "", "release notes")
	fs.Uint64Var(&f.gen, "config-gen", 0, "cluster config generation")
	fs.Uint64Var(&f.gen, "gen", 0, "cluster config generation")
	fs.DurationVar(&f.deadline, "deadline", time.Hour, "evacuate: give up waiting after this")
	fs.StringVar(&f.bin, "bin", "", "release pack: build output (bin/)")
	fs.StringVar(&f.units, "units", "", "release pack: systemd unit files")
	fs.StringVar(&f.deps, "deps", "", "release pack: fetched runtime dependencies (deploy/fetch-deps.sh output)")
	fs.StringVar(&f.out, "out", "", "output directory or file")
	fs.StringVar(&f.domains, "domains", "", "rollout: failure domains")
	fs.StringVar(&f.nodes, "nodes", "", "rollout: node names")
	fs.IntVar(&f.canary, "canary", 0, "rollout: edge nodes in the first batch (default 1, -1 none)")
	fs.IntVar(&f.batch, "batch", 0, "rollout: edge nodes per batch (default 5%)")
	fs.IntVar(&f.perDomain, "max-per-domain", 0, "rollout: per batch and failure domain")
	fs.IntVar(&f.maxFail, "max-failures", 0, "rollout: failed nodes before pausing")
	fs.Float64Var(&f.bake, "bake", 0, "rollout: seconds to watch the canary (default 300)")
	fs.Float64Var(&f.pause, "pause", 0, "rollout: seconds between batches (default 60)")
	fs.Float64Var(&f.stepTimeout, "step-timeout", 0, "rollout: seconds per node (default 600)")
	fs.BoolVar(&f.steps, "steps", false, "rollout status: every node's step")
	fs.Parse(reorder(fs, args, 0))
	pos := fs.Args()
	need := func(n int) error {
		if len(pos) < n {
			return fmt.Errorf("fleet %s: expected %d argument(s)\n\n%s", cmd, n, fleetUsage)
		}
		return nil
	}
	if cmd == "release pack" {
		return packRelease(f)
	}
	fc, closeFn, err := f.dial()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch cmd {
	case "nodes":
		l, err := fc.ListNodes(ctx, &pb.FleetListNodesRequest{State: f.state, Role: f.role, Domain: f.domain})
		if err != nil {
			return err
		}
		printNodes(l.Nodes)
		return nil
	case "node get":
		if err := need(1); err != nil {
			return err
		}
		n, err := fc.GetNode(ctx, &pb.FleetNodeRef{Name: pos[0]})
		if err != nil {
			return err
		}
		printJSON(n)
		return nil
	case "node accept", "node cordon", "node uncordon", "node retire", "node sync", "node unpin", "node pin", "node set":
		if err := need(1); err != nil {
			return err
		}
		req := &pb.FleetUpdateNodeRequest{Name: pos[0], Action: strings.TrimPrefix(cmd, "node "), Domain: f.domain,
			Addr: f.addr, Reason: f.reason, Roles: kv(f.roles), Labels: kv(f.labels)}
		n, err := fc.UpdateNode(ctx, req)
		if err != nil {
			return err
		}
		printNodes([]*pb.FleetNode{n})
		return nil
	case "node evacuate":
		if err := need(1); err != nil {
			return err
		}
		return evacuate(ctx, f, fc, pos[0])
	case "import":
		return importInventory(ctx, f, fc)
	case "releases":
		l, err := fc.ListReleases(ctx, &pb.Empty{})
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "VERSION\tNODES\tSIZE\tCREATED\tBY\tDEPS\tNOTES")
		for _, r := range l.Releases {
			var deps []string
			for _, k := range sortedMapKeys(r.Deps) {
				deps = append(deps, k+"="+r.Deps[k])
			}
			fmt.Fprintf(w, "%s\t%d\t%.1fM\t%s\t%s\t%s\t%s\n", r.Version, r.Nodes, float64(r.Size)/(1<<20),
				time.Unix(int64(r.CreatedAt), 0).Format("01-02 15:04"), r.CreatedBy, strings.Join(deps, ","), r.Notes)
		}
		return w.Flush()
	case "release push":
		if err := need(1); err != nil {
			return err
		}
		return pushRelease(ctx, fc, pos[0], f.note)
	case "config put":
		if err := need(1); err != nil {
			return err
		}
		b, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		c, err := fc.PutConfig(ctx, &pb.FleetPutConfigRequest{ClusterJson: b, Note: f.note})
		if err != nil {
			return err
		}
		fmt.Printf("config generation %d stored\n", c.Gen)
		return nil
	case "config get":
		c, err := fc.GetConfig(ctx, &pb.FleetGetConfigRequest{Gen: f.gen})
		if err != nil {
			return err
		}
		if f.out != "" {
			return os.WriteFile(f.out, c.ClusterJson, 0o640)
		}
		fmt.Fprintf(os.Stderr, "generation %d by %s at %s: %s\n", c.Gen, c.CreatedBy, time.Unix(int64(c.CreatedAt), 0).Format(time.RFC3339), c.Note)
		os.Stdout.Write(c.ClusterJson)
		return nil
	case "rollout create":
		req := &pb.FleetCreateRolloutRequest{Release: f.rel, ConfigGen: f.gen, Note: f.note,
			Selector: &pb.FleetSelector{Roles: list(f.roles), Domains: list(f.domains), Nodes: list(f.nodes), Labels: kv(f.labels)},
			Strategy: &pb.FleetStrategy{Canary: int32(f.canary), BakeS: f.bake, Batch: int32(f.batch), MaxPerDomain: int32(f.perDomain),
				PauseS: f.pause, MaxFailures: int32(f.maxFail), StepTimeoutS: f.stepTimeout}}
		ro, err := fc.CreateRollout(ctx, req)
		if err != nil {
			return err
		}
		printRollout(ro, false)
		return nil
	case "rollout status":
		id := ""
		if len(pos) > 0 {
			id = pos[0]
		} else {
			l, err := fc.ListRollouts(ctx, &pb.Empty{})
			if err != nil {
				return err
			}
			if len(l.Rollouts) == 0 {
				return fmt.Errorf("no rollouts")
			}
			id = l.Rollouts[0].Id
		}
		ro, err := fc.GetRollout(ctx, &pb.FleetRolloutRef{Id: id})
		if err != nil {
			return err
		}
		printRollout(ro, f.steps)
		return nil
	case "rollout pause", "rollout resume", "rollout abort", "rollout rollback":
		if err := need(1); err != nil {
			return err
		}
		ro, err := fc.ControlRollout(ctx, &pb.FleetControlRolloutRequest{Id: pos[0], Action: strings.TrimPrefix(cmd, "rollout ")})
		if err != nil {
			return err
		}
		printRollout(ro, false)
		return nil
	case "rollouts":
		l, err := fc.ListRollouts(ctx, &pb.Empty{})
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATE\tRELEASE\tCONFIG\tBATCH\tCREATED\tBY\tMESSAGE")
		for _, r := range l.Rollouts {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d/%d\t%s\t%s\t%s\n", r.Id, r.State, r.Release, r.ConfigGen, r.Batch, r.Batches,
				time.Unix(int64(r.CreatedAt), 0).Format("01-02 15:04"), r.CreatedBy, r.Message)
		}
		return w.Flush()
	}
	fmt.Fprint(os.Stderr, fleetUsage)
	return fmt.Errorf("unknown fleet command %q", cmd)
}

func (f *fleetFlags) dial() (pb.FleetAdminClient, func(), error) {
	if f.direct {
		if f.fleetAddr == "" || f.pkiDir == "" || f.opsID == "" {
			return nil, nil, fmt.Errorf("-direct needs -fleet, -pki and -ops-id")
		}
		m, err := pki.Load(f.pkiDir, pki.Identity{Role: pki.RoleOps, ID: f.opsID})
		if err != nil {
			return nil, nil, err
		}
		conn, err := rpcutil.Dial(f.fleetAddr, &rpcutil.Security{TLS: m}, nil)
		if err != nil {
			return nil, nil, err
		}
		return pb.NewFleetAdminClient(conn), func() { conn.Close() }, nil
	}
	if f.cn.addr == "" || f.cn.token == "" {
		return nil, nil, fmt.Errorf("set -addr and -token (or OPENDSEC_ADDR / OPENDSEC_TOKEN), or use -direct")
	}
	var dopts []client.Option
	if f.cn.ca != "" {
		dopts = append(dopts, client.WithCAFile(f.cn.ca))
	}
	c, err := client.Dial(f.cn.addr, f.cn.token, f.cn.project, dopts...)
	if err != nil {
		return nil, nil, err
	}
	return c.Fleet(), func() { c.Close() }, nil
}

func list(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// kv parses "k=v,k2=v2"; a bare "k" maps to "" (e.g. the monitor role).
func kv(s string) map[string]string {
	if s == "" {
		return nil
	}
	m := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(p, "=")
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func rolesString(m map[string]string) string {
	var out []string
	for _, k := range sortedMapKeys(m) {
		if m[k] == "" {
			out = append(out, k)
		} else {
			out = append(out, k+"="+m[k])
		}
	}
	return strings.Join(out, ",")
}

func printNodes(ns []*pb.FleetNode) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tDOMAIN\tROLES\tRELEASE\tRUNNING\tUNITS\tSEEN\tNOTE")
	for _, n := range ns {
		st := n.Status
		running, units, seen := "-", "-", "never"
		if st != nil {
			running = st.CurrentRelease
			ready := 0
			for _, u := range st.Units {
				if u.Ready {
					ready++
				}
			}
			units = fmt.Sprintf("%d/%d", ready, len(st.Units))
			seen = fmt.Sprintf("%.0fs ago", float64(time.Now().UnixNano())/1e9-st.LastSeen)
		}
		note := n.Message
		if n.Pinned {
			note = "PINNED " + n.PinnedReason
		}
		if st != nil && st.Op != nil && st.Op.State == "running" {
			note = "running " + st.Op.Kind + " " + st.Op.OpId
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, n.State, n.Domain, rolesString(n.Roles), n.Release, running, units, seen, note)
	}
	w.Flush()
}

func printRollout(ro *pb.FleetRollout, steps bool) {
	fmt.Printf("rollout %s: %s  release=%s config=%d  batch %d/%d  by %s\n", ro.Id, ro.State, orDash(ro.Release), ro.ConfigGen,
		ro.Batch, ro.Batches, ro.CreatedBy)
	if ro.Rollback {
		fmt.Println("  (rollback)", ro.Note)
	}
	if ro.Message != "" {
		fmt.Println("  " + ro.Message)
	}
	if len(ro.Phases) > 0 {
		var ps []string
		for _, k := range sortedMapKeys(toStrMap(ro.Phases)) {
			ps = append(ps, fmt.Sprintf("%s=%d", k, ro.Phases[k]))
		}
		fmt.Println("  nodes:", strings.Join(ps, " "))
	}
	for _, e := range ro.Events[max(0, len(ro.Events)-10):] {
		fmt.Printf("  %s  %s\n", time.Unix(int64(e.At), 0).Format("15:04:05"), e.Message)
	}
	if steps {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "NODE\tBATCH\tPHASE\tFROM\tTO\tMESSAGE")
		for _, s := range ro.Steps {
			b := fmt.Sprint(s.Batch)
			if s.Batch < 0 {
				b = "control"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s/%d\t%s/%d\t%s\n", s.Node, b, s.Phase, orDash(s.FromRelease), s.FromGen, orDash(s.ToRelease), s.ToGen, s.Message)
		}
		w.Flush()
	}
}

func toStrMap(m map[string]int32) map[string]string {
	out := map[string]string{}
	for k := range m {
		out[k] = ""
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// importInventory turns an opendsecops inventory into nodes already running
// release (spec §28.9). Lines: name ssh-addr private-addr role...
func importInventory(ctx context.Context, f *fleetFlags, fc pb.FleetAdminClient) error {
	if f.inventory == "" || f.rel == "" {
		return fmt.Errorf("import needs -inventory and -release")
	}
	file, err := os.Open(f.inventory)
	if err != nil {
		return err
	}
	defer file.Close()
	var nodes []*pb.FleetNode
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) < 4 {
			return fmt.Errorf("inventory line %q: want name ssh-addr private-addr roles...", line)
		}
		n := &pb.FleetNode{Name: fs[0], Addr: fs[2], Domain: f.domain, Release: f.rel, ConfigGen: f.gen, State: "active",
			Roles: map[string]string{}}
		for _, r := range fs[3:] {
			k, v, _ := strings.Cut(r, "=")
			n.Roles[k] = v
		}
		nodes = append(nodes, n)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	l, err := fc.ImportNodes(ctx, &pb.FleetImportRequest{Nodes: nodes})
	if err != nil {
		return err
	}
	printNodes(l.Nodes)
	return nil
}

// packRelease builds <out>/<version> from a build, the unit files and the
// fetched runtime dependencies, with its SHA256SUMS (spec §28.5).
func packRelease(f *fleetFlags) error {
	if f.bin == "" || f.units == "" || f.out == "" {
		return fmt.Errorf("release pack needs -bin, -units and -out")
	}
	out, err := exec.Command(filepath.Join(f.bin, "opendsecctl"), "version").Output()
	if err != nil {
		return fmt.Errorf("%s/opendsecctl version: %v", f.bin, err)
	}
	ver := strings.TrimSpace(string(out))
	if !release.ValidVersion(ver) {
		return fmt.Errorf("build version %q cannot name a release", ver)
	}
	dir := filepath.Join(f.out, ver)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("release %s exists in %s", ver, f.out)
	}
	copyTo := func(src, dst string, mode os.FileMode) error {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, mode)
	}
	bins, _ := filepath.Glob(filepath.Join(f.bin, "opendsec*"))
	for _, b := range bins {
		name := filepath.Base(b)
		sub := "bin"
		if name == "opendsec-aether" || name == "opendsec-chronus" {
			sub = "agents"
		}
		if err := copyTo(b, filepath.Join(dir, sub, name), 0o755); err != nil {
			return err
		}
	}
	units, _ := filepath.Glob(filepath.Join(f.units, "opendsec-*.service"))
	for _, u := range units {
		if err := copyTo(u, filepath.Join(dir, "units", filepath.Base(u)), 0o644); err != nil {
			return err
		}
	}
	if f.deps != "" {
		err := filepath.Walk(f.deps, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(f.deps, p)
			return copyTo(p, filepath.Join(dir, rel), fi.Mode().Perm())
		})
		if err != nil {
			return err
		}
	}
	if err := release.WriteSums(dir); err != nil {
		return err
	}
	fmt.Println(dir)
	return nil
}

func pushRelease(ctx context.Context, fc pb.FleetAdminClient, dir, notes string) error {
	dir = filepath.Clean(dir)
	tmp, err := os.CreateTemp("", "opendsec-release-*.tgz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	if err := release.Pack(dir, io.MultiWriter(tmp, h)); err != nil {
		return err
	}
	size, _ := tmp.Seek(0, io.SeekCurrent)
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}
	up, err := fc.PushRelease(ctx)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	first := true
	for {
		n, rerr := tmp.Read(buf)
		if n > 0 || first {
			c := &pb.ReleaseChunk{Data: append([]byte(nil), buf[:n]...)}
			if first {
				c.Version, c.Size, c.Sha256, c.Notes = filepath.Base(dir), size, hex.EncodeToString(h.Sum(nil)), notes
				first = false
			}
			if err := up.Send(c); err != nil {
				_, cerr := up.CloseAndRecv()
				if cerr != nil {
					return cerr
				}
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	r, err := up.CloseAndRecv()
	if err != nil {
		return err
	}
	fmt.Printf("release %s pushed: %.1f MB, sha256 %s, on fleet replicas %s\n", r.Version, float64(r.Size)/(1<<20), r.Sha256, strings.Join(r.Replicas, ","))
	return nil
}

// evacuate cordons node and waits until its edge runs no sandbox (spec §28.7).
func evacuate(ctx context.Context, f *fleetFlags, fc pb.FleetAdminClient, name string) error {
	n, err := fc.GetNode(ctx, &pb.FleetNodeRef{Name: name})
	if err != nil {
		return err
	}
	edgeID, ok := n.Roles["edge"]
	if !ok {
		return fmt.Errorf("node %s has no edge", name)
	}
	if n.State == "active" {
		if _, err := fc.UpdateNode(ctx, &pb.FleetUpdateNodeRequest{Name: name, Action: "cordon"}); err != nil {
			return err
		}
	}
	if f.direct {
		return fmt.Errorf("node %s cordoned; watching its sandboxes needs the apiserver (drop -direct)", name)
	}
	var dopts []client.Option
	if f.cn.ca != "" {
		dopts = append(dopts, client.WithCAFile(f.cn.ca))
	}
	c, err := client.Dial(f.cn.addr, f.cn.token, f.cn.project, dopts...)
	if err != nil {
		return err
	}
	defer c.Close()
	deadline := time.Now().Add(f.deadline)
	for {
		snap, err := c.ClusterStatus(ctx, &pb.Empty{})
		if err != nil {
			return err
		}
		left := int32(-1)
		for _, e := range snap.Edges {
			if e.Id == edgeID {
				left = 0
				for _, k := range e.CountByBackend {
					left += k
				}
			}
		}
		if left == 0 {
			fmt.Printf("%s: no sandboxes left; the node stays cordoned (fleet node uncordon %s)\n", name, name)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: %d sandboxes still on edge %s after %v; list them with `opendsecctl status`, stop them or wait longer", name, left, edgeID, f.deadline)
		}
		fmt.Printf("%s  %s: %d sandboxes left on edge %s\n", time.Now().Format("15:04:05"), name, left, edgeID)
		time.Sleep(30 * time.Second)
	}
}
