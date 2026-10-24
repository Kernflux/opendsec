// opendsecctl is the OpenDsec command-line tool: run a local cluster, benchmark
// scheduling, and manage sandboxes, tasks and IAM through the public API.
//
// Connection settings come from flags or OPENDSEC_ADDR / OPENDSEC_TOKEN / OPENDSEC_PROJECT.
package main

import (
	"context"
	csvpkg "encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/cmdutil"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/pkg/client"
)

const usage = `usage: opendsecctl <command> [flags]

cluster up      run a whole cluster in this process (from -config, or -sim-edges N)
bench           scheduling benchmark on an in-process sim cluster
status          cluster snapshot (edges, health, load)
edge drain      <edge-id> [-undo]   stop (or resume) placing sandboxes on an edge
iam backup      -out FILE           save principals, projects, grants, quotas, tokens (gzipped JSON, 0600)
iam restore     FILE                replace them with a backup's (leases of live sandboxes are kept)
iam members                         list the Raft replicas
iam member add  <id> -raft-addr H:P -iam-addr H:P   add a replica started with opendsec-iam -join
iam member remove <id>              remove a replica (e.g. its node is gone)
whoami
version                             print this build's version
sandbox create  -backend sim -cpu 1 -mem 1024 [-disk MB] [-image I] [-task T] [-ttl-idle S] [-ttl-max S] [-count N] [-net pypi,!npm,1.2.3.0/24]
sandbox get|stop|pause|resume|touch <id>
sandbox fork    <id> [-count N] [-task T] [-ttl-idle S] [-ttl-max S]   copy a running sandbox into N
sandbox list    [-task T] [-all]
sandbox network <id> <rule>... [-replace]   change network rules: "pypi" allows, "!pypi" takes back
exec            <id> [-session S] [-user U] [-timeout S] -- <command...>  run a shell command in a sandbox
cp              <id>:<path> <local> | <local> <id>:<path>     copy a file out of / into a sandbox
task pause|resume|stop <task-id>
project create  <parent> <name> [-quota sandboxes=10,cpu_cores=40]
project get     <path>
principal create <project> <id> [-kind agent]
principal delete <id>
project delete  <path>
token create    [<principal>] [-ttl S] [-desc D]    issue a token (default: for yourself)
token list      [<principal>]
token revoke    <principal> <token-id>             ("primary" = the legacy token)
pki init        -config opendsec.json -out DIR [-days N] [-ca-days N] [-hosts h1,h2]
pki ca          -out DIR [-days N]  a new CA only (CA rotation)
pki issue       -ca DIR -role edge|node|fleet|ops|... -id ID [-hosts ip1,ip2] -out DIR [-days N]   (node provisioning)
usage           [<project>] [-from YYYY-MM-DD] [-to YYYY-MM-DD] [-daily] [-csv]   resource usage of a project and its subprojects (project.admin)
image import    <ref> -as <project>/<repo>:<tag> -store DIR [-plain-http]   pull an OCI image into the shared store
                [-username U -password-stdin | -registry-auth FILE]   private registries (default: docker login's credentials)
                <ref> may be an image archive: an OCI layout (directory or tar), a docker save tar; PATH#NAME picks one of several
image save      <ref> -out FILE [-plain-http] [-username U -password-stdin]   write a registry's image as an OCI tar (for offline machines)
image compose   <name> <part>... [-overwrite]       stack images (base, workspace, toolkits) into one
image list      [-project P]
image get       <name>
image delete    <name>
image pack      <sandbox-id> <name> [-scrub a,b] [-overwrite]   pack_diff: snapshot a sandbox as an image
image snapshot  <sandbox-id> <name> [-memory] [-overwrite]      save a sandbox as is (with memory on microvm)
image gc        -store DIR [-grace 24h] [-dry-run]   remove layers and snapshots nothing uses
image store-check -store DIR                         check that a filesystem (e.g. a NAS) can hold the image store
fleet           ...                 cluster management: machines, releases, rollouts (opendsecctl fleet for help)
grant           <project> <principal> <perm>[,<perm>...]
revoke          <project> <principal> [<perm>,...]

common flags: -addr host:port  -token dsk.x.y  -project root/...  -ca ca.crt (TLS)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if (cmd == "sandbox" || cmd == "task" || cmd == "project" || cmd == "principal" || cmd == "cluster" ||
		cmd == "token" || cmd == "pki" || cmd == "image" || cmd == "edge" || cmd == "iam") && len(args) > 0 {
		cmd, args = cmd+" "+args[0], args[1:]
	}
	var err error
	switch cmd {
	case "cluster up":
		err = clusterUp(args)
	case "bench":
		err = bench(args)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	case "version":
		fmt.Println(metrics.Version)
	case "pki init":
		err = pkiInit(args)
	case "pki issue":
		err = pkiIssue(args)
	case "pki ca":
		err = pkiCA(args)
	case "fleet":
		err = fleetCommand(args)
	default:
		err = apiCommand(cmd, args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func clusterUp(args []string) error {
	fs := flag.NewFlagSet("cluster up", flag.ExitOnError)
	cfgPath := fs.String("config", "", "cluster config (default: generated sim cluster)")
	simEdges := fs.Int("sim-edges", 4, "number of sim edges when no -config is given")
	apiservers := fs.Int("apiservers", 1, "number of apiservers when no -config is given")
	write := fs.String("write-config", "", "write the effective config (with bound addresses) here")
	runtimeName := fs.String("runtime", "sim", "runtime of the container backend for generated clusters: sim | linux")
	stateDir := fs.String("state-dir", "/var/lib/opendsec", "sandbox state dir (linux runtime)")
	useTLS := fs.Bool("tls", false, "generate a cluster CA + certificates and run with mTLS / TLS")
	auditDir := fs.String("audit-dir", "", "write apiserver audit logs here")
	imageStore := fs.String("image-store", "", "shared image store root (enables store images and pack_diff)")
	diskReserve := fs.Int64("disk-reserve-mb", 512, "linux runtime: reject creations while the state dir filesystem has less free space (-1 disables)")
	hostImage := fs.Bool("host-image", true, "linux runtime: offer image \"host\" (host / as read-only lower layer; dev only, exposes host files)")
	vmKernel := fs.String("microvm-kernel", "", "linux runtime: also offer backend \"microvm\" (Firecracker) with this guest vmlinux")
	level := fs.String("log", "info", "log level")
	metricsAddr := fs.String("metrics", "", "serve Prometheus metrics at http://ADDR/metrics (e.g. :9464)")
	fs.Parse(args)
	log := cmdutil.Logger(*level)
	if *metricsAddr != "" {
		metrics.Serve(*metricsAddr, log)
	}
	var cfg *config.Cluster
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		cfg = c
	} else {
		cfg = cluster.SimConfig(*simEdges, *apiservers, 192, 1536*1024, 3200)
		if *runtimeName == "linux" {
			for i := range cfg.Edges {
				cfg.Edges[i].Capacity = config.Resources{} // detect from the host
				cfg.Edges[i].StateDir = *stateDir
				// Dev-sized writable disks; they are sparse, so allow 4x overcommit
				// (the free-space reserve still stops creations before the disk fills).
				cfg.Edges[i].Backends["container"] = config.Backend{Runtime: "linux", MaxSandboxes: 256, DefaultDiskMB: 1024}
				cfg.Edges[i].DiskOvercommit, cfg.Edges[i].DiskReserveMB = 4, *diskReserve
				if *hostImage {
					cfg.Edges[i].Images = map[string][]string{"host": {"/"}}
				}
				if *vmKernel != "" {
					cfg.Edges[i].Backends["microvm"] = config.Backend{Runtime: "firecracker", MaxSandboxes: 256, DefaultDiskMB: 1024, Kernel: *vmKernel}
				}
			}
		}
	}
	caFile := ""
	if *useTLS {
		dir, err := os.MkdirTemp("", "opendsec-pki")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if err := cluster.GeneratePKI(cfg, dir, 30*24*time.Hour); err != nil {
			return err
		}
		cfg.TLS.Dir, cfg.ServiceToken, caFile = dir, "", filepath.Join(dir, "ca.crt")
	}
	if *imageStore != "" {
		cfg.ImageStore.Root = *imageStore
	}
	if *auditDir != "" {
		for i := range cfg.APIServers {
			cfg.APIServers[i].AuditDir = *auditDir
		}
	}
	l, err := cluster.StartLocal(cfg, log)
	if err != nil {
		return err
	}
	defer l.Stop()
	if *write != "" {
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(*write, b, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("OpenDsec cluster up: %d edges, %d apiservers\n", len(cfg.Edges), len(cfg.APIServers))
	fmt.Printf("export OPENDSEC_ADDR=%s OPENDSEC_TOKEN=%s OPENDSEC_PROJECT=root", cfg.APIServers[0].Addr, l.AdminToken)
	if caFile != "" {
		fmt.Printf(" OPENDSEC_CA=%s", caFile)
	}
	fmt.Println()
	// SIGUSR1 restarts every edge, with a second of outage: lets client
	// tests exercise riding out an edge restart.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
			for i := range cfg.Edges {
				ec := &cfg.Edges[i]
				ec.KeepSandboxesOnExit = true // the restarted edge adopts them
				if err := l.RestartEdge(ec.ID, func() { time.Sleep(time.Second) }); err != nil {
					log.Error("restart edge", "edge", ec.ID, "err", err)
				}
				ec.KeepSandboxesOnExit = false // the final stop cleans up
			}
			log.Warn("edges restarted")
		}
	}()
	cmdutil.WaitSignal()
	return nil
}

// ---- API commands ------------------------------------------------------------------

type conn struct {
	addr, token, project, ca string
}

func connFlags(fs *flag.FlagSet) *conn {
	c := &conn{}
	fs.StringVar(&c.addr, "addr", os.Getenv("OPENDSEC_ADDR"), "apiserver address")
	c.token = os.Getenv("OPENDSEC_TOKEN")
	fs.Var((*secretFlag)(&c.token), "token", "bearer token (default $OPENDSEC_TOKEN)")
	fs.StringVar(&c.project, "project", envOr("OPENDSEC_PROJECT", "root"), "project")
	fs.StringVar(&c.ca, "ca", os.Getenv("OPENDSEC_CA"), "CA certificate for TLS (OPENDSEC_CA)")
	return c
}

// secretFlag is a string flag whose value never shows in -help (the
// default comes from the environment and is a credential).
type secretFlag string

func (s *secretFlag) String() string     { return "" }
func (s *secretFlag) Set(v string) error { *s = secretFlag(v); return nil }

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func printJSON(m proto.Message) {
	b, _ := protojson.MarshalOptions{Multiline: true, Indent: "  ", EmitUnpopulated: false}.Marshal(m)
	fmt.Println(string(b))
}

func apiCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cn := connFlags(fs)
	backendName := fs.String("backend", "sim", "sandbox backend")
	image := fs.String("image", "", "image")
	cpu := fs.Float64("cpu", 1, "cpu cores")
	mem := fs.Int64("mem", 1024, "memory MB")
	gpus := fs.Int("gpus", 0, "gpus")
	disk := fs.Int64("disk", 0, "writable disk MB (0 = backend default)")
	task := fs.String("task", "", "task id")
	ttlIdle := fs.Int64("ttl-idle", 0, "ttl_running_stop seconds")
	ttlMax := fs.Int64("ttl-max", 0, "ttl_max seconds")
	count := fs.Int("count", 1, "number of sandboxes (batch)")
	all := fs.Bool("all", false, "include ended sandboxes")
	quota := fs.String("quota", "", "quota, e.g. sandboxes=10,cpu_cores=40")
	kind := fs.String("kind", "agent", "principal kind")
	ttl := fs.Float64("ttl", 0, "token lifetime seconds (0 = server default)")
	as := fs.String("as", "", "image name to register (image import)")
	storeRoot := fs.String("store", os.Getenv("OPENDSEC_IMAGE_STORE"), "shared image store root (image import)")
	plainHTTP := fs.Bool("plain-http", false, "registry without TLS (image import)")
	regUser := fs.String("username", "", "image import: registry user name (the password or access token is read from stdin, with -password-stdin)")
	regPassStdin := fs.Bool("password-stdin", false, "image import: read the registry password or access token from stdin")
	regAuth := fs.String("registry-auth", "", "image import: docker config file with registry credentials (default: $REGISTRY_AUTH_FILE, $DOCKER_CONFIG/config.json, ~/.docker/config.json)")
	overwrite := fs.Bool("overwrite", false, "replace an existing image")
	memory := fs.Bool("memory", false, "include memory in the snapshot (microvm)")
	scrub := fs.String("scrub", "", "extra paths to drop when packing, comma separated")
	desc := fs.String("desc", "", "token description")
	session := fs.String("session", "default", "shell session")
	runAs := fs.String("user", "", "exec: the session's user when this starts it (a name, or uid[:gid])")
	deadline := fs.Duration("deadline", 0, "give up after this long (default 5m; image import: no limit, a pull of a large image can take long)")
	timeoutS := fs.Float64("timeout", 0, "command timeout seconds")
	grace := fs.Duration("grace", 24*time.Hour, "image gc: keep anything younger")
	dryRun := fs.Bool("dry-run", false, "image gc: only list what would go")
	netRules := fs.String("net", "", "network rules, comma separated (\"!rule\" takes one back)")
	undo := fs.Bool("undo", false, "edge drain: take sandboxes again")
	replace := fs.Bool("replace", false, "replace the sandbox's network rules instead of merging (sandbox network)")
	outFile := fs.String("out", "", "iam backup, image save: file to write")
	from := fs.String("from", "", "usage: first day (YYYY-MM-DD, UTC)")
	to := fs.String("to", "", "usage: last day (YYYY-MM-DD, UTC)")
	daily := fs.Bool("daily", false, "usage: a row per day and project (default: per project over the period)")
	csvOut := fs.Bool("csv", false, "usage: CSV")
	raftAddr := fs.String("raft-addr", "", "iam member add: the new replica's raft address")
	iamAddr := fs.String("iam-addr", "", "iam member add: the new replica's gRPC address")
	stop := 0
	if cmd == "exec" {
		stop = 2 // opendsecctl exec <id> ls -la: the command's own flags stay its own
	}
	fs.Parse(reorder(fs, args, stop))
	pos := fs.Args()
	if cmd == "image store-check" { // offline: no cluster needed
		return storeCheck(*storeRoot)
	}
	if cmd == "image save" { // no cluster needed
		if len(pos) != 1 || *outFile == "" {
			return fmt.Errorf("usage: opendsecctl image save <ref> -out FILE")
		}
		return imageSave(pos[0], *outFile, *plainHTTP, *regUser, *regPassStdin, *regAuth)
	}
	if cn.addr == "" || cn.token == "" {
		return fmt.Errorf("set -addr and -token (or OPENDSEC_ADDR / OPENDSEC_TOKEN)")
	}
	var dopts []client.Option
	if cn.ca != "" {
		dopts = append(dopts, client.WithCAFile(cn.ca))
	}
	c, err := client.Dial(cn.addr, cn.token, cn.project, dopts...)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if d := *deadline; d > 0 || cmd != "image import" {
		if d == 0 {
			d = 5 * time.Minute
		}
		ctx, cancel = context.WithTimeout(context.Background(), d)
	}
	defer cancel()
	need := func(n int) error {
		if len(pos) < n {
			return fmt.Errorf("%s: expected %d argument(s)\n\n%s", cmd, n, usage)
		}
		return nil
	}
	var out proto.Message
	switch cmd {
	case "status":
		out, err = c.ClusterStatus(ctx, &pb.Empty{})
	case "whoami":
		out, err = c.WhoAmI(ctx, &pb.Empty{})
	case "sandbox create":
		spec := &pb.SandboxSpec{Backend: *backendName, Image: *image, TaskId: *task,
			Resources:       &pb.Resources{CpuCores: *cpu, MemoryMb: *mem, Gpus: int32(*gpus), DiskMb: *disk},
			TtlRunningStopS: *ttlIdle, TtlMaxS: *ttlMax, NetworkRules: parseRules(strings.Split(*netRules, ","))}
		if *count == 1 {
			out, err = c.Create(ctx, spec)
			break
		}
		start := time.Now()
		res, err := c.CreateBatch(ctx, spec, int32(*count))
		if err != nil {
			return err
		}
		fails := map[string]int{}
		for _, r := range res { // as sandbox fork prints them
			if r.ErrorReason != "" {
				fails[r.ErrorReason]++
				fmt.Printf("%d\terror\t%s: %s\n", r.Index, r.ErrorReason, r.ErrorMessage)
			} else {
				fmt.Printf("%d\t%s\n", r.Index, r.Sandbox.Id)
			}
		}
		fmt.Printf("created %d/%d in %v; failures: %v\n", len(res)-sum(fails), *count, time.Since(start).Round(time.Millisecond), fails)
		return nil
	case "sandbox get", "sandbox stop", "sandbox pause", "sandbox resume", "sandbox touch":
		if err := need(1); err != nil {
			return err
		}
		ref := &pb.SandboxRef{Id: pos[0]}
		switch strings.TrimPrefix(cmd, "sandbox ") {
		case "get":
			out, err = c.GetSandbox(ctx, ref)
		case "stop":
			out, err = c.StopSandbox(ctx, ref)
		case "pause":
			out, err = c.PauseSandbox(ctx, ref)
		case "resume":
			out, err = c.ResumeSandbox(ctx, ref)
		case "touch":
			out, err = c.TouchSandbox(ctx, ref)
		}
	case "edge drain":
		if err := need(1); err != nil {
			return err
		}
		out, err = c.DrainEdge(ctx, &pb.DrainEdgeRequest{EdgeId: pos[0], Draining: !*undo})
	case "iam backup":
		if *outFile == "" {
			return fmt.Errorf("iam backup: set -out FILE")
		}
		st, err := c.BackupIAM(ctx, &pb.IAMBackupRequest{})
		if err != nil {
			return err
		}
		_, data, err := iam.RecvChunks(st.Recv)
		if err != nil {
			return err
		}
		tmp := *outFile + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, *outFile); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", *outFile, len(data))
		return nil
	case "iam restore":
		if err := need(1); err != nil {
			return err
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		st, err := c.RestoreIAM(ctx)
		if err != nil {
			return err
		}
		if err := iam.SendChunks(data, st.Send); err != nil {
			return err
		}
		out, err = st.CloseAndRecv()
	case "iam members":
		out, err = c.IAMMembers(ctx, &pb.IAMMemberRequest{})
	case "iam member":
		if err := need(2); err != nil {
			return err
		}
		switch pos[0] {
		case "add":
			if *raftAddr == "" || *iamAddr == "" {
				return fmt.Errorf("iam member add: set -raft-addr and -iam-addr")
			}
			out, err = c.AddIAMMember(ctx, &pb.IAMMemberRequest{Id: pos[1], RaftAddr: *raftAddr, Addr: *iamAddr})
		case "remove":
			out, err = c.RemoveIAMMember(ctx, &pb.IAMMemberRequest{Id: pos[1]})
		default:
			return fmt.Errorf("iam member: add or remove, not %q", pos[0])
		}
	case "sandbox network":
		if err := need(1); err != nil {
			return err
		}
		out, err = c.UpdateNetwork(ctx, &pb.UpdateNetworkRequest{SandboxId: pos[0], Rules: parseRules(pos[1:]), Replace: *replace})
	case "sandbox fork":
		if err := need(1); err != nil {
			return err
		}
		start := time.Now()
		res, err := c.Fork(ctx, &pb.ForkSandboxRequest{SandboxId: pos[0], Count: int32(*count), TaskId: *task,
			TtlRunningStopS: *ttlIdle, TtlMaxS: *ttlMax})
		if err != nil {
			return err
		}
		failed := 0
		for _, r := range res {
			if r.ErrorReason != "" {
				failed++
				fmt.Printf("%d\terror\t%s: %s\n", r.Index, r.ErrorReason, r.ErrorMessage)
			} else {
				fmt.Printf("%d\t%s\n", r.Index, r.Sandbox.Id)
			}
		}
		fmt.Fprintf(os.Stderr, "forked %d/%d in %v\n", len(res)-failed, *count, time.Since(start).Round(time.Millisecond))
		return nil
	case "exec":
		if err := need(2); err != nil {
			return err
		}
		st, err := c.ExecStream(ctx, &pb.ExecRequest{SandboxId: pos[0], Session: *session, User: *runAs,
			Cmd: shellCmd(pos[1:]), TimeoutS: *timeoutS})
		if err != nil {
			return err
		}
		for {
			ev, err := st.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			switch e := ev.Event.(type) {
			case *pb.ExecEvent_Stdout:
				os.Stdout.Write(e.Stdout)
			case *pb.ExecEvent_Stderr:
				os.Stderr.Write(e.Stderr)
			case *pb.ExecEvent_Exit:
				if e.Exit.TimedOut {
					fmt.Fprintln(os.Stderr, "opendsecctl: command timed out")
				}
				if e.Exit.ExitCode != 0 {
					os.Exit(int(e.Exit.ExitCode) & 0xff)
				}
				return nil
			}
		}
	case "cp":
		if err := need(2); err != nil {
			return err
		}
		if id, path, ok := strings.Cut(pos[0], ":"); ok && strings.Contains(id, ".") {
			d, err := c.ReadFile(ctx, &pb.FileRequest{SandboxId: id, Path: path})
			if err != nil {
				return err
			}
			if d.Size > int64(len(d.Data)) {
				return fmt.Errorf("%s is %d bytes; cp copies at most %d", path, d.Size, len(d.Data))
			}
			return os.WriteFile(pos[1], d.Data, 0o644)
		}
		id, path, ok := strings.Cut(pos[1], ":")
		if !ok {
			return fmt.Errorf("cp: one side must be <sandbox-id>:<path>")
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		out, err = c.WriteFile(ctx, &pb.WriteFileRequest{SandboxId: id, Path: path, Data: data})
	case "sandbox list":
		out, err = c.ListSandboxes(ctx, &pb.SandboxFilter{Project: cn.project, TaskId: *task, IncludeEnded: *all})
	case "task pause", "task resume", "task stop":
		if err := need(1); err != nil {
			return err
		}
		action := map[string]pb.TaskAction{"task pause": pb.TaskAction_TASK_PAUSE,
			"task resume": pb.TaskAction_TASK_RESUME, "task stop": pb.TaskAction_TASK_STOP}[cmd]
		out, err = c.ApplyTaskAction(ctx, &pb.TaskActionRequest{Project: cn.project, TaskId: pos[0], Action: action})
	case "project create":
		if err := need(2); err != nil {
			return err
		}
		q, qerr := parseQuota(*quota)
		if qerr != nil {
			return qerr
		}
		out, err = c.CreateProject(ctx, &pb.CreateProjectRequest{Parent: pos[0], Name: pos[1], Quota: q})
	case "project get":
		if err := need(1); err != nil {
			return err
		}
		out, err = c.GetProject(ctx, &pb.GetProjectRequest{Project: pos[0]})
	case "principal create":
		if err := need(2); err != nil {
			return err
		}
		out, err = c.CreatePrincipal(ctx, &pb.CreatePrincipalRequest{Project: pos[0], Id: pos[1], Kind: *kind, TtlS: *ttl})
	case "principal delete":
		if err := need(1); err != nil {
			return err
		}
		out, err = c.DeletePrincipal(ctx, &pb.DeletePrincipalRequest{Principal: pos[0]})
	case "project delete":
		if err := need(1); err != nil {
			return err
		}
		out, err = c.DeleteProject(ctx, &pb.DeleteProjectRequest{Project: pos[0]})
	case "token create", "token list":
		principal := ""
		if len(pos) > 0 {
			principal = pos[0]
		} else {
			me, err := c.WhoAmI(ctx, &pb.Empty{})
			if err != nil {
				return err
			}
			principal = me.Id
		}
		if cmd == "token create" {
			out, err = c.CreateToken(ctx, &pb.CreateTokenRequest{Principal: principal, TtlS: *ttl, Description: *desc})
		} else {
			out, err = c.ListTokens(ctx, &pb.ListTokensRequest{Principal: principal})
		}
	case "image import":
		if err := need(1); err != nil {
			return err
		}
		if *as == "" || *storeRoot == "" {
			return fmt.Errorf("image import needs -as <name> and -store <dir> (or OPENDSEC_IMAGE_STORE)")
		}
		st, err := images.NewStore(*storeRoot)
		if err != nil {
			return err
		}
		p := &images.Puller{Store: st, PlainHTTP: *plainHTTP,
			Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
		var res *images.ImportResult
		if f, _, _ := strings.Cut(pos[0], "#"); strings.HasPrefix(f, "/") || strings.HasPrefix(f, ".") {
			if _, err := os.Stat(f); err != nil { // a path, not an image reference
				return fmt.Errorf("image archive: %w", err)
			}
		}
		if images.IsArchive(pos[0]) { // an image archive on disk (spec §38)
			res, err = p.Import(ctx, pos[0])
		} else {
			if p.Creds, err = registryCreds(pos[0], *regUser, *regPassStdin, *regAuth); err != nil {
				return err
			}
			res, err = p.Pull(ctx, pos[0])
		}
		if err != nil {
			return err
		}
		out, err = c.RegisterImage(ctx, &pb.RegisterImageRequest{Overwrite: *overwrite, Image: &pb.ImageInfo{
			Name: *as, Layers: res.Layers, Env: res.Env, Workdir: res.Workdir, User: res.User, Source: res.Source}})
	case "image gc":
		if *storeRoot == "" {
			return fmt.Errorf("image gc needs -store <dir> (or OPENDSEC_IMAGE_STORE)")
		}
		st, err := images.NewStore(*storeRoot)
		if err != nil {
			return err
		}
		res, err := st.GC(*grace, *dryRun)
		if res != nil {
			verb := "removed"
			if *dryRun {
				verb = "would remove"
			}
			fmt.Printf("%s %d layers, %d snapshots, %d VM image disk files, %d partial writes: %d MB\n", verb, len(res.Layers),
				len(res.Snapshots), len(res.VMDisks), len(res.Partial), res.Bytes>>20)
		}
		return err
	case "image compose":
		if err := need(2); err != nil {
			return err
		}
		out, err = c.ComposeImage(ctx, &pb.ComposeImageRequest{Name: pos[0], Parts: pos[1:], Overwrite: *overwrite})
	case "usage":
		project := cn.project
		if len(pos) > 0 {
			project = pos[0]
		}
		rep, err := c.GetUsage(ctx, &pb.UsageRequest{Project: project, From: *from, To: *to})
		if err != nil {
			return err
		}
		printUsage(os.Stdout, rep, *daily, *csvOut)
		return nil
	case "image list":
		out, err = c.ListImages(ctx, &pb.ListImagesRequest{Project: cn.project})
	case "image get", "image delete":
		if err := need(1); err != nil {
			return err
		}
		if cmd == "image get" {
			out, err = c.GetImage(ctx, &pb.ImageRef{Name: pos[0]})
		} else {
			out, err = c.DeleteImage(ctx, &pb.ImageRef{Name: pos[0]})
		}
	case "image pack":
		if err := need(2); err != nil {
			return err
		}
		var sc []string
		if *scrub != "" {
			sc = strings.Split(*scrub, ",")
		}
		out, err = c.PackDiff(ctx, &pb.PackDiffRequest{SandboxId: pos[0], Image: pos[1], Scrub: sc, Overwrite: *overwrite})
	case "image snapshot":
		if err := need(2); err != nil {
			return err
		}
		out, err = c.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{SandboxId: pos[0], Image: pos[1], Memory: *memory, Overwrite: *overwrite})
	case "token revoke":
		if err := need(2); err != nil {
			return err
		}
		out, err = c.RevokeToken(ctx, &pb.RevokeTokenRequest{Principal: pos[0], TokenId: pos[1]})
	case "grant":
		if err := need(3); err != nil {
			return err
		}
		out, err = c.Grant(ctx, &pb.GrantRequest{Project: pos[0], Principal: pos[1], Perms: strings.Split(pos[2], ",")})
	case "revoke":
		if err := need(2); err != nil {
			return err
		}
		var perms []string
		if len(pos) > 2 {
			perms = strings.Split(pos[2], ",")
		}
		out, err = c.Revoke(ctx, &pb.RevokeRequest{Project: pos[0], Principal: pos[1], Perms: perms})
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

// reorder moves flags ahead of positional args so "sandbox stop <id> -addr x"
// works. After stop positional args (if > 0) the rest is positional too.
func reorder(fs *flag.FlagSet, args []string, stop int) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || (stop > 0 && len(pos) >= stop) { // everything after is positional (e.g. a command line)
			if a == "--" {
				i++
			}
			pos = append(pos, args[i:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !isBoolFlag(fs, a) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(append(flags, "--"), pos...)
}

// isBoolFlag reports whether a (-name, --name) is one of fs's bool flags,
// which take no separate value.
func isBoolFlag(fs *flag.FlagSet, a string) bool {
	f := fs.Lookup(strings.TrimLeft(a, "-"))
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func parseQuota(s string) (map[string]float64, error) {
	if s == "" {
		return nil, nil
	}
	out := map[string]float64{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		var f float64
		if _, err := fmt.Sscan(v, &f); !ok || err != nil {
			return nil, fmt.Errorf("bad quota entry %q", kv)
		}
		out[k] = f
	}
	return out, nil
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func pkiInit(args []string) error {
	fs := flag.NewFlagSet("pki init", flag.ExitOnError)
	cfgPath := fs.String("config", "opendsec.json", "cluster config")
	out := fs.String("out", "pki", "output directory")
	days := fs.Int("days", 365, "certificate validity in days")
	caDays := fs.Int("ca-days", 3650, "CA validity in days")
	hosts := fs.String("hosts", "", "extra hostnames/IPs for every certificate, comma separated")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	var extra []string
	if *hosts != "" {
		extra = strings.Split(*hosts, ",")
	}
	if err := cluster.GeneratePKIWithCA(cfg, *out, time.Duration(*caDays)*24*time.Hour, time.Duration(*days)*24*time.Hour, extra...); err != nil {
		return err
	}
	nIAM := max(1, len(cfg.IAM.Replicas))
	fmt.Printf("wrote CA and %d component certificates to %s\n", nIAM+1+len(cfg.APIServers)+len(cfg.Edges), *out)
	fmt.Printf("set \"tls\": {\"dir\": %q} in the config; keep %s/ca.key offline\n", *out, *out)
	return nil
}

// pkiIssue signs one component certificate with an existing CA, e.g. for an
// edge node being provisioned (spec §16.2).
// pkiCA writes a new CA only (CA rotation, docs/OPERATIONS.md).
func pkiCA(args []string) error {
	fs := flag.NewFlagSet("pki ca", flag.ExitOnError)
	out := fs.String("out", "pki-next", "output directory (gets ca.crt, ca.key)")
	days := fs.Int("days", 3650, "CA validity in days")
	fs.Parse(args)
	if _, err := os.Stat(filepath.Join(*out, "ca.key")); err == nil {
		return fmt.Errorf("%s/ca.key exists", *out)
	}
	ca, err := pki.NewCA("opendsec cluster CA", time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := ca.Write(*out); err != nil {
		return err
	}
	fmt.Printf("wrote a new CA (valid %d days) to %s\n", *days, *out)
	return nil
}

func pkiIssue(args []string) error {
	fs := flag.NewFlagSet("pki issue", flag.ExitOnError)
	caDir := fs.String("ca", "pki", "directory with ca.crt and ca.key")
	role := fs.String("role", "edge", "component role: edge | apiserver | watcher | iam | fleet | node | ops")
	id := fs.String("id", "", "component id (edge id, replica id, ...)")
	hosts := fs.String("hosts", "", "hostnames/IPs the component is reachable at, comma separated")
	out := fs.String("out", ".", "output directory (gets ca.crt, <role>-<id>.crt/.key)")
	days := fs.Int("days", 365, "validity in days")
	fs.Parse(args)
	switch *role {
	case pki.RoleEdge, pki.RoleAPIServer, pki.RoleWatcher, pki.RoleIAM, pki.RoleFleet, pki.RoleNode, pki.RoleOps:
	default:
		return fmt.Errorf("unknown role %q", *role)
	}
	if (*role == pki.RoleEdge || *role == pki.RoleNode) && !ids.ValidEdgeID(*id) {
		return fmt.Errorf("%s id %q must match [a-z0-9-]{1,32}", *role, *id)
	}
	ca, err := pki.LoadCA(*caDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	var hs []string
	if *hosts != "" {
		hs = strings.Split(*hosts, ",")
	}
	ident := pki.Identity{Role: *role, ID: *id}
	if err := ca.IssueTo(*out, ident, append(hs, "localhost", "127.0.0.1"), time.Duration(*days)*24*time.Hour); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "ca.crt"), ca.PEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("issued %s -> %s/%s.{crt,key} (plus ca.crt; no CA key copied)\n", ident, *out, ident.FileName())
	return nil
}

// parseRules turns "rule" / "!rule" words into network rules.
func parseRules(words []string) map[string]bool {
	rules := map[string]bool{}
	for _, w := range words {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		if r, ok := strings.CutPrefix(w, "!"); ok {
			rules[r] = false
		} else {
			rules[w] = true
		}
	}
	if len(rules) == 0 {
		return nil
	}
	return rules
}

// storeCheck reports whether dir's filesystem can hold the image store
// (spec §29.5).
func storeCheck(dir string) error {
	if dir == "" {
		return fmt.Errorf("image store-check needs -store <dir> (or OPENDSEC_IMAGE_STORE)")
	}
	failed := 0
	for _, c := range images.CheckStore(dir) {
		status := "ok"
		switch {
		case c.Err != nil && c.Required:
			status, failed = "FAIL", failed+1
		case c.Err != nil:
			status = "info"
		}
		line := fmt.Sprintf("%-5s %s", status, c.Name)
		if c.Err != nil {
			line += ": " + c.Err.Error()
		}
		fmt.Println(line)
	}
	if failed > 0 {
		return fmt.Errorf("%d required checks failed: %s cannot hold the image store", failed, dir)
	}
	fmt.Printf("%s can hold the image store\n", dir)
	return nil
}

// registryCreds is the credentials for pulling ref: -username with the
// password from stdin, else the docker config file's for its registry
// (none: anonymous).
// printUsage writes a usage report: per project over the period, or per
// day and project; a total row last.
func printUsage(w io.Writer, rep *pb.UsageReport, daily, csv bool) {
	type key struct{ day, project string }
	sums := map[key]*pb.UsageRow{}
	var order []key
	total := &pb.UsageRow{Project: "TOTAL"}
	for _, r := range rep.Rows {
		k := key{"", r.Project}
		if daily {
			k.day = r.Day
		}
		s := sums[k]
		if s == nil {
			s = &pb.UsageRow{Project: r.Project, Day: k.day}
			sums[k] = s
			order = append(order, k)
		}
		for _, x := range []*pb.UsageRow{s, total} {
			x.SandboxesStarted += r.SandboxesStarted
			x.SandboxHours += r.SandboxHours
			x.CpuCoreHours += r.CpuCoreHours
			x.MemoryGbHours += r.MemoryGbHours
			x.GpuHours += r.GpuHours
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].day != order[j].day {
			return order[i].day < order[j].day
		}
		return order[i].project < order[j].project
	})
	head := []string{"PROJECT", "SANDBOXES", "SANDBOX_H", "CPU_CORE_H", "MEM_GB_H", "GPU_H"}
	if daily {
		head = append([]string{"DAY"}, head...)
	}
	row := func(r *pb.UsageRow) []string {
		f := func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
		out := []string{r.Project, strconv.FormatInt(r.SandboxesStarted, 10), f(r.SandboxHours), f(r.CpuCoreHours), f(r.MemoryGbHours), f(r.GpuHours)}
		if daily {
			out = append([]string{r.Day}, out...)
		}
		return out
	}
	lines := [][]string{head}
	for _, k := range order {
		lines = append(lines, row(sums[k]))
	}
	lines = append(lines, row(total))
	if csv {
		cw := csvpkg.NewWriter(w)
		cw.WriteAll(lines)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', tabwriter.AlignRight)
	for _, l := range lines {
		fmt.Fprintln(tw, strings.Join(l, "\t")+"\t")
	}
	tw.Flush()
	fmt.Fprintf(w, "as of %s (UTC days; sandboxes running now counted up to then)\n", time.Unix(int64(rep.AsOf), 0).UTC().Format(time.RFC3339))
}

// imageSave writes ref's image as an OCI image layout tar (spec §38).
func imageSave(ref, file string, plainHTTP bool, user string, passStdin bool, authFile string) error {
	creds, err := registryCreds(ref, user, passStdin, authFile)
	if err != nil {
		return err
	}
	tmp := file + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	p := &images.Puller{PlainHTTP: plainHTTP, Creds: creds, Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
	err = p.Save(context.Background(), ref, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, file)
}

func registryCreds(ref, user string, passStdin bool, authFile string) (*images.Credentials, error) {
	if user != "" || passStdin {
		if user == "" || !passStdin {
			return nil, fmt.Errorf("-username and -password-stdin go together")
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return nil, err
		}
		pass := strings.TrimRight(string(b), "\r\n")
		if pass == "" {
			return nil, fmt.Errorf("-password-stdin: nothing on stdin")
		}
		return &images.Credentials{Username: user, Password: pass}, nil
	}
	r, err := images.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	if authFile == "" {
		authFile = images.DefaultAuthFile()
	}
	ra, err := images.LoadAuthFile(authFile)
	if err != nil {
		return nil, err
	}
	return ra.For(r.Registry)
}

// shellCmd makes exec's command line: one argument is a shell command as
// it stands ('cd /tmp && ls'); several are a command and its arguments,
// each quoted as needed (python3 -c 'print(6*7)'), as docker exec takes them.
func shellCmd(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = a
		if a == "" || strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") != "" {
			q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(q, " ")
}
