// Package cluster wires OpenDsec components into gRPC servers. The cmd/ binaries
// start one component each; Local starts a whole cluster in one process for
// tests, benchmarks and development (spec §6).
package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/apiserver"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/container"
	"github.com/kernflux/opendsec/internal/edge/backend/fullvm"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/edge/backend/microvm"
	"github.com/kernflux/opendsec/internal/edge/host"
	"github.com/kernflux/opendsec/internal/edge/netpol"
	"github.com/kernflux/opendsec/internal/fleet"
	"github.com/kernflux/opendsec/internal/iam"
	"github.com/kernflux/opendsec/internal/images"
	"github.com/kernflux/opendsec/internal/metrics"
	"github.com/kernflux/opendsec/internal/pki"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/internal/watcher"
)

// Component is a running gRPC server plus its background loops.
type Component struct {
	Name   string
	Addr   string
	srv    *grpc.Server
	cancel context.CancelFunc
	done   sync.WaitGroup
	onStop []func() // run after the server and loops have stopped

	// Grace bounds how long Stop lets in-flight RPCs finish before closing
	// them (default 2s).
	Grace time.Duration
}

// Stop shuts the component down, abruptly if graceful stop takes too long.
func (c *Component) Stop() {
	c.cancel()
	grace := c.Grace
	if grace <= 0 {
		grace = 2 * time.Second
	}
	stopped := make(chan struct{})
	go func() { c.srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(grace):
		c.srv.Stop()
	}
	c.done.Wait()
	for _, f := range c.onStop {
		f()
	}
}

func serve(name, addr string, srv *grpc.Server, loops ...func(context.Context)) (*Component, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: listen %s: %w", name, addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Component{Name: name, Addr: lis.Addr().String(), srv: srv, cancel: cancel}
	c.done.Add(1)
	go func() { defer c.done.Done(); srv.Serve(lis) }()
	for _, l := range loops {
		c.done.Add(1)
		go func(l func(context.Context)) { defer c.done.Done(); l(ctx) }(l)
	}
	return c, nil
}

// Security returns how component self authenticates to its peers: its own
// certificate when cfg.TLS is set, the shared service token otherwise.
func Security(cfg *config.Cluster, self pki.Identity) (*rpcutil.Security, error) {
	if cfg.TLS.Dir == "" {
		return &rpcutil.Security{Token: cfg.ServiceToken}, nil
	}
	m, err := pki.Load(cfg.TLS.Dir, self)
	if err != nil {
		return nil, fmt.Errorf("tls for %s: %w", self, err)
	}
	metrics.CertExpiry(self.String(), m.Cert.Leaf.NotAfter)
	if !m.CAExpiry.IsZero() {
		metrics.CertExpiry("ca", m.CAExpiry)
	}
	return &rpcutil.Security{TLS: m}, nil
}

// StartIAM starts the IAM service and returns it with the admin token.
func StartIAM(cfg *config.Cluster, log *slog.Logger) (*Component, *iam.IAM, string, error) {
	m, err := iam.New(cfg.IAM.State)
	if err != nil {
		return nil, nil, "", err
	}
	m.MaxTokenTTL = config.Seconds(cfg.IAM.MaxTokenTTL)
	tok, err := m.Bootstrap(cfg.IAM.AdminID, cfg.IAM.AdminToken, cfg.IAM.RootQuota)
	if err != nil {
		return nil, nil, "", err
	}
	sec, err := Security(cfg, pki.Identity{Role: pki.RoleIAM})
	if err != nil {
		return nil, nil, "", err
	}
	srv := grpc.NewServer(rpcutil.InternalServerOptions(sec, rpcutil.IAMACL)...)
	pb.RegisterIAMServer(srv, &iam.Service{IAM: m})
	iamMetrics("", m)
	c, err := serve("iam", cfg.IAM.Addr, srv)
	if err == nil {
		metrics.SetReady("iam", func() error { return nil })
		c.onStop = append(c.onStop, func() { metrics.SetReady("iam", nil) })
		log.Info("iam listening", "addr", c.Addr)
	}
	return c, m, tok, err
}

// StartIAMReplica starts replica i of a Raft-replicated IAM (spec §15.1).
// Followers forward requests to the leader; whichever replica becomes leader
// (re)applies the idempotent bootstrap of the root project and admin. With
// join, a replica without Raft state waits to be added to the running
// cluster (spec §27.2) instead of bootstrapping one.
func StartIAMReplica(cfg *config.Cluster, i int, join bool, log *slog.Logger) (*Component, *iam.IAM, error) {
	rc := cfg.IAM.Replicas[i]
	if cfg.IAM.AdminToken == "" {
		return nil, nil, fmt.Errorf("iam replica %s: no admin token (is iam.admin_token_file %q readable?)", rc.ID, cfg.IAM.AdminTokenFile)
	}
	self := pki.Identity{Role: pki.RoleIAM, ID: rc.ID}
	sec, err := Security(cfg, self)
	if err != nil {
		return nil, nil, err
	}
	var peers []iam.Peer
	addrOf := map[string]string{}
	for _, r := range cfg.IAM.Replicas {
		peers = append(peers, iam.Peer{ID: r.ID, RaftAddr: r.RaftAddr})
		addrOf[r.ID] = r.Addr
	}
	m, err := iam.NewReplicated(iam.RaftOptions{ID: rc.ID, RaftAddr: rc.RaftAddr, DataDir: rc.DataDir, Peers: peers, TLS: sec.TLS, Join: join})
	if err != nil {
		return nil, nil, fmt.Errorf("iam replica %s: %w", rc.ID, err)
	}
	m.SetConfigAddrs(addrOf)
	m.MaxTokenTTL = config.Seconds(cfg.IAM.MaxTokenTTL)
	pool := rpcutil.NewPool(sec)
	svc := &iam.Service{IAM: m, Leader: func() (pb.IAMClient, error) {
		id := m.LeaderID()
		addr := m.MemberAddr(id)
		if id == "" || addr == "" {
			return nil, rpcutil.Err(rpcutil.Unavailable, "iam: no leader elected yet")
		}
		conn, err := pool.Get(addr)
		if err != nil {
			return nil, err
		}
		return pb.NewIAMClient(conn), nil
	}}
	srv := grpc.NewServer(rpcutil.InternalServerOptions(sec, rpcutil.IAMACL)...)
	pb.RegisterIAMServer(srv, svc)
	iamMetrics(rc.ID, m)
	lg := log.With("c", "iam", "replica", rc.ID)
	bootstrap := func(ctx context.Context) {
		lead := m.LeaderCh()
		for {
			if m.IsLeader() {
				for attempt := 0; attempt < 20 && m.IsLeader(); attempt++ {
					if _, err := m.Bootstrap(cfg.IAM.AdminID, cfg.IAM.AdminToken, cfg.IAM.RootQuota); err == nil {
						lg.Info("iam leader: bootstrap applied")
						break
					} else {
						lg.Warn("iam bootstrap", "err", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-lead:
			}
		}
	}
	c, err := serve("iam-"+rc.ID, rc.Addr, srv, bootstrap)
	if err != nil {
		m.Shutdown()
		return nil, nil, err
	}
	ready := "iam/" + rc.ID
	metrics.SetReady(ready, func() error {
		if m.LeaderID() == "" {
			return errors.New("no raft leader")
		}
		return nil
	})
	c.onStop = append(c.onStop, func() { metrics.SetReady(ready, nil); m.Shutdown(); pool.Close() })
	lg.Info("iam replica listening", "addr", c.Addr, "raft", rc.RaftAddr)
	return c, m, nil
}

// StartWatcher starts watcher instance i of cfg.Watcher.List(). With
// several instances, all probe and serve snapshots and the holder of the IAM
// reconcile lock reconciles (spec §16.1).
func StartWatcher(cfg *config.Cluster, i int, log *slog.Logger) (*Component, *watcher.Watcher, error) {
	wr := cfg.Watcher.List()[i]
	sec, err := Security(cfg, pki.Identity{Role: pki.RoleWatcher, ID: wr.ID})
	if err != nil {
		return nil, nil, err
	}
	pool := rpcutil.NewPool(sec)
	conn, err := pool.Get(cfg.IAM.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	w := watcher.New(cfg.Watcher, cfg.Edges, pool, pb.NewIAMClient(conn), log.With("c", "watcher", "watcher", wr.ID))
	watcherMetrics(wr.ID, w)
	if len(cfg.Watcher.Replicas) > 0 {
		w.Holder = "watcher/" + wr.ID
	}
	srv := grpc.NewServer(rpcutil.InternalServerOptions(sec, rpcutil.WatcherACL)...)
	pb.RegisterWatcherServer(srv, &watcher.Service{W: w})
	c, err := serve("watcher-"+wr.ID, wr.Addr, srv, w.Run)
	if err == nil {
		stale := 5*config.Seconds(cfg.Watcher.ProbeInterval) + 5*time.Second
		metrics.SetReady("watcher/"+wr.ID, func() error {
			snap := w.Snapshot()
			if snap == nil || time.Since(time.Unix(0, int64(snap.TakenAt*1e9))) > stale {
				return errors.New("no recent probe round")
			}
			return nil
		})
		c.onStop = append(c.onStop, func() { metrics.SetReady("watcher/"+wr.ID, nil) })
		log.Info("watcher listening", "addr", c.Addr, "id", wr.ID, "edges", len(cfg.Edges))
	}
	return c, w, err
}

// StartFleet starts fleet replica i of cfg.Fleet.Replicas (spec §28).
func StartFleet(cfg *config.Cluster, i int, log *slog.Logger) (*Component, *fleet.Server, error) {
	fr := cfg.Fleet.Replicas[i]
	sec, err := Security(cfg, pki.Identity{Role: pki.RoleFleet, ID: fr.ID})
	if err != nil {
		return nil, nil, err
	}
	pool := rpcutil.NewPool(sec)
	ic, err := pool.Get(cfg.IAM.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	wc, err := pool.Get(cfg.Watcher.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	iamc := pb.NewIAMClient(ic)
	f, err := fleet.New(fleet.Options{ID: fr.ID, Cfg: cfg.Fleet, KV: fleet.IAMKV{C: iamc}, IAM: iamc,
		Watcher: pb.NewWatcherClient(wc), Pool: pool, Log: log.With("c", "fleet", "replica", fr.ID)})
	if err != nil {
		return nil, nil, err
	}
	srv := grpc.NewServer(rpcutil.InternalServerOptions(sec, rpcutil.FleetACL)...)
	pb.RegisterFleetServer(srv, f)
	pb.RegisterFleetAdminServer(srv, f)
	c, err := serve("fleet-"+fr.ID, fr.Addr, srv, f.Run)
	if err != nil {
		return nil, nil, err
	}
	ready := "fleet/" + fr.ID
	metrics.SetReady(ready, f.Ready)
	fleetMetrics(fr.ID, f)
	c.onStop = append(c.onStop, func() { metrics.SetReady(ready, nil); metrics.SetCollector("fleet/"+fr.ID, nil); pool.Close() })
	log.Info("fleet replica listening", "addr", c.Addr, "id", fr.ID)
	return c, f, nil
}

// StartAPIServer starts apiserver instance i of cfg.APIServers.
func StartAPIServer(cfg *config.Cluster, i int, log *slog.Logger) (*Component, *apiserver.Server, error) {
	if err := ext.SetupWith(ext.Env{Component: "apiserver", Log: log, AuditDir: cfg.APIServers[i].AuditDir, AuditName: fmt.Sprint(i)},
		cfg.Extensions); err != nil {
		return nil, nil, err
	}
	sec, err := Security(cfg, pki.Identity{Role: pki.RoleAPIServer, ID: fmt.Sprint(i)})
	if err != nil {
		return nil, nil, err
	}
	pool := rpcutil.NewPool(sec)
	ic, err := pool.Get(cfg.IAM.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	wc, err := pool.Get(cfg.Watcher.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	ac := cfg.APIServers[i]
	a := apiserver.New(ac, cfg.Placement, pb.NewIAMClient(ic), pb.NewWatcherClient(wc), pool, log.With("c", "apiserver"))
	ext.SetDirectory(a.Directory())
	a.SetAdmission(cfg.Admission)
	if cfg.ImageStore.Root != "" {
		if a.Images, err = images.NewStore(cfg.ImageStore.Root); err != nil {
			return nil, nil, fmt.Errorf("image store: %w", err)
		}
	}
	var extra []grpc.ServerOption
	if ac.AuditDir != "" {
		a.Audit, err = apiserver.NewAuditor(ac.AuditDir, fmt.Sprint(i), ac.AuditMaxMB, ac.AuditKeep, ac.AuditRuntime)
		if err != nil {
			return nil, nil, fmt.Errorf("audit log: %w", err)
		}
		extra = a.Audit.ServerOptions()
	}
	extra = append(extra, a.ServerOptions()...)                          // after audit: rejections are audited
	srv := grpc.NewServer(rpcutil.PublicServerOptions(sec, extra...)...) // public API: bearer tokens, checked per call
	pb.RegisterDSecServer(srv, a)
	proxy := &apiserver.FleetProxy{S: a}
	if len(cfg.Fleet.Replicas) > 0 {
		fc, err := pool.Get(cfg.Fleet.ClientAddr())
		if err != nil {
			return nil, nil, err
		}
		proxy.Fleet = pb.NewFleetAdminClient(fc)
	}
	pb.RegisterFleetAdminServer(srv, proxy)
	c, err := serve(fmt.Sprintf("apiserver-%d", i), ac.Addr, srv, a.Run)
	if err != nil {
		return nil, nil, err
	}
	if a.Audit != nil {
		c.onStop = append(c.onStop, a.Audit.Close)
	}
	ready := fmt.Sprintf("apiserver/%d", i)
	metrics.SetReady(ready, a.Ready)
	c.onStop = append(c.onStop, func() { metrics.SetReady(ready, nil) })
	log.Info("apiserver listening", "addr", c.Addr, "tls", sec.TLS != nil, "audit", ac.AuditDir != "")
	return c, a, nil
}

// Backends builds the runtime backends configured for an edge. A backend
// with runtime "linux" is the real container runtime, "firecracker" the real
// microVM runtime; anything else is
// simulated, so scheduling for every backend type can be exercised before
// its real runtime exists.
func Backends(cfg *config.Cluster, ec config.Edge, log *slog.Logger) (map[string]backend.Backend, error) {
	out := map[string]backend.Backend{}
	var store *images.Store
	if cfg.ImageStore.Root != "" {
		var err error
		if store, err = images.NewStore(cfg.ImageStore.Root); err != nil {
			return nil, fmt.Errorf("image store: %w", err)
		}
	}
	var gpus *linuxrt.GPUs
	if len(ec.GPU.Devices) > 0 {
		gpus = linuxrt.NewGPUs(ec.GPU.Devices, ec.GPU.Extra, ec.GPU.Mounts, ec.GPU.SharedSlots)
	}
	for name, bc := range ec.Backends {
		switch bc.Runtime {
		case "", "sim":
			out[name] = backend.NewSim(name, bc)
		case "linux":
			o := container.FromConfig(name, ec, bc, store, log)
			o.GPUs = gpus
			b, err := container.New(o)
			if err != nil {
				return nil, fmt.Errorf("edge %s backend %s: %w", ec.ID, name, err)
			}
			out[name] = b
		case "qemu":
			b, err := fullvm.New(fullvm.FromConfig(name, ec, bc, store, log))
			if err != nil {
				return nil, fmt.Errorf("edge %s backend %s: %w", ec.ID, name, err)
			}
			out[name] = b
		case "firecracker":
			b, err := microvm.New(microvm.FromConfig(name, ec, bc, store, log))
			if err != nil {
				return nil, fmt.Errorf("edge %s backend %s: %w", ec.ID, name, err)
			}
			out[name] = b
		default:
			return nil, fmt.Errorf("edge %s backend %s: unknown runtime %q", ec.ID, name, bc.Runtime)
		}
	}
	return out, nil
}

// StartEdge starts the edge with the given id. register=true makes it announce
// itself to the watcher periodically.
func StartEdge(cfg *config.Cluster, id string, register bool, log *slog.Logger) (*Component, *edge.Edge, error) {
	ec, err := cfg.Edge(id)
	if err != nil {
		return nil, nil, err
	}
	sec, err := Security(cfg, pki.Identity{Role: pki.RoleEdge, ID: id})
	if err != nil {
		return nil, nil, err
	}
	pool := rpcutil.NewPool(sec)
	ic, err := pool.Get(cfg.IAM.ClientAddr())
	if err != nil {
		return nil, nil, err
	}
	lg := log.With("c", "edge", "edge", id)
	backends, err := Backends(cfg, *ec, lg)
	if err != nil {
		return nil, nil, err
	}
	hasLinux := false
	for _, bc := range ec.Backends {
		hasLinux = hasLinux || bc.Real()
	}
	if hasLinux {
		autoCapacity(ec, lg)
	}
	if ec.Capacity.GPUs == 0 {
		ec.Capacity.GPUs = int32(len(ec.GPU.Devices))
	}
	e := edge.New(*ec, backends)
	if reserve := ec.MemReserveMB; reserve >= 0 && hasLinux {
		if reserve == 0 {
			reserve = host.DefaultReserveMB()
		}
		e.Pressure = &host.Pressure{ReserveMB: reserve}
	}
	if reserve := ec.DiskReserveMB; reserve >= 0 && hasLinux {
		if reserve == 0 {
			reserve = host.DefaultDiskReserveMB(ec.StateDir)
		}
		e.DiskPressure = &host.DiskPressure{Path: ec.StateDir, ReserveMB: reserve}
	}
	if hasLinux {
		e.Usage, e.CPUPressureLimit = &host.Usage{}, ec.CPUPressureLimit
	}
	e.Release = edge.IAMReleaser(pb.NewIAMClient(ic), id, lg)
	e.LeaseEdge = edge.IAMLeaseEdge(pb.NewIAMClient(ic), lg)
	e.Peers = func(p *pb.EdgePeer) (pb.EdgeClient, error) {
		conn, err := pool.GetEdge(p.Addr, p.Id)
		if err != nil {
			return nil, err
		}
		return pb.NewEdgeClient(conn), nil
	}
	if ec.Network.Enabled {
		if e.Net, err = netpol.New(ec.ID, ec.Network, &cfg.Network, ec.StateDir, lg); err != nil {
			e.Shutdown(true)
			return nil, nil, fmt.Errorf("edge %s: network: %w", id, err)
		}
	}
	persist := hasLinux
	if ec.PersistState != nil {
		persist = *ec.PersistState
	}
	if persist {
		if err := e.EnableStore(filepath.Join(ec.StateDir, ec.ID, "records")); err != nil {
			return nil, nil, fmt.Errorf("edge %s: record store: %w", id, err)
		}
	}
	// Re-adopt sandboxes from a previous edge process before serving.
	st := e.Recover(context.Background())
	if st.Adopted > 0 || st.Failed > 0 {
		lg.Info("recovered sandboxes", "adopted", st.Adopted, "failed", st.Failed)
	}
	for _, err := range st.Errors {
		lg.Warn("recovery", "err", err)
	}
	srv := grpc.NewServer(rpcutil.InternalServerOptions(sec, rpcutil.EdgeACL)...)
	pb.RegisterEdgeServer(srv, &edge.Service{Edge: e})
	e.RegisterMetrics()
	loops := []func(context.Context){func(ctx context.Context) { e.Run(ctx, time.Second) }}
	c, err := serve("edge-"+id, ec.Addr, srv, loops...)
	if err != nil {
		e.Shutdown(true)
		return nil, nil, err
	}
	// Read the flag at stop time, so callers can change it on a running edge.
	c.onStop = append(c.onStop, func() { metrics.SetReady("edge/"+id, nil); e.Shutdown(!ec.KeepSandboxesOnExit) })
	metrics.SetReady("edge/"+id, func() error { return nil }) // serving, sandboxes recovered
	if register {
		advertise := ec.Advertise
		if advertise == "" {
			advertise = c.Addr
		}
		ctx, cancel := context.WithCancel(context.Background())
		prev := c.cancel
		c.cancel = func() { cancel(); prev() }
		// Register with every watcher instance.
		for _, wr := range cfg.Watcher.List() {
			wc, err := pool.Get(wr.Addr)
			if err != nil {
				c.Stop()
				return nil, nil, err
			}
			c.done.Add(1)
			go func() {
				defer c.done.Done()
				edge.RegisterLoop(ctx, pb.NewWatcherClient(wc), id, advertise, ec.Zone, 10*time.Second, lg)
			}()
		}
	}
	return c, e, nil
}

// autoCapacity fills an unconfigured edge capacity from the host, so a real
// runtime is never admitted against made-up numbers.
func autoCapacity(ec *config.Edge, log *slog.Logger) {
	if ec.Capacity.DiskMB == 0 {
		os.MkdirAll(ec.StateDir, 0o700)
		if total, _, err := host.DiskInfo(ec.StateDir); err == nil {
			ec.Capacity.DiskMB = total
			log.Info("edge disk capacity from state_dir filesystem", "disk_mb", total, "state_dir", ec.StateDir)
		} else {
			log.Warn("cannot stat state_dir; disk capacity unlimited", "err", err)
		}
	}
	if ec.Capacity.CPUCores > 0 || ec.Capacity.MemoryMB > 0 {
		return
	}
	total, _, err := host.MemInfo()
	if err != nil {
		log.Warn("cannot read host memory; leaving capacity unset", "err", err)
		return
	}
	ec.Capacity.CPUCores, ec.Capacity.MemoryMB = float64(host.CPUs()), total
	log.Info("edge capacity from host", "cpu_cores", ec.Capacity.CPUCores, "memory_mb", total)
}

// ---- in-process cluster ---------------------------------------------------------------

type Local struct {
	Cfg        *config.Cluster
	AdminToken string
	IAM        *iam.IAM // standalone IAM, or the leader replica at startup
	IAMComp    *Component
	// Replicated IAM (cfg.IAM.Replicas).
	IAMReplicas     []*iam.IAM
	IAMReplicaComps []*Component
	Watcher         *watcher.Watcher
	WatcherC        *Component
	Watchers        []*watcher.Watcher // every instance (Watcher is the first)
	WatcherComps    []*Component
	APIServers      []*apiserver.Server
	APIComps        []*Component
	Edges           map[string]*edge.Edge
	EdgeComps       map[string]*Component
	Fleets          []*fleet.Server // cfg.Fleet.Replicas
	FleetComps      []*Component
	log             *slog.Logger
}

// StartLocal starts every component of cfg in this process. Addresses ending
// in ":0" get a free port; cfg is updated with the bound addresses.
func StartLocal(cfg *config.Cluster, log *slog.Logger) (*Local, error) {
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	l := &Local{Cfg: cfg, Edges: map[string]*edge.Edge{}, EdgeComps: map[string]*Component{}, log: log}
	var err error
	if len(cfg.IAM.Replicas) > 0 {
		if err := l.startIAMReplicas(); err != nil {
			l.Stop()
			return nil, err
		}
	} else {
		if l.IAMComp, l.IAM, l.AdminToken, err = StartIAM(cfg, log); err != nil {
			return nil, err
		}
		cfg.IAM.Addr = l.IAMComp.Addr
	}
	// Edges first so their bound addresses go into the watcher's static list.
	for i := range cfg.Edges {
		id := cfg.Edges[i].ID
		c, e, err := StartEdge(cfg, id, false, log)
		if err != nil {
			l.Stop()
			return nil, err
		}
		cfg.Edges[i].Addr = c.Addr
		l.Edges[id], l.EdgeComps[id] = e, c
	}
	if len(cfg.Watcher.Replicas) > 0 {
		for i := range cfg.Watcher.Replicas {
			if strings.HasSuffix(cfg.Watcher.Replicas[i].Addr, ":0") {
				cfg.Watcher.Replicas[i].Addr = freeAddr()
			}
		}
	}
	for i := range cfg.Watcher.List() {
		c, w, err := StartWatcher(cfg, i, log)
		if err != nil {
			l.Stop()
			return nil, err
		}
		if len(cfg.Watcher.Replicas) == 0 {
			cfg.Watcher.Addr = c.Addr
		}
		l.Watchers, l.WatcherComps = append(l.Watchers, w), append(l.WatcherComps, c)
	}
	l.Watcher, l.WatcherC = l.Watchers[0], l.WatcherComps[0]
	for i := range cfg.Fleet.Replicas {
		if strings.HasSuffix(cfg.Fleet.Replicas[i].Addr, ":0") {
			cfg.Fleet.Replicas[i].Addr = freeAddr()
		}
	}
	for i := range cfg.Fleet.Replicas {
		if err := l.StartFleet(i); err != nil {
			l.Stop()
			return nil, err
		}
	}
	for i := range cfg.APIServers {
		c, a, err := StartAPIServer(cfg, i, log)
		if err != nil {
			l.Stop()
			return nil, err
		}
		cfg.APIServers[i].Addr = c.Addr
		l.APIServers = append(l.APIServers, a)
		l.APIComps = append(l.APIComps, c)
	}
	// Prime: one probe round and one snapshot refresh so the cluster is usable now.
	ctx := context.Background()
	l.Watcher.ProbeAll(ctx)
	for _, a := range l.APIServers {
		a.Refresh(ctx)
	}
	return l, nil
}

func (l *Local) startIAMReplicas() error {
	cfg := l.Cfg
	for i := range cfg.IAM.Replicas {
		r := &cfg.IAM.Replicas[i]
		if strings.HasSuffix(r.Addr, ":0") {
			r.Addr = freeAddr()
		}
		if strings.HasSuffix(r.RaftAddr, ":0") {
			r.RaftAddr = freeAddr()
		}
	}
	l.IAMReplicas = make([]*iam.IAM, len(cfg.IAM.Replicas))
	l.IAMReplicaComps = make([]*Component, len(cfg.IAM.Replicas))
	for i := range cfg.IAM.Replicas {
		if err := l.StartIAMReplica(i); err != nil {
			return err
		}
	}
	l.AdminToken = cfg.IAM.AdminToken
	// Wait for a leader and the bootstrap, so the cluster is usable on return.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := l.IAMLeader(); m != nil {
			if _, err := m.Authenticate(l.AdminToken); err == nil {
				l.IAM = m
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("replicated IAM did not elect a leader and bootstrap")
}

// StartIAMReplica (re)starts replica i of a replicated local IAM.
func (l *Local) StartIAMReplica(i int) error {
	return l.startIAMReplica(i, false)
}

func (l *Local) startIAMReplica(i int, join bool) error {
	c, m, err := StartIAMReplica(l.Cfg, i, join, l.log)
	if err != nil {
		return err
	}
	l.IAMReplicas[i], l.IAMReplicaComps[i] = m, c
	return nil
}

// JoinIAMReplica starts a new, empty replica r with -join (its addresses
// may end in :0) and returns its index; AddMember then adds it.
func (l *Local) JoinIAMReplica(r config.IAMReplica) (int, error) {
	if strings.HasSuffix(r.Addr, ":0") {
		r.Addr = freeAddr()
	}
	if strings.HasSuffix(r.RaftAddr, ":0") {
		r.RaftAddr = freeAddr()
	}
	l.Cfg.IAM.Replicas = append(l.Cfg.IAM.Replicas, r)
	l.IAMReplicas = append(l.IAMReplicas, nil)
	l.IAMReplicaComps = append(l.IAMReplicaComps, nil)
	i := len(l.Cfg.IAM.Replicas) - 1
	return i, l.startIAMReplica(i, true)
}

// StopIAMReplica stops replica i (simulating a crash of that IAM node).
func (l *Local) StopIAMReplica(i int) {
	if c := l.IAMReplicaComps[i]; c != nil {
		c.Stop()
		l.IAMReplicaComps[i], l.IAMReplicas[i] = nil, nil
	}
}

// StopWatcher stops watcher instance i (simulating its crash).
func (l *Local) StopWatcher(i int) {
	if c := l.WatcherComps[i]; c != nil {
		c.Stop()
		l.WatcherComps[i] = nil
	}
}

// IAMLeader returns the current leader replica, or nil.
func (l *Local) IAMLeader() *iam.IAM {
	for _, m := range l.IAMReplicas {
		if m != nil && m.IsLeader() {
			return m
		}
	}
	return nil
}

func freeAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "127.0.0.1:0"
	}
	defer ln.Close()
	return ln.Addr().String()
}

// Settle runs a probe round and refreshes every apiserver's snapshot.
func (l *Local) Settle() {
	ctx := context.Background()
	l.Watcher.ProbeAll(ctx)
	for _, a := range l.APIServers {
		a.Refresh(ctx)
	}
}

// RestartEdge stops edge id (leaving its sandboxes running if
// keep_sandboxes_on_exit is set) and starts it again on the same address,
// where it re-adopts them. between runs while the edge is down.
func (l *Local) RestartEdge(id string, between func()) error {
	l.StopEdge(id)
	if between != nil {
		between()
	}
	c, e, err := StartEdge(l.Cfg, id, false, l.log)
	if err != nil {
		return err
	}
	l.Edges[id], l.EdgeComps[id] = e, c
	return nil
}

func (l *Local) StopEdge(id string) {
	if c := l.EdgeComps[id]; c != nil {
		c.Stop()
		delete(l.EdgeComps, id)
	}
}

// StartFleet (re)starts fleet replica i.
func (l *Local) StartFleet(i int) error {
	c, f, err := StartFleet(l.Cfg, i, l.log)
	if err != nil {
		return err
	}
	for len(l.Fleets) <= i {
		l.Fleets, l.FleetComps = append(l.Fleets, nil), append(l.FleetComps, nil)
	}
	l.Fleets[i], l.FleetComps[i] = f, c
	return nil
}

// StopFleet stops fleet replica i.
func (l *Local) StopFleet(i int) {
	if i < len(l.FleetComps) && l.FleetComps[i] != nil {
		l.FleetComps[i].Stop()
		l.FleetComps[i] = nil
	}
}

func (l *Local) Stop() {
	for _, c := range l.APIComps {
		c.Stop()
	}
	for i := range l.FleetComps {
		l.StopFleet(i)
	}
	for _, c := range l.WatcherComps {
		if c != nil {
			c.Stop()
		}
	}
	for _, c := range l.EdgeComps {
		c.Stop()
	}
	if l.IAMComp != nil {
		l.IAMComp.Stop()
	}
	for _, c := range l.IAMReplicaComps {
		if c != nil {
			c.Stop()
		}
	}
}

// SimConfig returns a config for a local cluster of n sim edges.
func SimConfig(n, apiservers int, edgeCPU float64, edgeMemMB int64, maxSandboxes int32) *config.Cluster {
	cfg := &config.Cluster{
		ServiceToken: "local-service-token",
		IAM:          config.IAM{Addr: "127.0.0.1:0"},
		Watcher:      config.Watcher{Addr: "127.0.0.1:0"},
	}
	for i := 0; i < apiservers; i++ {
		cfg.APIServers = append(cfg.APIServers, config.APIServer{Addr: "127.0.0.1:0"})
	}
	for i := 0; i < n; i++ {
		cfg.Edges = append(cfg.Edges, config.Edge{
			ID: fmt.Sprintf("e%03d", i), Addr: "127.0.0.1:0",
			Capacity: config.Resources{CPUCores: edgeCPU, MemoryMB: edgeMemMB},
			Backends: map[string]config.Backend{"sim": {MaxSandboxes: maxSandboxes}, "container": {MaxSandboxes: maxSandboxes}},
		})
	}
	cfg.Defaults()
	return cfg
}

// GeneratePKI creates a CA in dir and issues a certificate for every
// component in cfg (spec §14.1), with the hosts of their listen addresses.
func GeneratePKI(cfg *config.Cluster, dir string, validity time.Duration, extraHosts ...string) error {
	return GeneratePKIWithCA(cfg, dir, validity, validity, extraHosts...)
}

// GeneratePKIWithCA is GeneratePKI with a CA valid for caValidity.
func GeneratePKIWithCA(cfg *config.Cluster, dir string, caValidity, validity time.Duration, extraHosts ...string) error {
	ca, err := pki.NewCA("opendsec cluster CA", caValidity)
	if err != nil {
		return err
	}
	if err := ca.Write(dir); err != nil {
		return err
	}
	hosts := func(addr string) []string {
		return append([]string{pki.HostOf(addr), "localhost", "127.0.0.1"}, extraHosts...)
	}
	issue := func(id pki.Identity, addr string) error { return ca.IssueTo(dir, id, hosts(addr), validity) }
	if len(cfg.IAM.Replicas) == 0 {
		if err := issue(pki.Identity{Role: pki.RoleIAM}, cfg.IAM.Addr); err != nil {
			return err
		}
	}
	for _, r := range cfg.IAM.Replicas {
		hs := append(hosts(r.Addr), pki.HostOf(r.RaftAddr))
		if err := ca.IssueTo(dir, pki.Identity{Role: pki.RoleIAM, ID: r.ID}, hs, validity); err != nil {
			return err
		}
	}
	for _, wr := range cfg.Watcher.List() {
		if err := issue(pki.Identity{Role: pki.RoleWatcher, ID: wr.ID}, wr.Addr); err != nil {
			return err
		}
	}
	for i, a := range cfg.APIServers {
		if err := issue(pki.Identity{Role: pki.RoleAPIServer, ID: fmt.Sprint(i)}, a.Addr); err != nil {
			return err
		}
	}
	for _, e := range cfg.Edges {
		if err := issue(pki.Identity{Role: pki.RoleEdge, ID: e.ID}, e.Addr); err != nil {
			return err
		}
	}
	for _, f := range cfg.Fleet.Replicas {
		if err := issue(pki.Identity{Role: pki.RoleFleet, ID: f.ID}, f.Addr); err != nil {
			return err
		}
	}
	return nil
}

// ---- metrics (spec §26.3) ---------------------------------------------------------

func iamMetrics(replica string, m *iam.IAM) {
	metrics.SetCollector("iam/"+replica, metrics.Gauges(prometheus.Labels{"replica": replica}, map[string]metrics.Gauge{
		"opendsec_iam_leader": {Help: "1 on the IAM replica that leads (always 1 unreplicated).", F: func() float64 {
			if m.IsLeader() {
				return 1
			}
			return 0
		}},
		"opendsec_iam_leases": {Help: "Quota leases held (one per live sandbox).", F: func() float64 {
			n := 0
			for _, c := range m.EdgeLeases() {
				n += c
			}
			return float64(n)
		}},
	}))
}

func watcherMetrics(id string, w *watcher.Watcher) {
	count := func(f func(*pb.EdgeState) bool) func() float64 {
		return func() float64 {
			n := 0
			if snap := w.Snapshot(); snap != nil {
				for _, e := range snap.Edges {
					if f(e) {
						n++
					}
				}
			}
			return float64(n)
		}
	}
	metrics.SetCollector("watcher/"+id, metrics.Gauges(prometheus.Labels{"watcher": id}, map[string]metrics.Gauge{
		"opendsec_watcher_edges_healthy":   {Help: "Edges answering their status polls.", F: count(func(e *pb.EdgeState) bool { return e.Healthy })},
		"opendsec_watcher_edges_unhealthy": {Help: "Edges not answering their status polls.", F: count(func(e *pb.EdgeState) bool { return !e.Healthy })},
		"opendsec_watcher_edges_draining":  {Help: "Edges taking no new sandboxes.", F: count(func(e *pb.EdgeState) bool { return e.Draining })},
	}))
}

func fleetMetrics(id string, f *fleet.Server) {
	metrics.SetCollector("fleet/"+id, &fleetCollector{id: id, f: f})
}

var (
	descFleetLeader   = prometheus.NewDesc("opendsec_fleet_leader", "1 on the fleet replica that leads.", []string{"replica"}, nil)
	descFleetNodes    = prometheus.NewDesc("opendsec_fleet_nodes", "Nodes by state and failure domain (leader only).", []string{"state", "domain"}, nil)
	descFleetRelease  = prometheus.NewDesc("opendsec_fleet_node_release", "Active nodes by the release they run (leader only).", []string{"release"}, nil)
	descFleetHBAge    = prometheus.NewDesc("opendsec_fleet_heartbeat_age_seconds", "Oldest heartbeat among active nodes (leader only).", nil, nil)
	descFleetRollout  = prometheus.NewDesc("opendsec_fleet_rollout_active", "1 while a rollout is in the given state (leader only).", []string{"state"}, nil)
	descFleetProgress = prometheus.NewDesc("opendsec_fleet_rollout_progress", "Finished steps / steps of the active rollout (leader only).", nil, nil)
)

type fleetCollector struct {
	id string
	f  *fleet.Server
}

func (c *fleetCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descFleetLeader, descFleetNodes, descFleetRelease, descFleetHBAge, descFleetRollout, descFleetProgress} {
		ch <- d
	}
}

func (c *fleetCollector) Collect(ch chan<- prometheus.Metric) {
	st := c.f.Stats()
	leader := 0.0
	if st.Leader {
		leader = 1
	}
	ch <- prometheus.MustNewConstMetric(descFleetLeader, prometheus.GaugeValue, leader, c.id)
	if !st.Leader {
		return
	}
	for k, n := range st.Nodes {
		ch <- prometheus.MustNewConstMetric(descFleetNodes, prometheus.GaugeValue, float64(n), k[0], k[1])
	}
	for r, n := range st.Releases {
		ch <- prometheus.MustNewConstMetric(descFleetRelease, prometheus.GaugeValue, float64(n), r)
	}
	ch <- prometheus.MustNewConstMetric(descFleetHBAge, prometheus.GaugeValue, st.MaxHBAge)
	if st.RolloutState != "" {
		ch <- prometheus.MustNewConstMetric(descFleetRollout, prometheus.GaugeValue, 1, st.RolloutState)
		ch <- prometheus.MustNewConstMetric(descFleetProgress, prometheus.GaugeValue, st.Progress)
	}
}
