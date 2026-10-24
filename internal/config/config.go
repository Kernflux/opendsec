// Package config loads the cluster configuration (spec §6).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kernflux/opendsec/internal/ids"
)

type Cluster struct {
	ServiceToken string      `json:"service_token"` // dev-mode internal auth when tls is not configured
	TLS          TLS         `json:"tls"`
	IAM          IAM         `json:"iam"`
	Watcher      Watcher     `json:"watcher"`
	APIServers   []APIServer `json:"apiserver"`
	Placement    Placement   `json:"placement"`
	Edges        []Edge      `json:"edges"`
	// EdgeTemplate configures edges not listed in Edges (dynamic nodes, e.g.
	// a Kubernetes DaemonSet): `opendsec-edge -id <id> -advertise <addr>`.
	EdgeTemplate *Edge `json:"edge_template"`
	// ImageStore is the shared image store every edge and apiserver mounts
	// (spec §17.2); without it only edge-local static images exist.
	ImageStore ImageStore `json:"image_store"`
	// Admission applies cluster-wide creation policy at the apiservers
	// (spec §18.1).
	Admission Admission `json:"admission"`
	// Network is the network policy's rule sets and defaults (spec §20).
	Network NetworkPolicy `json:"network"`
	// Fleet is the cluster management service (spec §28); optional.
	Fleet Fleet `json:"fleet"`
	// Extensions configures the extensions linked into the build, by name
	// (ext); the open-source build has none.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
	// E2B is the E2B-compatible gateway (spec §37); optional.
	E2B *E2B `json:"e2b,omitempty"`
}

// E2B configures the E2B gateways (opendsec-e2b, spec §37): E2B's SDKs run
// their sandboxes through them.
type E2B struct {
	// Gateways are the instances (role e2b=<index>), each serving on Addr.
	Gateways []E2BGateway `json:"gateways"`
	// Project sandboxes are created in and listed from, unless a request
	// names another (X-OpenDsec-Project).
	Project string `json:"project"`
	// Domain is returned as the sandboxes' domain, for SDKs that build
	// sandbox hosts "<port>-<id>.<domain>" (wildcard DNS and certificate
	// to the gateways). Empty: clients set E2B_SANDBOX_URL.
	Domain string `json:"domain,omitempty"`
	// Templates maps E2B template ids (SDKs default to "base") to sandboxes.
	// A template id holding "/" is taken as an image name, with
	// DefaultTemplate's other settings.
	Templates       map[string]E2BTemplate `json:"templates"`
	DefaultTemplate E2BTemplate            `json:"default_template"`
	// MaxTimeout caps a sandbox's timeout (seconds; 0 = only the admission cap).
	MaxTimeout int64 `json:"max_timeout_s,omitempty"`
}

type E2BGateway struct {
	Addr    string `json:"addr"`               // listen address, e.g. 10.0.0.1:7400
	TLSCert string `json:"tls_cert,omitempty"` // serve TLS (default: plain HTTP behind a TLS proxy)
	TLSKey  string `json:"tls_key,omitempty"`
}

// E2BTemplate is what a sandbox of an E2B template is.
type E2BTemplate struct {
	Image    string  `json:"image"`
	Backend  string  `json:"backend,omitempty"`   // default microvm
	CPU      float64 `json:"cpu,omitempty"`       // default 2
	MemoryMB int64   `json:"memory_mb,omitempty"` // default 512
	DiskMB   int64   `json:"disk_mb,omitempty"`   // default: the backend's
	// StartCmd is started (bash -l -c) in every new sandbox of the template,
	// as E2B templates' start command, and ReadyPort waited for before the
	// sandbox is handed out (up to ReadyTimeout seconds, default 60). Not
	// needed for an image that is a memory snapshot of a running server.
	StartCmd     string `json:"start_cmd,omitempty"`
	ReadyPort    int    `json:"ready_port,omitempty"`
	ReadyTimeout int    `json:"ready_timeout_s,omitempty"`
}

// Fleet configures the cluster management service and its node agents
// (spec §28). Durations are seconds.
type Fleet struct {
	Replicas     []FleetReplica `json:"replicas"`
	LockTTL      float64        `json:"lock_ttl"`      // leader lock, default 10
	Heartbeat    float64        `json:"heartbeat_s"`   // node agent interval, default 10
	MaxDownloads int            `json:"max_downloads"` // concurrent release downloads per replica, default 64
	KeepReleases int            `json:"keep_releases"` // releases kept besides those in use, default 10
	EdgePort     int            `json:"edge_port"`     // edges listen on node-addr:edge_port, default 7201
	// Readiness ports per role, for units the agents restart; defaults are
	// the -metrics ports of deploy/systemd: iam 9461, watcher 9462,
	// apiserver 9463, edge 9464, fleet 9465, e2b 9467.
	ReadyPorts map[string]int `json:"ready_ports"`
	// Optional rollout gates evaluated against Prometheus while a batch
	// bakes: each query's value must stay at or below max.
	PrometheusURL string      `json:"prometheus_url"`
	Gates         []FleetGate `json:"gates"`
}

type FleetReplica struct {
	ID      string `json:"id"`
	Addr    string `json:"addr"`
	DataDir string `json:"data_dir"` // releases; default /var/lib/opendsec/fleet
}

type FleetGate struct {
	Name  string  `json:"name"`
	Query string  `json:"query"`
	Max   float64 `json:"max"`
}

// ClientAddr is what fleet clients dial (comma separated).
func (f Fleet) ClientAddr() string {
	addrs := make([]string, len(f.Replicas))
	for i, r := range f.Replicas {
		addrs[i] = r.Addr
	}
	return strings.Join(addrs, ",")
}

// Admission holds the defaults and limits every apiserver enforces (spec
// §18). TTLs are seconds; for the defaults and the cap, 0 means the built-in
// value and -1 means none. Rates are per principal and per apiserver
// instance (N instances admit up to N times the rate); -1 disables a limit.
type Admission struct {
	DefaultTTLRunningStop float64 `json:"default_ttl_running_stop_s"` // idle TTL when the request has none; default 3600
	DefaultTTLMax         float64 `json:"default_ttl_max_s"`          // lifetime when the request has none; default 86400
	MaxTTLMax             float64 `json:"max_ttl_max_s"`              // largest lifetime a request may ask for; default 7 days

	// One RL job drives thousands of sandboxes from a single principal, so
	// the defaults only stop runaway clients.
	RequestRate        float64 `json:"request_rate"`         // API calls/s, including exec/file calls; default 10000
	RequestBurst       float64 `json:"request_burst"`        // default 2 x rate
	CreateRate         float64 `json:"create_rate"`          // sandbox creations/s; default 2000
	CreateBurst        float64 `json:"create_burst"`         // default 32768: one full batch at once
	AuthFailRate       float64 `json:"auth_fail_rate"`       // failed authentications/s per client address; default 5
	MaxInflightCreates int     `json:"max_inflight_creates"` // concurrent creations per apiserver; default 2048
}

type ImageStore struct {
	Root string `json:"root"`
}

type IAMReplica struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`      // gRPC
	RaftAddr string `json:"raft_addr"` // replication
	DataDir  string `json:"data_dir"`  // Raft log, stable store and snapshots
}

// ClientAddr is what IAM clients dial: the standalone address, or every
// replica (comma separated; clients balance and fail over between them).
func (i IAM) ClientAddr() string {
	if len(i.Replicas) == 0 {
		return i.Addr
	}
	addrs := make([]string, len(i.Replicas))
	for k, r := range i.Replicas {
		addrs[k] = r.Addr
	}
	return strings.Join(addrs, ",")
}

// TLS enables mTLS between components and TLS on the public API (spec §14).
// Dir holds ca.crt and <component>.crt/.key, as written by `opendsecctl pki init`.
type TLS struct {
	Dir string `json:"dir"`
}

type IAM struct {
	Addr string `json:"addr"` // standalone IAM
	// Replicas, if set, run IAM replicated with Raft (spec §15.1); Addr and
	// State are then ignored and admin_token is required.
	Replicas   []IAMReplica `json:"replicas"`
	State      string       `json:"state"`       // JSON state file; "" = in-memory
	AdminID    string       `json:"admin_id"`    // default "admin"
	AdminToken string       `json:"admin_token"` // "dsk.<admin_id>.<secret>"
	// AdminTokenFile holds admin_token instead, so the shared config file
	// carries no secret; only IAM nodes need it (spec §27.3).
	AdminTokenFile string             `json:"admin_token_file"`
	RootQuota      map[string]float64 `json:"root_quota"`
	// MaxTokenTTL caps the lifetime of issued tokens (seconds); 0 = no cap.
	// With a cap, tokens that never expire cannot be issued.
	MaxTokenTTL float64 `json:"max_token_ttl_s"`
}

type Watcher struct {
	Addr string `json:"addr"` // single watcher
	// Replicas run several watchers: all probe and serve snapshots; the one
	// holding the IAM lease lock reconciles (spec §16.1).
	Replicas          []WatcherReplica `json:"replicas"`
	LockTTL           float64          `json:"lock_ttl"`           // seconds, default 10
	ProbeInterval     float64          `json:"probe_interval"`     // seconds, default 1
	ProbeTimeout      float64          `json:"probe_timeout"`      // seconds, default 0.5
	UnhealthyAfter    int              `json:"unhealthy_after"`    // consecutive failures, default 3
	ReconcileInterval float64          `json:"reconcile_interval"` // seconds, default 30
	ReconcileMinAge   float64          `json:"reconcile_min_age"`  // seconds, default 60
	LostEdgeGrace     float64          `json:"lost_edge_grace"`    // release a dead edge's quota after this, default 120
	UnboundMaxAge     float64          `json:"unbound_max_age"`    // release leases no edge claimed after this, default 600
}

type WatcherReplica struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

// List returns every watcher instance (a single addr becomes id "").
func (w Watcher) List() []WatcherReplica {
	if len(w.Replicas) > 0 {
		return w.Replicas
	}
	return []WatcherReplica{{Addr: w.Addr}}
}

// ClientAddr is what watcher clients dial (comma separated for replicas).
func (w Watcher) ClientAddr() string {
	l := w.List()
	addrs := make([]string, len(l))
	for i, r := range l {
		addrs[i] = r.Addr
	}
	return strings.Join(addrs, ",")
}

type APIServer struct {
	Addr            string  `json:"addr"`
	AuditDir        string  `json:"audit_dir"`        // "" disables the audit log
	AuditMaxMB      int64   `json:"audit_max_mb"`     // rotate after this size, default 256
	AuditKeep       int     `json:"audit_keep"`       // files kept, the current one included (oldest go first), default 8
	AuditRuntime    bool    `json:"audit_runtime"`    // also audit exec/file/http calls
	SnapshotRefresh float64 `json:"snapshot_refresh"` // seconds, default 1
}

type Placement struct {
	K                   int      `json:"k"`                     // power-of-k, default 2
	MaxAttempts         int      `json:"max_attempts"`          // default 3
	RejectPenalty       float64  `json:"reject_penalty"`        // seconds, default 2
	OverlayGrace        float64  `json:"overlay_grace"`         // seconds, default 2
	BurstThreshold      float64  `json:"burst_threshold"`       // default 0.8; <=0 disables
	BurstEligibleImages []string `json:"burst_eligible_images"` // images whose layers are mirrored to cloud
	// UsageFloor: a host's actual CPU or memory use (spec §3.4) counts in its
	// load only from this share up, default 0.2; -1 counts it always. Below
	// it, use is the host's own baseline (daemons, an NFS server: a few
	// percent that differ by host), which would otherwise steer placement
	// away from a host that is not busy at all.
	UsageFloor float64 `json:"usage_floor"`
}

type Edge struct {
	ID            string    `json:"id"`
	Addr          string    `json:"addr"`      // listen address
	Advertise     string    `json:"advertise"` // address registered with watchers; default: the bound address
	Zone          string    `json:"zone"`      // onprem | cloud
	Capacity      Resources `json:"capacity"`
	CPUOvercommit float64   `json:"cpu_overcommit"` // default 8
	// Admission under memory pressure: reject creations while host
	// MemAvailable < this. 0 = auto (10% of RAM, >= 128 MB) when the edge has
	// a linux runtime backend; -1 disables.
	MemReserveMB int64 `json:"mem_reserve_mb"`
	// Admission under CPU pressure (spec §3.4): reject creations while the
	// host's PSI "some" avg10 (/proc/pressure/cpu, percent of time a runnable
	// task waited for a CPU) is above this. 0 = off (the default): placement
	// already ranks a busy host lower; a burst of creations alone can raise
	// PSI, so set it from the node's own measurements (e.g. 50).
	CPUPressureLimit float64 `json:"cpu_pressure_limit"`
	// Sandbox record persistence and re-adoption across edge restarts (spec
	// §13). Default: on when the edge has a linux runtime backend.
	PersistState *bool `json:"persist_state"`
	// Disk admission (spec §18.2): sandboxes' writable disks are charged
	// against capacity.disk_mb x disk_overcommit, and creations are rejected
	// while the state_dir filesystem has less than disk_reserve_mb free.
	// disk_reserve_mb: 0 = auto (5% of the filesystem, >= 1024 MB) when the
	// edge has a linux runtime backend; -1 disables.
	DiskOvercommit float64 `json:"disk_overcommit"` // default 1
	DiskReserveMB  int64   `json:"disk_reserve_mb"`
	// Leave sandboxes running when the edge exits (rolling upgrades). Default
	// false: dev clusters and tests clean up after themselves.
	KeepSandboxesOnExit bool    `json:"keep_sandboxes_on_exit"`
	MemOvercommit       float64 `json:"mem_overcommit"` // default 1
	// PausedMemCharge: the part of its memory a paused sandbox whose pause
	// frees its memory (microVMs; containers with pause_reclaim) still
	// counts for admission, in [0, 1]; default 1 (spec §24). Resuming
	// charges all of it again and fails only under memory pressure.
	PausedMemCharge  *float64           `json:"paused_mem_charge,omitempty"`
	Backends         map[string]Backend `json:"backends"`
	StoppedRetention float64            `json:"stopped_retention"` // seconds to keep ended records, default 600

	// Sandbox networking and its policy (spec §20); off by default (sandboxes
	// then only have lo).
	Network EdgeNetwork `json:"network"`
	// GPU devices for container-runtime sandboxes (spec §22.2).
	GPU GPUConfig `json:"gpu"`

	// Container runtime (spec §11.5).
	StateDir string              `json:"state_dir"` // default /var/lib/opendsec
	AgentDir string              `json:"agent_dir"` // opendsec-aether + opendsec-chronus; default: next to the edge binary
	Images   map[string][]string `json:"images"`    // image -> overlay lowerdirs, topmost first (P2; P3 adds layers)
}

// EdgeNetwork enables networking for an edge's sandboxes (spec §20).
// Edges sharing a host need distinct subnets and DNS ports.
type EdgeNetwork struct {
	Enabled bool   `json:"enabled"`
	Subnet  string `json:"subnet"`   // sandbox addresses, a /30 each; default 10.88.0.0/16
	DNSPort int    `json:"dns_port"` // the edge's DNS proxy, on the host side; default 15353
}

type DiskIO struct {
	ReadMBps  int64 `json:"read_mbps"`
	WriteMBps int64 `json:"write_mbps"`
	ReadIOPS  int64 `json:"read_iops"`
	WriteIOPS int64 `json:"write_iops"`
}

// GPUConfig lists a node's GPUs. capacity.gpus defaults to len(devices).
type GPUConfig struct {
	Devices     []string `json:"devices"`      // e.g. ["/dev/nvidia0", "/dev/nvidia1"]
	Extra       []string `json:"extra"`        // nodes every GPU sandbox gets, e.g. /dev/nvidiactl, /dev/nvidia-uvm
	Mounts      []string `json:"mounts"`       // host files or dirs bound read-only (driver libraries, nvidia-smi)
	SharedSlots int      `json:"shared_slots"` // gpu_mode "shared" sandboxes per device; default 4
	// PCI devices (e.g. "0000:3b:00.0") passed through to fullvm sandboxes
	// with VFIO (spec §23): bound to vfio-pci, /dev/vfio/<group> usable by
	// group kvm.
	PCI []string `json:"pci"`
}

// NetworkPolicy is the cluster-wide part of the network policy (spec §20).
type NetworkPolicy struct {
	// RuleSets names groups of destinations a sandbox's network_rules can
	// allow: domains ("pypi.org" also covers its subdomains) and IPv4 CIDRs.
	RuleSets map[string][]string `json:"rule_sets"`
	// DefaultRules apply under every sandbox's own network_rules.
	DefaultRules map[string]bool `json:"default_rules"`
	// UpstreamDNS: resolvers the edges' DNS proxies query; default: the
	// host's /etc/resolv.conf.
	UpstreamDNS []string `json:"upstream_dns"`
}

type Resources struct {
	CPUCores float64 `json:"cpu_cores"`
	MemoryMB int64   `json:"memory_mb"`
	GPUs     int32   `json:"gpus"`
	DiskMB   int64   `json:"disk_mb"` // writable-disk capacity; 0 = auto (state_dir filesystem size) for linux runtimes, else unlimited
}

type Backend struct {
	MaxSandboxes int32  `json:"max_sandboxes"`
	Runtime      string `json:"runtime"` // sim (default) | linux | firecracker | qemu

	// linux and firecracker runtimes
	DefaultDiskMB int64 `json:"default_disk_mb"` // writable layer size when the request has none; default 10240
	PidsMax       int   `json:"pids_max"`        // default 4096 (linux)
	// DiskIO bounds each sandbox's disk I/O (cgroup io.max; spec §24): for
	// containers on their writable disk, for VMs on the state filesystem's
	// device. Zero fields are unlimited.
	DiskIO DiskIO `json:"disk_io"`
	// PauseReclaim: pausing a container also pushes its memory out to swap
	// (memory.reclaim; needs host swap), read back ahead of use on resume
	// (spec §22.1).
	PauseReclaim bool `json:"pause_reclaim,omitempty"`
	// CoreSched (linux, firecracker and qemu runtimes; paper §5.2, spec
	// §29.1): each sandbox gets its own core scheduling cookie, so no two
	// sandboxes share a core's hardware threads at once. A latency-sensitive
	// sandbox then keeps its core to itself under best-effort load, and SMT
	// side channels between sandboxes close. Default (absent): on when the
	// kernel has CONFIG_SCHED_CORE; true requires it; false turns it off.
	CoreSched *bool `json:"core_sched,omitempty"`
	// WarmPool (linux runtime): image -> sandboxes kept started ahead of
	// requests (the FnCall backend, spec §22.3). Plain requests for the
	// image (no snapshot, user, workdir, path restrictions or GPUs, default
	// disk) take one and start in milliseconds.
	WarmPool map[string]int `json:"warm_pool,omitempty"`
	// LayerCache (linux runtime): containers run on node-local copies of
	// their store layers, copied on first use, instead of mounting the
	// store's (spec §33.1). Running containers then do not stall when the
	// store (an NFS NAS) is unreachable. Default (absent): on.
	LayerCache *bool `json:"layer_cache,omitempty"`

	// firecracker runtime (microvm, spec §19.3)
	Kernel      string `json:"kernel"`      // guest vmlinux (required)
	Firecracker string `json:"firecracker"` // default: "firecracker" on PATH
	Jailer      string `json:"jailer"`      // default: "jailer" on PATH
	UIDBase     int    `json:"uid_base"`    // each microVM runs as its own uid from [uid_base, uid_base+65536); default 1000000000
	// ErofsImages: images as EROFS disks, built once in the image store
	// and copied to each node, instead of flattened to ext4 on every node
	// (spec §29.4). Needs a guest kernel with EROFS (deploy/guest-kernel)
	// and mkfs.erofs (erofs-utils) on the node.
	ErofsImages bool `json:"erofs_images,omitempty"`
	// VMOverheadMB is added to the guest memory for the VM's cgroup limit
	// (the VMM itself, page tables, device buffers); default 64.
	VMOverheadMB int64 `json:"vm_overhead_mb"`
	// Memory optimizations (spec §19.13); they need the OpenDsec guest kernel
	// (deploy/guest-kernel). ImagePmem attaches the image as virtio-pmem,
	// mounted with DAX: VMs of an image share its host page cache instead of
	// each caching it. FreePageReporting returns memory the guest frees to
	// the host (virtio-balloon). ColdAgeS > 0 runs DAMON_RECLAIM in the
	// guest, paging out memory idle that long to compressed swap (zram of
	// ZramPct % of the VM's memory, default 100: it bounds the data swapped,
	// before compression); the pages freed go back to the host with
	// FreePageReporting.
	// fullvm runtime (QEMU, spec §23): the QEMU binary (default
	// qemu-system-x86_64 on PATH); FullInit hands PID 1 to the image's
	// /sbin/init (aether runs beside it).
	QEMU     string `json:"qemu,omitempty"`
	FullInit bool   `json:"full_init,omitempty"`

	ImagePmem         bool `json:"image_pmem,omitempty"`
	FreePageReporting bool `json:"free_page_reporting,omitempty"`
	ColdAgeS          int  `json:"cold_age_s,omitempty"`
	ZramPct           int  `json:"zram_pct,omitempty"`
	// ColdBootDirtyTracking (microvm, default true): cold-booted VMs keep
	// a KVM dirty page log, so their pauses write only the pages touched.
	// false: they run without one, which keeps the host's huge pages under
	// guest memory (memory writes 1.3–1.7x faster in spec §19.14),
	// and their first pause or snapshot writes all memory instead. VMs
	// restored from a snapshot always keep the log.
	ColdBootDirtyTracking *bool `json:"cold_boot_dirty_tracking,omitempty"`

	// sim backend only
	CreateLatencyMs float64 `json:"create_latency_ms"` // median; lognormal
	LatencySigma    float64 `json:"latency_sigma"`
	FailureRate     float64 `json:"failure_rate"`
}

// Real reports whether the backend runs real sandboxes on this host (it
// then needs the host's capacity, disk and memory pressure accounting).
func (b Backend) Real() bool {
	return b.Runtime == "linux" || b.Runtime == "firecracker" || b.Runtime == "qemu"
}

func Load(path string) (*Cluster, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Cluster
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f := c.IAM.AdminTokenFile; f != "" && c.IAM.AdminToken == "" {
		if tb, err := os.ReadFile(f); err == nil {
			c.IAM.AdminToken = strings.TrimSpace(string(tb))
		} else if !os.IsNotExist(err) && !os.IsPermission(err) {
			return nil, fmt.Errorf("iam.admin_token_file: %w", err)
		}
		// Absent or unreadable: a component other than IAM, which never needs it.
	}
	c.Defaults()
	return &c, c.Validate()
}

// PlaceholderSecret reports whether a secret is still the example configs'
// placeholder ("change-me"), which the IAM refuses to bootstrap with.
func PlaceholderSecret(s string) bool {
	return strings.Contains(strings.ToLower(s), "change-me")
}

func (c *Cluster) Defaults() {
	if c.IAM.AdminID == "" {
		c.IAM.AdminID = "admin"
	}
	w := &c.Watcher
	def(&w.ProbeInterval, 1)
	def(&w.ProbeTimeout, 0.5)
	def(&w.ReconcileInterval, 30)
	def(&w.ReconcileMinAge, 60)
	def(&w.LostEdgeGrace, 120)
	def(&w.UnboundMaxAge, 600)
	def(&w.LockTTL, 10)
	if w.UnhealthyAfter == 0 {
		w.UnhealthyAfter = 3
	}
	for i := range c.APIServers {
		def(&c.APIServers[i].SnapshotRefresh, 1)
	}
	p := &c.Placement
	if p.K == 0 {
		p.K = 2
	}
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 3
	}
	def(&p.RejectPenalty, 2)
	def(&p.UsageFloor, 0.2)
	def(&p.OverlayGrace, 2)
	def(&p.BurstThreshold, 0.8)
	a := &c.Admission
	def(&a.DefaultTTLRunningStop, 3600)
	def(&a.DefaultTTLMax, 86400)
	def(&a.MaxTTLMax, 7*86400)
	def(&a.RequestRate, 10000)
	def(&a.RequestBurst, 2*a.RequestRate)
	def(&a.CreateRate, 2000)
	def(&a.CreateBurst, 32768)
	def(&a.AuthFailRate, 5)
	if a.MaxInflightCreates == 0 {
		a.MaxInflightCreates = 2048
	}
	f := &c.Fleet
	def(&f.LockTTL, 10)
	def(&f.Heartbeat, 10)
	if f.MaxDownloads == 0 {
		f.MaxDownloads = 64
	}
	if f.KeepReleases == 0 {
		f.KeepReleases = 10
	}
	if f.EdgePort == 0 {
		f.EdgePort = 7201
	}
	ports := map[string]int{"iam": 9461, "watcher": 9462, "apiserver": 9463, "edge": 9464, "fleet": 9465, "e2b": 9467}
	for k, v := range f.ReadyPorts {
		ports[k] = v
	}
	f.ReadyPorts = ports
	for i := range f.Replicas {
		if f.Replicas[i].DataDir == "" {
			f.Replicas[i].DataDir = "/var/lib/opendsec/fleet"
		}
	}
	for i := range c.Edges {
		c.Edges[i].Defaults()
	}
	if c.EdgeTemplate != nil {
		c.EdgeTemplate.Defaults()
	}
}

func (e *Edge) Defaults() {
	if e.Zone == "" {
		e.Zone = "onprem"
	}
	def(&e.CPUOvercommit, 8)
	def(&e.MemOvercommit, 1)
	def(&e.StoppedRetention, 600)
	def(&e.DiskOvercommit, 1)
	if e.StateDir == "" {
		e.StateDir = "/var/lib/opendsec"
	}
	if len(e.Backends) == 0 {
		e.Backends = map[string]Backend{"sim": {MaxSandboxes: 3200}}
	}
	for name, b := range e.Backends {
		if b.Real() && b.DefaultDiskMB == 0 {
			b.DefaultDiskMB = 10240
			e.Backends[name] = b
		}
	}
}

func (c *Cluster) Validate() error {
	if c.ServiceToken == "" && c.TLS.Dir == "" {
		return fmt.Errorf("either tls.dir (production) or service_token (dev) is required")
	}
	if e := c.E2B; e != nil {
		if len(e.Gateways) > 0 && e.Project == "" {
			return fmt.Errorf("e2b.project is required")
		}
		for i, g := range e.Gateways {
			if g.Addr == "" || (g.TLSCert == "") != (g.TLSKey == "") {
				return fmt.Errorf("e2b.gateways[%d]: addr required; tls_cert and tls_key go together", i)
			}
		}
		for id, t := range e.Templates {
			if t.Image == "" {
				return fmt.Errorf("e2b.templates.%s: image required", id)
			}
		}
	}
	if len(c.IAM.Replicas) > 0 {
		if c.IAM.AdminToken == "" && c.IAM.AdminTokenFile == "" {
			return fmt.Errorf("replicated IAM needs iam.admin_token or iam.admin_token_file")
		}
		ids := map[string]bool{}
		for _, r := range c.IAM.Replicas {
			if r.ID == "" || strings.ContainsAny(r.ID, "/. ") || ids[r.ID] {
				return fmt.Errorf("iam replica ids must be unique, non-empty, without '/', '.' or spaces")
			}
			ids[r.ID] = true
			if r.Addr == "" || r.RaftAddr == "" || r.DataDir == "" {
				return fmt.Errorf("iam replica %s needs addr, raft_addr and data_dir", r.ID)
			}
		}
	}
	fleetIDs := map[string]bool{}
	for _, r := range c.Fleet.Replicas {
		if r.ID == "" || strings.ContainsAny(r.ID, "/. ") || fleetIDs[r.ID] || r.Addr == "" {
			return fmt.Errorf("fleet replicas need unique ids without '/', '.' or spaces, and an addr")
		}
		fleetIDs[r.ID] = true
	}
	for _, g := range c.Fleet.Gates {
		if g.Query == "" || c.Fleet.PrometheusURL == "" {
			return fmt.Errorf("fleet gate %q needs a query and fleet.prometheus_url", g.Name)
		}
	}
	if t := c.EdgeTemplate; t != nil && t.Zone != "onprem" && t.Zone != "cloud" {
		return fmt.Errorf("edge_template: zone %q must be \"onprem\" or \"cloud\" (placement only knows these)", t.Zone)
	}
	seen := map[string]bool{}
	for _, e := range c.Edges {
		if !ids.ValidEdgeID(e.ID) {
			return fmt.Errorf("edge id %q must match [a-z0-9-]{1,32}", e.ID)
		}
		if seen[e.ID] {
			return fmt.Errorf("duplicate edge id %q", e.ID)
		}
		seen[e.ID] = true
		if e.Zone != "onprem" && e.Zone != "cloud" {
			return fmt.Errorf("edge %s: zone %q must be \"onprem\" or \"cloud\" (placement only knows these)", e.ID, e.Zone)
		}
		for name, b := range e.Backends {
			if b.ColdAgeS < 0 || b.ZramPct < 0 || b.ZramPct > 400 {
				return fmt.Errorf("edge %s backend %s: cold_age_s must be >= 0 and zram_pct in [0, 400]", e.ID, name)
			}
		}
	}
	return nil
}

// Edge returns the config of the edge with the given id: its entry in
// Edges, or a copy of EdgeTemplate for unlisted (dynamic) edges.
func (c *Cluster) Edge(id string) (*Edge, error) {
	for i := range c.Edges {
		if c.Edges[i].ID == id {
			return &c.Edges[i], nil
		}
	}
	if c.EdgeTemplate == nil {
		return nil, fmt.Errorf("edge %q not in config (and no edge_template)", id)
	}
	if !ids.ValidEdgeID(id) {
		return nil, fmt.Errorf("edge id %q must match [a-z0-9-]{1,32}", id)
	}
	e := *c.EdgeTemplate
	e.ID = id
	e.Backends = map[string]Backend{}
	for k, v := range c.EdgeTemplate.Backends {
		e.Backends[k] = v
	}
	e.Defaults()
	return &e, nil
}

// Seconds converts a float-seconds config value to a Duration.
func Seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

func def(v *float64, d float64) {
	if *v == 0 {
		*v = d
	}
}
