# Configuration reference

The whole cluster shares one JSON configuration file, deployed to `/etc/opendsec/opendsec.json` on every node. Every component reads it and uses the parts that concern it. This page describes each field and its default.

- A complete production example: `deploy/prod/cluster.example.json`; the config a single-node install generates is `/root/opendsec-ops/opendsec.json`.
- Durations are in **seconds** (fractions allowed).
- For most numeric fields, 0 or leaving the field out means the default; some fields take -1 to turn something off, as noted.
- Changing the config: on a cluster run by fleet, `opendsecctl fleet config put` and `fleet rollout create -config-gen <generation>` ([operations manual §6.2](OPERATIONS.md)); before fleet, `opendsecops push-config all` and `opendsecops restart`.
- Validating a config: `opendsecctl pki init -config <file> -out $(mktemp -d)` succeeds only if its format and constraints are right.

## Top level

```json
{
  "tls":            { ... },   // mTLS between components, TLS on the public API
  "service_token":  "...",     // development only: component auth without TLS
  "iam":            { ... },
  "watcher":        { ... },
  "apiserver":      [ ... ],
  "placement":      { ... },
  "admission":      { ... },
  "image_store":    { ... },
  "network":        { ... },
  "edges":          [ ... ],   // edges listed one by one
  "edge_template":  { ... },   // every other edge (new machines, Kubernetes)
  "fleet":          { ... },
  "e2b":            { ... },
  "extensions":     { ... }    // extensions in the build (none in the open-source build)
}
```

At least one of `tls.dir` and `service_token` must be set; production clusters use `tls`.

## tls

| Field | Meaning |
|---|---|
| `dir` | Certificate directory, e.g. `/etc/opendsec/pki`, holding `ca.crt` and each component's `<role>-<id>.crt` and `.key` (from `opendsecctl pki init` or `opendsecops certs`). Set, components use mTLS among themselves and the public API uses TLS |

## service_token

For development clusters: a shared secret components authenticate with when there is no TLS. Do not set it in production; a config delivered through fleet may not contain it.

## iam

| Field | Default | Meaning |
|---|---|---|
| `replicas` | — | Raft replicas, each `{"id", "addr", "raft_addr", "data_dir"}`. With replicas, `addr` and `state` are not used, and `admin_token` or `admin_token_file` is required |
| `replicas[].id` | — | Replica id: unique, without `/`, `.` or spaces |
| `replicas[].addr` | — | gRPC address, e.g. `10.0.0.1:7001` |
| `replicas[].raft_addr` | — | Raft address, e.g. `10.0.0.1:7011` |
| `replicas[].data_dir` | — | Raft log and snapshots, e.g. `/var/lib/opendsec/iam`, on a local SSD |
| `addr` | — | Address of a single unreplicated IAM |
| `state` | in memory | State file of a single IAM; unset, state lives in memory only and is lost on restart |
| `admin_id` | `admin` | The administrator created at bootstrap |
| `admin_token` | — | The administrator's token, `dsk.<admin_id>.<secret>`. Placeholders containing `change-me` are refused |
| `admin_token_file` | — | Read `admin_token` from this file instead, so the config holds no secret. Only IAM nodes need the file |
| `root_quota` | unlimited | The root project's quota, e.g. `{"sandboxes": 10000}` |
| `max_token_ttl_s` | 0 (none) | Longest lifetime of issued tokens. With a limit, tokens that never expire cannot be issued |

The admin token is used only when IAM first starts (bootstraps): it creates the `admin_id` principal with every permission on root.

## watcher

| Field | Default | Meaning |
|---|---|---|
| `replicas` | — | Several watchers, each `{"id", "addr"}`. All probe edges and serve snapshots; the one holding the IAM lock reconciles |
| `addr` | — | Address of a single watcher |
| `probe_interval` | 1 | How often each edge is probed |
| `probe_timeout` | 0.5 | Timeout of one probe |
| `unhealthy_after` | 3 | Consecutive failures before an edge counts as unhealthy |
| `reconcile_interval` | 30 | How often quotas are reconciled with IAM |
| `reconcile_min_age` | 60 | Leases younger than this are never released by reconciliation |
| `lost_edge_grace` | 120 | After an edge is unhealthy this long, its sandboxes' quota is released |
| `unbound_max_age` | 600 | Leases no edge claimed are released after this long |
| `lock_ttl` | 10 | Lease time of the reconciliation lock |

## apiserver

An array with one entry per apiserver instance; `opendsec-apiserver -index N` runs entry N.

| Field | Default | Meaning |
|---|---|---|
| `addr` | — | Listen address, e.g. `10.0.0.1:7100` |
| `audit_dir` | off | Audit log directory, e.g. `/var/log/opendsec/audit` |
| `audit_max_mb` | 256 | Rotate an audit log file at this size |
| `audit_keep` | 8 | Files kept, the current one included; the oldest go first |
| `audit_runtime` | false | Also audit runtime calls (commands, files, HTTP, processes, ports) and read-only queries (getting and listing sandboxes, cluster status, projects, usage, token lists). By default every other call is audited: creation, fork, stop, pause, resume, network changes, image publishing and deletion, projects, principals, grants, tokens, cluster operations. Commands are recorded as their length and SHA-256 only, never their text |
| `snapshot_refresh` | 1 | How often the cluster snapshot is refreshed from the watchers |

## placement

Scheduling parameters, applied by each apiserver.

| Field | Default | Meaning |
|---|---|---|
| `k` | 2 | power-of-k: pick k random candidate nodes and use the least loaded |
| `max_attempts` | 3 | Tries on other nodes after an edge rejects a creation |
| `reject_penalty` | 2 | A node that rejected is ranked down for this long |
| `overlay_grace` | 2 | A sandbox just placed counts toward its node's load for this long, until the snapshot shows it |
| `usage_floor` | 0.2 | A node's actual CPU and memory use below this share does not count as load (the host's own baseline); -1 counts it always |
| `burst_threshold` | 0.8 | Only for `burst_eligible_images` on the `container` backend: once local (`onprem`) nodes are used beyond this share, sandboxes go to `zone: cloud` nodes first, with a probability growing with the excess; below it, cloud nodes are only a fallback when no local node fits. ≤0 disables |
| `burst_eligible_images` | — | Images that may run on cloud nodes (their layers are mirrored there). Other images and backends never go to cloud nodes |

## admission

Creation policy each apiserver enforces. Timeouts: 0 means the built-in default, -1 means none. Rates are per principal and per apiserver instance (N apiservers admit up to N times the rate); -1 disables a limit.

| Field | Default | Meaning |
|---|---|---|
| `default_ttl_running_stop_s` | 3600 | Idle timeout when a request sets none |
| `default_ttl_max_s` | 86400 | Lifetime when a request sets none |
| `max_ttl_max_s` | 604800 (7 days) | Longest lifetime a request may ask for; more is `invalid` |
| `request_rate` | 10000 | Calls per second per principal (commands and file calls included) |
| `request_burst` | 2 × `request_rate` | Burst |
| `create_rate` | 2000 | Sandbox creations per second per principal |
| `create_burst` | 32768 | Burst: a whole batch may start at once |
| `auth_fail_rate` | 5 | Failed authentications per second per client address; beyond it, new tokens from that address are not checked for a while |
| `max_inflight_creates` | 2048 | Concurrent creations per apiserver |

A single creation over the rate gets `rate_limited`; batch creations are queued at the rate by the server and never partly fail on it. With the apiservers behind a load balancer, have it keep the client's source address, or every failed authentication counts against the load balancer's address.

## image_store

| Field | Meaning |
|---|---|
| `root` | Mount point of the shared image store, e.g. `/mnt/opendsec-images`, the same path on every apiserver and edge node. Without it, only edge-local images (`edges[].images`) exist |

File system requirements: [Images and snapshots §5](IMAGES.md).

## network

The cluster-wide network policy.

| Field | Meaning |
|---|---|
| `rule_sets` | Rule sets: name → destinations (domains, IPv4 addresses or networks, optionally with `:port[/protocol]`). E.g. `{"pypi": ["pypi.org", "files.pythonhosted.org"], "github": ["github.com", "codeload.github.com", "objects.githubusercontent.com"]}` |
| `default_rules` | Rules every sandbox has, under its own `network_rules`. `{"*": true}` lets every sandbox reach the internet by default; `{"pypi": true}` only PyPI |
| `upstream_dns` | Resolvers the edges' DNS proxies use; default: the host's `/etc/resolv.conf` |

Rule syntax and behaviour: [Network policy](NETWORK.md).

## edges and edge_template

`edges` lists edges one by one; `edge_template` applies to any edge not listed (`opendsec-edge -id <id>` uses the template when no entry has that id). New machines usually need no entry in `edges`.

| Field | Default | Meaning |
|---|---|---|
| `id` | — | Edge id, `[a-z0-9-]`, 1 to 32 characters; required in `edges` |
| `addr` | — | Listen address, e.g. `0.0.0.0:7201` |
| `advertise` | the bound address | Address registered with the watchers |
| `zone` | `onprem` | `onprem` or `cloud`, nothing else. `cloud` nodes are used only past `burst_threshold` |
| `capacity` | automatic | `{"cpu_cores", "memory_mb", "gpus", "disk_mb"}`. With a real backend: with neither `cpu_cores` nor `memory_mb` set, they are the host's CPU count and total memory (setting only one leaves the other unset); without `disk_mb`, it is the size of the file system holding `state_dir`. Overcommit applies on top |
| `cpu_overcommit` | 8 | CPU overcommit factor |
| `mem_overcommit` | 1 | Memory overcommit factor |
| `disk_overcommit` | 1 | Writable-disk overcommit factor |
| `mem_reserve_mb` | automatic | Reject creations while the host's MemAvailable is below this. 0 means automatic (10% of RAM, at least 128 MB); -1 disables |
| `disk_reserve_mb` | automatic | Reject creations while the state directory's file system has less free space. 0 means automatic (5% of the file system, at least 1024 MB); -1 disables |
| `cpu_pressure_limit` | 0 (off) | Reject creations while CPU pressure (`/proc/pressure/cpu` some avg10, percent) is above this. A burst of creations raises it too, so set it from the node's own measurements, e.g. 50 |
| `paused_mem_charge` | 1 | Share of their memory that paused sandboxes whose pause frees memory (microVMs; containers with `pause_reclaim`) still count for admission, 0 to 1 |
| `persist_state` | on with a real backend | Write sandbox records to disk and re-adopt the sandboxes after an edge restart |
| `keep_sandboxes_on_exit` | false | Leave sandboxes running when the edge exits. Needed for rolling upgrades |
| `stopped_retention` | 600 | How long records of ended sandboxes are kept |
| `state_dir` | `/var/lib/opendsec` | Sandbox disks, snapshots and records; should be local NVMe. XFS allows reflink copies |
| `agent_dir` | next to the edge binary | Directory of `opendsec-aether` and `opendsec-chronus` |
| `images` | — | Local static images: name → overlay lower directories (topmost first). Not needed with an image store |
| `network` | off | Sandbox networking; below |
| `gpu` | — | GPU devices; below |
| `backends` | `{"sim": {...}}` | The backends this edge offers; below |

### edges[].network

| Field | Default | Meaning |
|---|---|---|
| `enabled` | false | Enable sandbox networking. Off, sandboxes only have a loopback interface |
| `subnet` | `10.88.0.0/16` | Sandbox address pool, a /30 per sandbox |
| `dns_port` | 15353 | The edge's DNS proxy port on the host |

Edges sharing a machine need distinct `subnet`s and `dns_port`s.

### edges[].gpu

| Field | Meaning |
|---|---|
| `devices` | GPU device nodes, e.g. `["/dev/nvidia0", "/dev/nvidia1"]`. `capacity.gpus` defaults to their number |
| `extra` | Other devices every GPU sandbox needs, e.g. `/dev/nvidiactl`, `/dev/nvidia-uvm` |
| `mounts` | Host files or directories bound read-only into the sandbox (driver libraries, `nvidia-smi`) |
| `shared_slots` | Sandboxes per device with `gpu_mode: shared`, default 4 |
| `pci` | PCI devices passed through to `fullvm` sandboxes with VFIO, e.g. `["0000:3b:00.0"]` |

### edges[].backends

Backend name → backend config. The name is what creations put in `backend`, e.g.:

```json
"backends": {
  "microvm":   {"runtime": "firecracker", "max_sandboxes": 4000, "default_disk_mb": 2048,
                "kernel": "/opt/opendsec/current/vm/vmlinux-6.1.167-opendsec",
                "firecracker": "/opt/opendsec/current/bin/firecracker",
                "jailer": "/opt/opendsec/current/bin/jailer",
                "image_pmem": true, "erofs_images": true, "free_page_reporting": true, "cold_age_s": 120},
  "container": {"runtime": "linux", "max_sandboxes": 8000, "default_disk_mb": 1024},
  "fncall":    {"runtime": "linux", "max_sandboxes": 4000, "default_disk_mb": 1024,
                "warm_pool": {"root/py:3.12": 64}}
}
```

Common fields:

| Field | Default | Meaning |
|---|---|---|
| `runtime` | `sim` | `linux` (containers), `firecracker` (microVMs), `qemu` (full VMs), `sim` (simulated) |
| `max_sandboxes` | — | Most sandboxes of this backend running at once on the node |
| `default_disk_mb` | 10240 | Writable disk size when a request sets no `disk_mb` |
| `disk_io` | unlimited | Per-sandbox disk I/O limits: `{"read_mbps", "write_mbps", "read_iops", "write_iops"}`, 0 for unlimited |
| `core_sched` | on if the kernel supports it | A core scheduling cookie per sandbox: two sandboxes never run on the two hardware threads of one core at the same time, which closes SMT side channels and keeps best-effort load off a latency-sensitive sandbox's core. `true` requires kernel support; `false` turns it off |

`linux` runtime (container, fncall):

| Field | Default | Meaning |
|---|---|---|
| `pids_max` | 4096 | Process limit per sandbox |
| `pause_reclaim` | false | A pause pushes the container's memory to swap, read back ahead of use on resume. Needs host swap and `vm.swappiness` above 0 |
| `warm_pool` | — | Image → containers kept started ahead of requests (the fncall backend). A request without snapshot, user, working directory, path restrictions or GPUs, and with the default disk, takes one and is ready in milliseconds |
| `layer_cache` | true | Containers run on node-local copies of their image layers, copied on first use, so running containers are unaffected when the image store (NFS) is unreachable |

`firecracker` runtime (microvm):

| Field | Default | Meaning |
|---|---|---|
| `kernel` | required | Guest kernel (vmlinux) path |
| `firecracker`, `jailer` | the programs of that name on PATH | Paths of Firecracker and jailer |
| `uid_base` | 1000000000 | Each VM runs as its own uid from `[uid_base, uid_base+65536)` |
| `vm_overhead_mb` | 64 | Added to the guest memory for the VM's cgroup limit (the VMM itself, page tables, device buffers) |
| `erofs_images` | false | Images become EROFS disks built once in the image store and copied to each node, instead of flattened to ext4 on every node. Needs a guest kernel with EROFS and `mkfs.erofs` (erofs-utils) on the node |
| `image_pmem` | false | Attach the image as virtio-pmem with DAX: VMs of one image share the host page cache |
| `free_page_reporting` | false | Memory the guest frees goes back to the host (virtio-balloon) |
| `cold_age_s` | 0 (off) | Above 0, DAMON in the guest pages out memory idle this long to compressed zram |
| `zram_pct` | 100 | zram size, percent of the VM's memory (0 to 400) |
| `cold_boot_dirty_tracking` | true | Cold-booted VMs track dirty pages, so a pause writes only pages they touched. `false`: faster memory writes (host huge pages), but the first pause or snapshot writes all memory |

`image_pmem`, `free_page_reporting` and `cold_age_s` need OpenDsec's guest kernel (`deploy/guest-kernel`, published as a GitHub release).

`qemu` runtime (fullvm):

| Field | Default | Meaning |
|---|---|---|
| `qemu` | `qemu-system-x86_64` on PATH | QEMU path |
| `kernel` | — | Guest kernel |
| `full_init` | false | Hand PID 1 to the image's own `/sbin/init` (aether runs beside it) |

`sim` runtime: `create_latency_ms` (median creation time, lognormal), `latency_sigma`, `failure_rate`, for scheduling benchmarks.

## fleet

The cluster management service; optional.

| Field | Default | Meaning |
|---|---|---|
| `replicas` | — | Each `{"id", "addr", "data_dir"}`; `addr` e.g. `10.0.0.1:7300`, `data_dir` default `/var/lib/opendsec/fleet` |
| `heartbeat_s` | 10 | Node agent report interval |
| `lock_ttl` | 10 | Lease time of the leader lock |
| `max_downloads` | 64 | Concurrent release downloads served per replica |
| `keep_releases` | 10 | Releases kept besides those in use |
| `edge_port` | 7201 | Port edges listen on at the node's private address |
| `ready_ports` | iam 9461, watcher 9462, apiserver 9463, edge 9464, fleet 9465, e2b 9467 | Each role's `/readyz` port, which node agents check after restarting a unit |
| `prometheus_url` | — | Prometheus for rollout gates |
| `gates` | — | Rollout gates: `[{"name", "query", "max"}]`. While a batch bakes, each PromQL query must stay at or below `max`, or the rollout pauses |

```json
"fleet": {
  "replicas": [{"id": "0", "addr": "10.0.0.1:7300"}, {"id": "1", "addr": "10.0.0.2:7300"}, {"id": "2", "addr": "10.0.0.3:7300"}],
  "heartbeat_s": 10,
  "prometheus_url": "http://10.0.0.3:9090",
  "gates": [{"name": "create errors", "query": "sum(rate(opendsec_apiserver_create_seconds_count{reason!=\"ok\"}[5m]))", "max": 1}]
}
```

## e2b

The E2B-compatible gateway; optional.

| Field | Default | Meaning |
|---|---|---|
| `gateways` | — | Gateway instances: `[{"addr", "tls_cert", "tls_key"}]`. `addr` e.g. `10.0.0.1:7400`; set both `tls_cert` and `tls_key` for the gateway to serve HTTPS itself, or neither for plain HTTP behind a TLS-terminating load balancer |
| `project` | required with gateways | Sandboxes are created in this project. A request can name another with the `X-OpenDsec-Project` header |
| `domain` | — | The sandboxes' domain returned to SDKs, which then reach `<port>-<id>.<domain>` (needs wildcard DNS and a certificate pointing at the gateways). Unset, clients set `E2B_SANDBOX_URL` |
| `templates` | — | E2B template id → sandbox. SDKs default to `base`. A template id containing `/` is taken as an image name with `default_template`'s other settings |
| `default_template` | — | As above, the defaults |
| `max_timeout_s` | 0 (admission cap only) | Cap on a sandbox's timeout |

Template fields:

| Field | Default | Meaning |
|---|---|---|
| `image` | required | Image |
| `backend` | `microvm` | Backend |
| `cpu` | 2 | CPU cores |
| `memory_mb` | 512 | Memory. Must equal the snapshot's when the image is a memory snapshot |
| `disk_mb` | the backend's | Writable disk |
| `start_cmd` | — | Started with `bash -l -c` in every new sandbox (an E2B template's start command) |
| `ready_port` | — | Wait for this port to listen before handing the sandbox out |
| `ready_timeout_s` | 60 | Longest wait |

More in [Migrating from E2B](E2B.md).

## Command-line flags of the components

Usually passed by the systemd units (`deploy/systemd/`); you rarely set them yourself.

| Program | Flags |
|---|---|
| `opendsec-iam` | `-config`, `-replica <id>` (which replica to run, replicated mode), `-join` (a new replica: do not bootstrap; wait for `opendsecctl iam member add`), `-metrics`, `-log` |
| `opendsec-watcher` | `-config`, `-replica <id>`, `-metrics`, `-log` |
| `opendsec-apiserver` | `-config`, `-index <N>` (run entry N of `apiserver`), `-drain-delay` (on SIGTERM, fail `/readyz` and keep serving this long, default 6s), `-grace` (then give calls in flight this long, default 30s), `-metrics`, `-pprof`, `-log` |
| `opendsec-edge` | `-config`, `-id <id>[,<id>...]` (`all` for every configured edge; unlisted ids use `edge_template`), `-addr`, `-advertise`, `-metrics`, `-pprof`, `-log` |
| `opendsec-fleet` | `-config`, `-replica <id>`, `-metrics`, `-log` |
| `opendsec-e2b` | `-config`, `-index <N>`, `-ca` (default `tls.dir/ca.crt`), `-drain-delay` (default 5s), `-metrics`, `-log` |
| `opendsec-nodeagent` | `-config` (default `/etc/opendsec/opendsec.json`), `-name`, `-addr`, `-fleet`, `-root` (default `/opt/opendsec`), `-check`, `-metrics`, `-log` |

`-metrics <address>` serves `/metrics`, `/healthz` and `/readyz`. Default ports per role: [Monitoring and alerts](MONITORING.md).
