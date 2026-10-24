# How the components work

This document goes through how each OpenDsec component is built: what it does, where its code is, how it works inside, where its state lives, and what happens when it fails. Deployment is in the README's "Deploy a cluster" and the [operations manual](OPERATIONS.md); the reasons for each design decision and the measurements are in [SPEC.md](../SPEC.md) (Chinese; "§x" below refers to its sections).

## 0. Overview

```
callers (Python SDK / opendsecctl)
   | gRPC + TLS, bearer token
   v
apiserver xN (stateless, placement built in) ---> IAM x3 (Raft: identities, quotas, key-value area)
   |        ^ snapshot every second                ^ reconciliation
   |        watcher xN (probes edges, aggregates scheduling state)
   | mTLS
   v
edge (one per compute node, root) ---> backends: container / fncall / microvm / fullvm
   | unix socket or vsock
   v
aether (PID 1 in the sandbox) ---> chronus (one per shell session)

fleet x3 + nodeagent (every machine): releases, config, staged upgrades
shared image store (NFS / CephFS / JuiceFS): layers, manifests, snapshots, microVM image disks
```

Source layout:

| Directory | Contents |
|---|---|
| `cmd/opendsec-*` | Each component's main: flag parsing and startup only; the logic is in `internal/` |
| `internal/cluster` | Assembles components from the config and starts their gRPC services; `opendsecctl cluster up` uses it too |
| `internal/config` | The cluster config (one JSON file): structure, defaults, validation |
| `proto/opendsec/v1` | Every gRPC interface: `opendsec.proto` (public API), `iam.proto`, `cluster.proto` (watcher and edge), `runtime.proto` (aether), `fleet.proto` |
| `gen/go`, `sdk/python/opendsec/_pb` | Code generated from the protos |

### The path of one creation

Taking `client.run_sandbox(...)`:

1. The **SDK** calls `CreateSandbox` with its token and project. With several apiserver addresses it round-robins, and on `unavailable` retries on another.
2. The **apiserver** (`place` in `internal/apiserver/apiserver.go`):
   1. rate-limits per principal and checks the number of creations in flight;
   2. fills in default TTLs, and checks that the image exists and the caller has `layer.use`;
   3. makes a lease id; the sandbox id is `<edge>.<lease>`;
   4. **places first**: the built-in placement picks an edge;
   5. **then admits**: one IAM `Admit` call authenticates, authorizes `sandbox.create` and reserves quota, binding the reservation to the chosen edge.
3. **IAM** commits the reservation as one command through Raft: the project's and all its ancestors' usage grow by the sandbox's resources, and if any level would go over, nothing changes.
4. The **edge** receives `CreateSandbox` and makes the final admission decision: capacity, and memory, disk and CPU pressure. If they do not allow it, it returns `no_capacity`. Otherwise it:
   1. records the sandbox on disk;
   2. allocates its network;
   3. has the backend create it;
   4. sets it RUNNING and records that on disk.
5. When an edge returns `no_capacity` or `unavailable`, the apiserver gives that edge a short penalty and tries another, up to `max_attempts` times (default 3). In IAM the same lease is simply rebound to the new edge. If every attempt fails, the lease is released.
6. Later calls for this sandbox are forwarded straight to the edge named in its id; no table lookup is needed.

## 1. apiserver

**Role**: the cluster's only entry point: authentication, authorization, admission, placement, and forwarding to edges. Code in `internal/apiserver`.

- **Stateless**: a sandbox id encodes its edge, so any apiserver can serve any request, and a restart loses nothing. The one exception is sandboxes that moved (§26.2): their new location is recovered from the watcher snapshot (edges report `moved_in`) and from the original edge's answer (`move.go`).
- **Authentication cache**:
  - token-to-principal results and authorization results are each cached for 30 s, never past the token's own expiry;
  - in the background, IAM's security epoch is checked every second. Revoking a token or a permission changes the epoch, which clears the caches, so a revocation takes effect on every apiserver within about 1 s (§14.3).
- **Scheduling state**: every `snapshot_refresh`, the cluster snapshot is fetched from the watchers for the built-in placement. If none can be fetched, the last one is kept.
- **Readiness**: with no IAM answer or watcher snapshot for 15 s, `/readyz` fails, and the load balancer takes the apiserver out.
- **Admission** (`admission.go`, §18):
  - default TTLs and the lifetime cap;
  - per-principal token buckets; batch creations queue on the server and never partly fail;
  - a limit on creations in flight (default 2048);
  - authentication is paused for a source address with too many failures.
- **Batch creation** `CreateSandboxes`: up to 32768 per call, results streamed one by one.
- **Fork** (`fork.go`):
  - one snapshot of the source sandbox, then count copies, up to 256 per call;
  - each copy is an ordinary creation (authorized and charged on its own), placed on the source's node first;
  - copies placed on other nodes fetch the snapshot files straight from the source edge.
- **Image API** (`images.go`):
  - registers, composes and deletes image manifests, writing to the shared store directly;
  - writes need `layer.publish`, use needs `layer.use`, so the account that builds environments and the account that runs jobs can be separate.
- **Runtime calls** (`runtime.go`): exec, files and HTTP are authorized for `sandbox.operate` and forwarded to the edge, which passes them to aether in the sandbox. A paused sandbox is resumed by the edge; if its node has no room, it is moved to another node and resumed there.
- **Audit** (`audit.go`): one JSON line per public call, rotated by size.
- **Extension points** (`ext`, §34):
  - an extension's authenticator runs before IAM: a token it recognizes (an SSO token, say) maps straight to a principal, and IAM never sees that token; authorization and quotas stay with IAM, and Admit carries the principal instead.
  - audit extensions receive each line after it is written to the local file.
  - The open-source build links no extensions, so none of this applies there.
- **fleet proxy** (`fleet.go`): serves `FleetAdmin` on the public port; after authorizing `fleet.view` or `fleet.operate`, it forwards the call to fleet with the caller's identity.

## 2. placement (inside the apiserver)

**Role**: picks an edge for each new sandbox. Code in `internal/placement/placement.go` (§3.4).

- **Two steps**:
  1. **filter**: healthy, not draining, offers the backend, matching hardware (GPUs), enough allocatable capacity, has the image; for creations from snapshots, the same runtime versions;
  2. **power-of-k**: draw k candidates uniformly at random (default 2) and take the least loaded.
- **Load** is the highest of three:
  - allocated resources as a share of capacity;
  - actual CPU use (smoothed over 10 s by the edge);
  - actual memory use.

  Actual use below `usage_floor` (default 0.2) does not count, so different idle baselines of hosts do not skew placement.
- **Concurrency without coordination**: each apiserver overlays the sandboxes it just placed, not yet in the snapshot, onto the snapshot (in-flight overlay), so several apiservers placing at once do not all pick the same node.
- **Penalties**: a node that rejected a creation becomes the last choice for a short while. Not excluded outright: when every node is restarting, trying one beats failing.
- **Locality**:
  - fork copies prefer the source's node;
  - creations from snapshots prefer nodes that already cache the snapshot.
- **Cloud burst**: `zone` is `onprem` or `cloud`. When local utilization exceeds `burst_threshold`, some cloud-eligible images go to the cloud zone with a probability.
- **Errors**: when no node fits, it tells "the image does not exist" (`not_found`) from "every node with the image is full" (`no_capacity`), with the reasons nodes were skipped (memory, disk, CPU pressure, runtime version mismatch).

## 3. IAM

**Role**: identities, projects, permissions and quotas; also distributed locks, and a key-value area where other components keep small durable state. Code in `internal/iam` (§3.2, §15).

- **Data model**:
  - **projects**: nested, e.g. `root/team-a/rl`; unset quota keys take the parent's;
  - **principals**: belong to a project and may hold several tokens;
  - **tokens**: `dsk.<id>.<secret>`; only the secret's hash is stored; they can expire and be revoked;
  - **permissions**: granted on projects and valid for their subprojects; delegation is bounded, nobody grants what they do not hold.
- **Deterministic commands** (`commands.go`):
  - every state change is a Command. Nondeterministic values (time, token ids, secret hashes) are made by the proposer and written into the command, so every replica ends up with the same result.
  - Standalone: commands apply directly and the state is written to a JSON file.
  - Replicated (`raft.go`, hashicorp/raft + BoltDB): commands are replicated through Raft. Followers forward requests to the leader as they are (`service.go`), so clients may connect to any replica.
- **Quota leases**:
  - each sandbox has a lease recording its resources, counted in its project's and every ancestor's usage;
  - `Admit` authenticates, authorizes and reserves in one go; reserving the same lease again is idempotent (it only rebinds the edge);
  - leases are bound to edges, and when an edge is judged lost, its leases are released.
- **Reconciliation** (`reconcile.go`, §15.2):
  - watchers regularly report the leases actually alive on each edge;
  - IAM commits only the differences: leases on an edge that IAM did not know are adopted, leases IAM holds that the edge does not are released;
  - leases younger than `reconcile_min_age` are never released;
  - normally releases come from edges: when sandboxes end, the edge queues their leases and releases them with `ReleaseLeases` after 1000 of them or 50 ms, one Raft commit per batch, so stopping a million sandboxes at once does not clog IAM (§31);
  - leases no edge claimed for a long time are cleared by `SweepUnbound`.
- **Locks**: named locks with a TTL; watchers and fleet elect leaders with them.
- **Key-value area** (`kv.go`, §28.3):
  - accepts fixed prefixes only (fleet's nodes, releases and rollout records, for instance);
  - each write gets a globally increasing revision, with compare-and-set;
  - IAM does not interpret the contents. It is replicated and backed up with the rest of the state.
- **Backup and restore** (`ops.go`): gzipped JSON with principals, projects, token hashes, the security epoch and the key-value area. No leases (reconciliation rebuilds them after a restore).
- **Membership changes**: `opendsecctl iam member add/remove`; a new replica started with `-join` waits to be added (§27.2).
- **Bootstrap**: on first start, the root project and the administrator are created with the admin token from the config. A token still holding the example's placeholder (`change-me`) is refused.

## 4. watcher

**Role**: probes edge health, aggregates scheduling state, drives quota reconciliation. Code in `internal/watcher/watcher.go` (§3.5).

- **No durable state**: after a restart, its view is rebuilt from the config's edge list, the edges' periodic registrations, polling the edges, and the other watchers' snapshots.
- **Probing**:
  - every `probe_interval` (default 1 s), each edge's `Status` is called concurrently;
  - 3 consecutive failures make an edge unhealthy;
  - an edge answering with an unexpected id counts as a failure.
- **Snapshot**: after each round, a versioned snapshot with each edge's capacity, allocations, actual use, pressure, cached snapshots and runtime versions, for the apiservers to fetch.
- **Several instances**: all probe and all serve snapshots. Only the one holding the IAM lock reconciles: it renews the lock every TTL/3 and considers itself leader until "request time + TTL − 2 s" by its own clock, so clock skew against IAM never lets two instances reconcile at once.
- **Reconciliation**: every `reconcile_interval` (default 30 s).
  - healthy edges: their live leases go to IAM for reconciliation;
  - edges unhealthy for longer than `lost_edge_grace` (default 120 s): reconciled as empty, releasing their quota. An edge that comes back with sandboxes has them adopted in the next round;
  - each edge is reconciled on its own, so one unreachable edge only skips itself.
- **Registration**: with mTLS, an edge can register only itself (its certificate identity must match).

## 5. edge (the node's control plane)

**Role**: the control plane on each node: final admission, the sandbox state machine, TTL expiry, liveness checks, releasing resources, reporting to the watchers, and forwarding runtime calls to aether. Code in `internal/edge`, running as root.

- **State machine**: CREATING → RUNNING ⇄ PAUSING/PAUSED/RESUMING → STOPPING → STOPPED, FAILED on failure. Each sandbox has an operation lock: one lifecycle operation at a time.
- **Final admission** (`create`): capacity accounted per sandbox (CPU, memory, disk, GPUs, per-backend counts), plus three pressure checks:
  - memory: MemAvailable below the reserve (default 10% of RAM, at least 128 MB);
  - disk: free space on the file system holding `state_dir`;
  - CPU: PSI, optional.

  The edge has the last word: the snapshot placement used may be stale.
- **Persistence and re-adoption** (`store.go`, `recover.go`, §13):
  - one record file per live sandbox, written as temp file → fsync → rename;
  - the record is written before the backend is called, so an edge that crashes during a creation still knows the sandbox after restarting;
  - when a creation finishes, the edge asks IAM where the lease is bound (§36): if the caller gave up and created it on another edge, or the lease was released, the sandbox is deleted right there, leaving no orphan; if IAM cannot be asked, it is kept;
  - at startup, before serving: RUNNING and PAUSED sandboxes are handed to their backends to adopt again, the rest are marked failed and released; the backends then clean up leftovers on the node that match no record (cgroups, processes, disks, networks);
  - with `keep_sandboxes_on_exit` and systemd's `KillMode=process`, edge restarts and upgrades do not touch running sandboxes.
- **Background loop** (`Run`):
  - expires sandboxes by TTL: the idle timeout `ttl_running_stop` and the lifetime `ttl_max`;
  - probes backend liveness;
  - cleans up ended records;
  - when memory is short, inflates balloons of sandboxes that have them (`balloon.go`, §24): best-effort sandboxes first, then those idle longest, a quarter per round, at most half; deflates once the node has room again.
- **Runtime calls** (`runtime.go`):
  - each call resumes a paused sandbox first (transparently to the caller), resets the idle TTL, and keeps idle expiry from interrupting while the call runs;
  - then it gets aether's gRPC connection from the backend and forwards the call.
- **Reporting**: `Status` returns capacity, allocations, actual use and pressure (`host/usage.go` reads `/proc/stat`, `/proc/pressure/cpu` and `/proc/meminfo`; CPU smoothed over 10 s), plus live leases for reconciliation. Edges also register with the watchers periodically (`RegisterLoop`).
- **Between nodes** (`move.go`, `peerfile`, §26):
  - snapshot files stay on the node that took them; other nodes fetch them from there when needed;
  - only non-zero data is sent: memory files and disks are mostly holes, and the receiver keeps them as holes;
  - a paused sandbox can move to another node: the new node resumes it under the same id, and the move completes only once the old node lets go, so it never runs on both.
- **Metrics**: `internal/edge/metrics.go`, read live at scrape time.

### Backend interface

`internal/edge/backend/backend.go` defines the `Backend` interface every backend implements: `Create`, `Stop`, `Pause`, `Resume`, `Probe`. Optional capabilities, implemented as needed:

| Interface | Purpose |
|---|---|
| `Runtime` | Returns the gRPC connection to aether in the sandbox |
| `LossReporter` | Tells the edge when it notices a sandbox died (its aether connection broke) |
| `Snapshotter` / `Packer` | fork, snapshots, `pack_diff` |
| `Networked` | Needs sandbox networking |
| `ImageLister` | Can only run fixed local images (development) |
| `Versioned` | Reports runtime versions, e.g. firecracker 1.17.0 |

The `sim` backend only simulates lifecycles, for scheduling tests and `cluster up -sim-edges`.

## 6. Container backends (container, fncall)

Code in `internal/edge/backend/container` (§11.2, §21).

- **Root file system**:
  - lower layers: node-local copies of the image layers (`layercache.go`, §33.1): each layer is copied whole from the store to `<state_dir>/<edge>/layers/<layer id>` the first time it is used, shared by every container backend on the node. Running containers therefore no longer read the store and are unaffected when it (a NAS) is unreachable.
    - layers are immutable, so copies are keyed by layer id;
    - copies unused by any sandbox for 6 hours are removed by the edge;
    - `layer_cache: false` stacks layers straight from the store again (loaded on demand, file by file);
  - upper layer: a sparse ext4 image file per sandbox (`disk.go`) on a loop device, `disk_mb` in size.

  This disk is mounted in the sandbox's own mount namespace, not on the host. Otherwise each sandbox adds an entry to the host mount table, which every new namespace copies, and with thousands of sandboxes each start slows by about 0.1 s.
- **Startup**: "re-exec yourself", as runc does. The edge starts its own binary again with a special argv[0]; that process is the sandbox's setup process (`init.go`), which in new mount/pid/uts/ipc/net/cgroup namespaces:
  1. mounts the writable disk and overlay, then proc, sys read-only, and the sandbox's own cgroup (so Go or a JVM inside can size themselves to the limits);
  2. pivot_roots into the sandbox's root and sets the hostname;
  3. makes kernel interfaces read-only or masks them per `sandboxfs` (defaults as in Docker), plus the paths the caller asked for;
  4. lowers the agent's OOM score, so that when memory runs out the sandbox's processes are killed, not the agent;
  5. finally installs the seccomp filter, drops surplus capabilities (Docker's default set minus CAP_MKNOD), and execs aether as PID 1.
- **Resources**: cgroup v2, in `linuxrt/cgroup.go`.
  - limits on CPU, memory and pids, optionally disk I/O;
  - BE sandboxes get `cpu.idle`;
  - each sandbox gets its own core scheduling cookie (`linuxrt/coresched.go`, §29.1), so two sandboxes never share a physical core's hardware threads at once, which prevents interference and blocks SMT side channels.
- **Pause**: the cgroup freezer. With `pause_reclaim`, memory is also pushed to swap with `process_madvise(MADV_PAGEOUT)` and read back ahead of use on resume (`linuxrt/reclaim.go`, §22.1).
- **GPUs** (`linuxrt/gpu.go`):
  - exclusive: a whole device;
  - shared: a slot on a device without an exclusive user.
- **Snapshots and `pack_diff`**: file system only. A snapshot freezes the writable layer into a new image layer. `pack_diff` removes /tmp, caches and shell history. Container forks carry no memory.
- **fncall**: the same implementation plus a warm pool (`pool.go`, §22.3). For the images listed in the config, sandboxes are started ahead of time; a request takes one and gets its limits, network and id set. About 2 ms through the API.

## 7. microVM backend (Firecracker)

Code in `internal/edge/backend/microvm` (§19). This is the main backend.

- **One Firecracker process per sandbox**, started by jailer:
  - its own chroot;
  - a uid per sandbox;
  - new network/IPC/UTS namespaces, inside the sandbox's own cgroup.
- **Disks**: all VMs share one guest kernel; each VM gets four disks:
  1. **agent disk**: read-only, with aether and chronus (`BuildAgentDisk`);
  2. **image disk**: read-only, the image's layers flattened into one disk (`ImageCache` in `disks.go`). Each set of layers is built once, shared by every VM of the image on the node; virtio-pmem + DAX lets them share the host's page cache. With `erofs_images`, the image disk is EROFS and built only once, in the store: the first node that needs it builds it under the exclusive `vmdisks/<key>.lock`, and other nodes just copy it (`images/vmdisk.go`, §29.4);
  3. **writable disk**: the sandbox's own, sparse ext4;
  4. **config disk**: tiny, unmounted once the guest has read it, so a VM restored from a snapshot can get a new one.
- **In the guest**: aether runs as PID 1 with `--vm-init`, assembles the root file system, then serves the same Runtime API as in containers, over vsock (`internal/agent/aether/vminit.go`, `vsock.go`). zram, DAMON cold-page reclaim and free page reporting are turned on per config (`vmmem.go`).
- **Network**: Firecracker's "network for clones" layout: each VM's netns has a tap device of the same name and the same guest address, translated by netpol inside the netns, so copies restored from snapshots need no change to the guest's network config. While a VM is paused there is no VMM process; a minimal placeholder process keeps the netns alive (`linuxrt/netnsholder.go`).
- **Pause = snapshot and exit** (`Pause`):
  1. pause the vCPUs;
  2. the first time, a full snapshot; afterwards, dirty pages only (Diff), merged into the previous memory file (`diff.go`);
  3. end the Firecracker process, so the memory really goes back to the host;
  4. punch holes for zero pages in the memory file.

  Resume restores in a new process, in about 50 ms.
- **Creating from snapshots, fork** (`createRestored`): the snapshot's files are hard-linked into the jail. A snapshot on another file system or node is first fetched to a node-local copy (`snapcache.go`), which every copy on the node then links to, sharing the page cache. After the restore, aether receives `PostRestore` and gives the copy a new clock, random seed, hostname and machine-id (`aether/restore.go`).
- **Liveness**: the edge keeps a `Watch` stream open to aether; when it breaks, the sandbox counts as lost. After an edge restart, `Adopt` reconnects to running VMs.
- **Metrics**: each creation's phases (prepare, network, config disk, boot or restore) are timed.

## 8. Full VM backend (fullvm, QEMU)

Code in `internal/edge/backend/fullvm` (§23).

- One QEMU process per sandbox (q35 machine, KVM), with the same disk layout as microVMs on virtio-pci, and aether over vhost-vsock.
- Unlike microVMs: a full PCI bus, so GPUs can be passed through with VFIO (not yet tested on real devices); with `full_init`, the image's own `/sbin/init` (systemd) runs as PID 1.
- Pause only stops the vCPUs and keeps the memory; no memory snapshots and no fork. Controlled through QMP (`qmp.go`).

## 9. Network policy (netpol)

Code in `internal/edge/netpol` (§20, §29.2). The paper uses eBPF; this uses nftables.

- **Topology**: each sandbox has its own network namespace, connected to the host by a veth pair, with a /30 from the edge's subnet (default 10.88.0.0/16). microVMs add a tap inside the netns.
- **Default deny**: one nftables table per edge (`nft.go`).
  - New connections to a sandbox are always dropped, whether from other sandboxes, the host or outside; replies pass.
  - Every packet a sandbox sends enters its own chain, matched by veth and source address, so forged source addresses match nothing and are dropped. Established connections go through the chain too, so taking a rule back cuts its connections at once.
  - The chain: accept allowed networks; drop private, link-local and multicast addresses; accept addresses the DNS proxy resolved; drop the rest.
- **Allowing by domain**: each edge runs a DNS proxy (`dns.go`).
  - Only allowed domains (subdomains included) are forwarded upstream, and the IPv4 addresses in the answer join the sandbox's allowed set before the sandbox gets the answer;
  - other names get NXDOMAIN; AAAA queries get empty answers (sandboxes have IPv4 only);
  - the proxy tells sandboxes apart by the query's source address.
- **Rules** (`rules.go`):
  - a domain, an IPv4 network, a rule set named in the cluster config (such as `pypi`), or `*` (every public address);
  - each rule can be limited to a protocol and port range; each port combination gets an nftables set;
  - rules can change while the sandbox runs (`UpdateNetwork`).
- **Performance**: per-sandbox rules go through netlink directly (`nl.go`). The `nft` and `ip` commands reread the whole ruleset or copy the mount table every time, 100–300 ms each with thousands of sandboxes; only the edge's base rules are set with `nft`, once, at startup.

## 10. Image store (images)

Code in `internal/images` (§17, §24, §29). The image store is a shared directory every edge and apiserver mounts:

```
<root>/layers/<id>/rootfs/...      layers, overlay format (whiteouts are 0:0 character devices)
<root>/layers/<id>/meta.json
<root>/images/<project>/<repo>/<tag>.json   manifests: layer list, env, workdir, user
<root>/snapshots/<id>/             snapshots (file system layer + a microVM's memory and state)
<root>/vmdisks/<key>.erofs         microVM EROFS image disks
<root>/inuse/<holder>              layers used by running sandboxes (for GC)
```

- **Layers are immutable**: written to a temporary directory, then renamed into place as a whole. Manifests likewise, temporary file plus rename.
- **Import** (`oci.go`): `opendsecctl image import` pulls straight from OCI registries (Docker Hub by default); layers may be gzip-compressed, zstd-compressed or uncompressed. Whiteouts are restored as 0:0 character devices, which needs root.
- **Private registries** (`auth.go`, §35): credentials from `-username` plus `-password-stdin`, or the config file docker login saved; token services (Basic auth exchanged for a token), identity tokens (OAuth2 refresh tokens) and plain Basic auth are supported. Redirects to another host or port (a CDN, object storage) carry no credentials.
- **Opaque directories** (`opaque.go`): overlay marks opaque directories with the xattr `trusted.overlay.opaque`, which NFS does not carry. So at import, opaque directories are expanded: for each name visible in lower layers but absent from this one, a whiteout is written.
- **Composition**: an image is a list of layers; `compose` concatenates several images' layers in order, copying no data.
- **Merging** (`merge.go`): when a container fork chain gets too long, several layers are squashed into one; the result is still overlay format and stacks the same as the originals.
- **GC** (`gc.go`): layers and snapshots still referenced by manifests, snapshot records or running sandboxes are kept; the rest past the grace period are removed, along with interrupted writes.
- **Self-check** (`storecheck.go`): `opendsecctl image store-check` tries each capability the store needs in a directory: root not mapped to another user, chown, exclusive create, rename, hard links, 0:0 devices, overlay stacking and so on.

## 11. Agents in the sandbox: aether and chronus

Code in `internal/agent`. Both are statically linked; each version lives in `/opt/opendsec/agents/<version>/` and is mounted read-only into sandboxes. Running sandboxes keep the version they were started with.

- **aether** (`aether/aether.go`): one per sandbox, usually PID 1.
  - The edge talks only to it: over a unix socket in containers, vsock in VMs.
  - It routes calls by session id to the chronus serving that session, starting it on first use; closing a session kills chronus's whole process tree (`proctree`).
  - File calls, directory listings and HTTP requests made from inside the sandbox also go to the session's chronus, so they run as the session's user, with relative paths resolved against the session's current directory.
  - The `Watch` stream tells the edge it is alive.
  - **The process API** (`procs/`, §37) is aether's own, outside sessions: each command is a separate process, addressed by pid or tag, with stdin, signals and an optional PTY. A broken stream does not end its process, which can be reattached. User switching and environment reuse chronus's `Environ`. The E2B gateway builds envd's process API on it.
- **chronus** (`chronus/`): one process per shell session, holding a long-lived shell, so `cd`, exported variables and functions carry over between commands.
  - Command output is written to record files: callers can disconnect and fetch it later by offset (`GetOutput`), or receive it as a stream (`ExecStream`).
  - Each command carries a request id: when the SDK retries, chronus finds the command already running instead of starting it twice.
  - It is a subreaper: processes commands put in the background stay in the session's process tree and are cleaned up when the session closes.
  - Output limits (`record.go`, §29.3): each stream records up to a set number of bytes, and the rest is read and dropped (`dropped_bytes` in the result); each session's records are bounded too, the records of the earliest finished commands going first.
  - Sessions can run as a given user (`user`), different sessions as different users (§29.3).

## 12. fleet and nodeagent (cluster management)

Code in `internal/fleet`, `internal/nodeagent`, `internal/release` (§28).

- **Releases** (`release.go`): a release is a directory with:
  - `bin/`: every component, plus firecracker and jailer;
  - `agents/`, `units/`, `vm/` (the guest kernel);
  - `deps.lock`: the pinned runtime dependencies;
  - `SHA256SUMS`: checksums of every other file.

  `opendsecctl fleet release pack` packages it. Once pushed to fleet, each replica keeps a local tgz.
- **fleet**: three replicas; the one holding the IAM lock `fleet-controller` leads, and the others forward requests to it.
  - All desired state lives in IAM's key-value area, replicated and backed up with IAM: the node list (roles, failure domain, target release, config generation), releases, rollouts.
  - Node heartbeats are soft state, in the leader's memory only.
- **Controller** (`controller.go`): the leader runs a `tick` periodically, sending actions to nodes that lag and advancing rollouts in progress:
  - one step per node, going pending → staging (download) → staged → applying (switch release, write config, restart in order) → verifying (wait for the node's `/readyz` and the watcher snapshot to be fine) → ok.
  - Control-plane nodes first, one at a time, the IAM leader's node last; then one edge as a canary, and after the bake time the edges in batches, with a cap per failure domain in each batch.
  - Each edge is drained before its upgrade and resumes scheduling after. Before each batch: machines already upgraded are still fine and every control-plane component is ready; PromQL gates (`gates`) are checked too when configured.
  - A failure while applying or verifying sends the machine back to its old release and pins it, and the whole rollout pauses until a person decides to continue, roll back or abort.
- **nodeagent** (`agent.go`): one per machine, as root.
  - Reports to fleet every 10 s (release, unit states, actions in progress) and picks up actions from the answer.
  - Accepts five actions only: `stage`, `apply`, `restart`, `start`, `stop`. It changes only `/opt/opendsec`, `/etc/opendsec` (allow-listed files) and OpenDsec's own systemd units, and decides nothing by itself.
  - With all of fleet down, it changes nothing, and components and sandboxes keep running.
  - It runs from a separate copy in `/opt/opendsec/agent/` that does not switch with releases; a new release's nodeagent replaces it only after passing a `-check` self-test.
- **opendsecops** (`deploy/prod/opendsecops`): a bash tool on the ops machine for the first install, certificates, adding machines and emergencies, reaching nodes over ssh (nodes whose inventory address is `local` run on this machine).

## 13. Security and RPC infrastructure

Code in `internal/pki`, `internal/rpcutil` (§14).

- **mTLS between components**:
  - one certificate per component instance, with its identity in the URI SAN `opendsec://<role>/<id>`;
  - each gRPC service has an ACL of which roles may call which methods (`security.go`): only apiservers can call IAM's `Admit`, for instance, and edges can register only themselves.
  - Development mode can use a shared service token instead, without per-caller authorization.
- **Public port**: apiservers serve TLS, and callers send bearer tokens. Apiserver certificates carry the fixed name `api.opendsec.internal`, which the SDK checks when connecting to several apiservers by address.
- **Error reasons**: every error carries a stable string in `ErrorInfo.reason`, such as `no_capacity`, `quota_exceeded`, `not_found`, `unavailable`. The SDK and retry logic go by it, never by parsing messages.
- **Connections**:
  - servers ping idle connections every 20 s, so load balancers do not cut quiet streams on their idle timeout;
  - internal clients ping every 10 s, detecting a silently lost connection within about 15 s; reconnect backoff is capped at 2 s, so an edge is reachable again soon after a restart;
  - connections are pooled per address;
  - messages may be up to 80 MB each way.
- **CA rotation**: three steps, without downtime (`opendsecops rotate-ca`; see the operations manual).

## 14. Clients

- **Python SDK** (`sdk/python/opendsec/client.py`): an async API on grpc.aio.
  - `OPENDSEC_ADDR` can list several apiservers; the SDK round-robins over them and avoids broken ones.
  - On `unavailable`, it retries with backoff within `retry_timeout`.
  - `run_shell` carries a request id, so retries never run a command twice; `stream_shell` resumes from the offsets already received after a disconnect, losing and repeating nothing.
  - Callers choose the backend explicitly; the SDK does not abstract over backends.
- **Go client** (`pkg/client`): used by `opendsecctl` and the end-to-end tests.
- **opendsecctl** (`cmd/opendsecctl`):
  - the public API on the command line: sandboxes, exec, cp, images, IAM, fleet;
  - local tools: `cluster up` (an in-process cluster), `bench`, `pki`, `image store-check`, `fleet release pack`.

## 15. Metrics

Code in `internal/metrics` (§26.3). Every binary serves, with `-metrics :<port>`:

- `/metrics`: Prometheus format;
- `/healthz`: the process is alive;
- `/readyz`: whether it can serve, with the reason when not.

Main metrics:

- calls and latency per RPC (by method and error reason);
- apiserver creation latency and failure reasons;
- placement retries;
- per-backend sandbox counts on each edge, capacity and use, creation phase latencies;
- fleet and nodeagent state;
- `opendsec_build_info`: the running version.

Every metric and the alert rules: [Monitoring and alerts](MONITORING.md); the rules themselves are in `deploy/monitoring/alerts.yml`.

## 16. E2B gateway (opendsec-e2b)

Code in `internal/e2b`, `cmd/opendsec-e2b` (§37). Lets E2B's SDKs run on OpenDsec without code changes.

- **Two APIs on one port**:
  - E2B's management API (REST, `api.go`): create, get, list, delete, timeout, pause, connect;
  - network options and refresh (`network.go`): mapped to `network_rules` and `UpdateNetwork`; autoPause maps to `ttl_paused_s`;
  - fork and snapshots (`snapshots.go`): mapped to `ForkSandbox` and `CreateSnapshot`; a snapshot is an image in the gateway's project, and `snapshotID` is the image name;
  - E2B's in-sandbox envd API (`envd.go`): the process and file services over the Connect protocol, `/files` over HTTP.

  Requests with an `E2b-Sandbox-Id` header, or with host `<port>-<id>.<domain>`, are envd's.
- **Stateless**: every request calls the apiserver with the caller's own token (their E2B API key), so permissions, quotas and audit work as usual. The only cache is the environment variables passed at sandbox creation, kept for one minute.
- **Mapping**:
  - an E2B template is the image, backend and resources of `e2b.templates` in the cluster config;
  - metadata and envVars are stored as labels prefixed `e2b.`;
  - sandbox ids have `.` replaced by `-`;
  - timeouts use `SetSandboxTimeout`.
- **Deployment**: fleet role `e2b=<index>`, unit `opendsec-e2b@`, `/readyz` on port 9467. The unit runs as a `DynamicUser` and receives only the cluster config and the CA certificate, through `LoadCredential`.
