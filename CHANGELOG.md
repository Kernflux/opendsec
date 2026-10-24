# Changelog

What changed in each release, for operators and callers. The compatibility
rules behind "Breaking" are in [docs/VERSIONING.md](docs/VERSIONING.md).

## 0.11.0 (unreleased)

Upgrade from 0.10 with a rolling upgrade (`opendsecops upgrade`); running
sandboxes are kept. To move the cluster to the fleet service afterwards, see
docs/OPERATIONS.md §6.4.

### Licensing
- The server and tools are now under the **GNU AGPL-3.0**, with a
  commercial license available; the client parts stay **Apache-2.0**: the
  Python SDK, the Go client (`pkg/`), and the API definitions and generated
  code (`proto/`, `gen/`). Programs that only use OpenDsec through them are
  not bound by the AGPL. See NOTICE.
- Contributions need a signed Contributor License Agreement (CLA.md).

### Security
- Go 1.27.2 → 1.27.3 (`go.mod`), for GO-2026-6809: crypto/x509 distrusts
  compromised intermediate certificates. OpenDsec's own TLS uses its
  cluster CA, so the exposure was small; build releases with 1.27.3.
- `golang.org/x/net` 0.58.0 → 0.60.0. This fixes five HTTP/2 vulnerabilities
  that every gRPC server could reach: GO-2026-6603, -6610, -6611, -6612 and
  -6617 (memory exhaustion, CPU exhaustion, a server crash, a flow-control
  error, malformed headers accepted). Upgrade clusters running earlier 0.11
  builds too.

### Breaking
- **`opendsecctl exec <id> <command> ...`**: everything after the command
  name now goes to the command, each argument as given (quoted for the
  sandbox's shell, as `docker exec` takes them): `exec <id> python3 -c
  'print(6*7)'` works. A single argument is still a shell command line
  (`exec <id> 'cd /tmp && ls'`). Scripts that quoted arguments twice for
  the old joining must drop the inner quotes. Flags for opendsecctl itself
  must come before the command name, as in `exec -session s <id> <command>`.
- **Stricter config validation**: `edge_template.zone` must be `onprem` or
  `cloud`. Any other value used to pass, and then placement never used those
  edges.
- **Placeholder admin token**: IAM refuses to start with the example
  configs' placeholder (`change-me`).
- **Go module path**: now `github.com/kernflux/opendsec`. This matters only
  to code importing `pkg/client`.

### Changed behaviour
- **E2B gateway: internet by default, as on E2B** (SPEC §37.11). Sandboxes
  made through the gateway get the rule `"*": true` unless the caller turns
  it off (`allow_internet_access=False`, `deny_out` of all traffic),
  whatever the cluster's `network.default_rules`. Before, they followed the
  cluster default, so on a cluster that denies by default E2B code lost the
  internet it expects.
- **`deploy/quickstart.sh` sets up an E2B gateway** (port 7400, project
  `root/demo`, template `base`) and writes `E2B_API_URL`, `E2B_SANDBOX_URL`
  and `E2B_API_KEY` into `demo.env`. The demo caller may also publish images
  in `root/demo` (`layer.publish`: `pack_diff`, snapshots).
- **NFS 4.2 for the image store** (README, docs/OPERATIONS.md): 4.1 cannot
  find the holes of sparse files, so a memory snapshot moving to another
  node was read in full (141 s against 62 s in our test).
  `opendsecctl image store-check` says so.
- **Core scheduling**: every sandbox gets its own core-scheduling cookie
  where the kernel supports it (`core_sched`, default auto).
- **Placement**: edges are ranked by what their hosts actually use (CPU and
  memory, above `placement.usage_floor`), not only by what is allocated.
  An edge can also refuse new sandboxes under CPU pressure: the edge setting
  `cpu_pressure_limit`, off by default.
- **Guest kernel**: the release ships the `6.1.167-opendsec.2` build (with
  EROFS) at the same path, `vm/vmlinux-6.1.167-opendsec`. New microVMs boot
  it; running ones keep theirs.
- **Keepalive**: gRPC servers ping idle connections every 20 s, so quiet
  streams survive a load balancer's idle timeout (at least 30 s).
  Clients (internal connections, the Go client, the Python SDK) ping every
  10 s, so a peer that disappears without closing the connection (network
  partition, host down, a hung edge) fails its calls within about 15 s
  instead of at their deadlines; creations on a hung edge then move to
  another edge.
- **Certificates**: every apiserver certificate carries
  `api.opendsec.internal`, which clients verify when given several
  apiservers.

### Added
- **E2B gateway** (`opendsec-e2b`, SPEC §37): E2B's SDKs run their
  sandboxes on OpenDsec unchanged (`E2B_API_URL`, `E2B_SANDBOX_URL`,
  `E2B_API_KEY` = an OpenDsec token). Configured by the cluster config's
  `e2b` section; fleet role `e2b=<index>`, unit `opendsec-e2b@`. Checked
  with E2B's Python (sync and async) and JS SDKs.
- **E2B fork and snapshots** (SPEC §37.10): `sandbox.fork()`,
  `create_snapshot()`, `list_snapshots()`, `delete_snapshot()` and
  `Sandbox.create(snapshot_id)` through the gateway, on `ForkSandbox` and
  `CreateSnapshot`; a snapshot is an image in the gateway's project.
- **Usage accounting** (SPEC §41): per project and UTC day, sandboxes
  started, sandbox-, CPU core-, memory GB- and GPU-hours, from IAM's quota
  leases (replicated, kept 400 days). `GetUsage` (project.admin),
  `opendsecctl usage [-daily] [-csv]`, SDK `get_usage`. Counted from the
  upgrade of all IAM replicas.
- **`ext.Env.AuditDir`, `AuditName` and `ext.SetupWith`** (SPEC §40): an
  extension learns where the apiserver keeps its audit log (the enterprise
  edition's audit export reads it).
- **Extension point `ext.Directory`** (SPEC §39): extensions create IAM
  principals and set their grants through the apiserver (the enterprise
  edition's SSO provisions its users with it).
- **Offline installs** (`deploy/offline/`, SPEC §38): `build-bundle.sh`
  makes one archive with the release, a local package repository, base
  images and the Python SDK's wheels; `install.sh` installs a single node
  from it with no internet access, and `OPENDSEC_DEBS` plus
  `opendsecops release-add` do the same for a cluster.
- **Images as files**: `opendsecctl image import` takes an OCI layout
  (directory or tar) or a `docker save` tar; `opendsecctl image save` writes
  a registry's image as an OCI tar.
- **quickstart** takes a packaged release (`--release DIR`) and works on
  machines without a default route.
- **E2B autoPause, network options and refresh** (SPEC §37.11):
  `lifecycle={"on_timeout": "pause"}`, `allow_internet_access`,
  `network.allow_out`/`deny_out`, `update_network()` and the refresh
  keepalive through the gateway.
- **`SandboxSpec.ttl_paused_s`**: a sandbox reaching its lifetime or idle
  timeout is paused instead of stopped, and kept paused that long.
- **Creating from a memory snapshot image** without resources takes the
  snapshot's VM shape (vCPUs, memory, disk) instead of failing on a size
  mismatch.
- **Process API** (SPEC §37): `StartProcess`, `ConnectProcess`,
  `ListProcesses`, `SendProcessInput`, `CloseProcessStdin`, `SignalProcess`,
  `ResizeProcess`: commands as processes of their own, by pid or tag, with
  stdin, signals and a PTY; a stream ending leaves the process running.
  Also `MakeDir`, `Move`, and `SetSandboxTimeout` (end a sandbox N seconds
  from now).
- **Sandbox ports** (`ConnectPort`, SPEC §37.8): a TCP connection to a port
  of a sandbox's loopback, as a stream through apiserver and edge. The E2B
  gateway serves sandboxes' other ports with it (HTTP, streamed responses,
  WebSocket), so E2B's code interpreter can reach its server; templates can
  carry a start command and a ready port.
- **E2B code interpreter template** (`deploy/e2b/build-code-interpreter.py`,
  SPEC §37.8): a memory snapshot of a microVM running E2B's code-interpreter
  server with a Python kernel; E2B's `e2b_code_interpreter` SDK passes its
  acceptance check.
- **Private registries** for `opendsecctl image import` (SPEC §35): the
  credentials `docker login` saved, or `-username` with `-password-stdin`;
  token services, identity tokens and plain Basic auth.
- **zstd-compressed image layers** (`tar+zstd`), alone or mixed with gzip
  ones in one image.
- **Extension points** (`ext`, SPEC §34): authenticators that
  resolve tokens IAM does not issue (SSO), and audit sinks. A cluster
  config's `"extensions"` section configures them; the open-source build
  has none and refuses to start when that section names one.
- **Fleet service and node agents** (SPEC §28): releases, configuration
  generations, staged rollouts with automatic rollback, adding machines
  (`opendsecctl fleet ...`). The IAM gains a key-value area for this; its
  backup format becomes `opendsec-iam-backup/2`, and the older formats still
  restore.
- **EROFS image disks for microVMs** (`erofs_images`): built once in the
  image store, copied to each node. Needs `mkfs.erofs` on the edges.
- **Network rules limited to ports and protocols**.
- **Retries for fork and bulk creation**: `ForkSandbox` and
  `CreateSandboxes` take a `request_id`; a retry with `retry` set returns
  the sandboxes the first attempt made and creates only the rest. The SDK
  now retries both when the stream breaks (an edge or apiserver restart)
  instead of failing.
- **Containers run on node-local copies of their image layers**
  (`layer_cache`, on by default): each layer is copied from the image store
  on its first use on a node. Running containers no longer stall while the
  store (an NFS NAS) is unreachable; the first sandbox of an image on a
  node takes the copy's time. Unused copies are removed after 6 hours.
- **Service level objectives** (docs/SLO.md): what the cluster promises,
  Prometheus recording rules and burn-rate alerts (group `opendsec-slo`),
  and a soak test for callers (`sdk/python/examples/soak.py`,
  `soak_report.py`).
- **Command output limits and per-session users**: `run_shell(user=...)`,
  `opendsecctl exec -user`.
- **`opendsecctl image store-check`**: checks a file system before the image
  store moves onto it. Opaque directories are stored as whiteouts, so NFS
  (which has no `trusted.*` xattrs) works.
- **Docker Hub names**: `docker.io/...` and `name:tag@digest` references.
- **Deployment**: `deploy/quickstart.sh` (one machine); `opendsecops`
  handles `local` nodes; `deploy/node/install.sh` installs the packages the
  edge needs; the node settings now survive a reboot.
- **CLI**:
  - `opendsecctl` accepts several apiservers (`addr,addr`);
  - `-deadline` sets a deadline (`image import` has none by default);
  - `-help` no longer shows `$OPENDSEC_TOKEN`.
- **Licenses**: releases carry `licenses/` (Go modules, Firecracker, the
  guest kernel's GPL texts and its corresponding source); see NOTICE.
- **microvm `cold_boot_dirty_tracking`** (default `true`): `false` runs
  cold-booted VMs without a KVM dirty page log, which keeps guest memory on
  the host's huge pages (memory-bound guests 9–67% faster), at the cost of
  a full first pause and full snapshots for those VMs (about 0.6 s per GB of
  VM memory, mostly with the VM frozen). VMs restored from a snapshot keep
  the log. Full snapshots now have their zero blocks punched out before
  they go to the image store.

### Fixed
- **Files and command output over 4 MB failed through the apiserver**: the
  apiserver, the edge and the internal clients kept gRPC's 4 MB message
  limit, so `write_file` and `read_file` of a larger file, and `run_shell`
  of a command printing more than 4 MB, failed (the Python SDK reported
  `quota_exceeded`). Messages now go up to 80 MB each way, as the agents in
  the sandbox already allowed; the Python SDK and the Go client accept as
  much, and the SDK reports a message over the limit as `invalid`.
- **MicroVMs could not resume on Ubuntu 24.04's current kernel** (6.8.0-1xx):
  after `cgroup.kill`, that kernel kills every process later cloned into the
  cgroup, and a paused microVM resumes into its own. Killing a cgroup's
  processes now freezes it and signals them one by one.
- **`not_found: unknown edge` during control-plane restarts**: a watcher that
  had just started left edges of the edge template out of its snapshots
  until they registered again (10 s), and calls to their sandboxes failed
  with an error callers do not retry. A watcher now starts with the edges
  its peers know, and apiservers keep routing to an edge missing from a
  snapshot for 2 minutes. During the upgrade to this version the old
  behaviour can still show (earlier watchers do not answer their peers):
  in our test, 7 of about 4,000 calls in the minute the control plane
  restarted.
- **`opendsecops restart`, `status` and `monitor` skipped the E2B gateway**
  (role `e2b`): a config pushed with `push-config` never reached it.
- **`opendsecctl sandbox create -count N`** prints the sandboxes' ids, as
  `sandbox fork` does. **`opendsecctl help`** (and `-h`, `--help`) prints
  the usage. **`image import /missing/file.tar`** says the file is missing
  instead of trying it as a Docker Hub image.
- **`deploy/quickstart.sh`** checks for `make` and the Go version before
  building; `--uninstall` also removes the empty `opendsec` cgroup.
- **`deploy/offline/build-bundle.sh`** checks for pip, make and Go before
  spending ten minutes downloading; the bundle carries E2B's SDK wheels, and
  the closing hints work without internet.
- **`deploy/e2b/build-code-interpreter.py`** asks for internet access, so it
  works on clusters that deny it by default.
- **Kubernetes manifests**: the apiserver ran as an unprivileged user and
  could not write the image store; it runs as root with only `DAC_OVERRIDE`
  and `FOWNER`, as its systemd unit, and reports ready on `/readyz`.
- **Alert `OpenDsecEdgeDiskLow`** fired on every edge with less than 200 GB
  free, whatever its size; it fires under 10% of the edge's disk now.
- **Fleet rollouts after adding roles to several nodes** (SPEC §37.7): the
  rollout waited for every node's new, not yet deployed units to be ready,
  and those waited for the rollout. Nodes now record the roles they were
  last applied with (`deployed_roles`), and only those count when other
  nodes' health is checked. Add roles with `fleet node sync`, one node at
  a time.
- **Orphan sandboxes** (SPEC §36): an edge finishing a creation whose
  caller gave up and placed it on another edge now drops it, instead of
  leaving a sandbox nobody knew of until its idle TTL; and an edge returning
  a lease that moved to another edge no longer frees that sandbox's quota.
- **Ending a large task no longer stalls the cluster.** Edges used to return
  each ended sandbox's quota lease to IAM separately, one Raft commit each,
  retrying timed-out calls whose commits were already queued. Stopping 1.15
  million sandboxes stalled new creations for about 45 s and left leases
  held until the reconcile, about 2 min later. Edges now batch the returns
  through the new IAM call `ReleaseLeases`, up to 1000 leases per Raft
  commit: the same stop returns every lease in about 2.3 s, and creations
  meanwhile wait at most 1.4 s (SPEC §31). While the IAM leader still runs
  an older release, edges return leases one by one, and they try batches
  again every minute, so the order of a rolling upgrade does not matter.
- **An edge no longer takes an OS thread per sandbox.** Waiting on each
  sandbox's process (container init, Firecracker, QEMU, the netns holder)
  blocked a thread in `waitid`; at 5781 containers an edge had 5817 threads,
  and the Go runtime ends a program past 10000. The waits now go through
  pidfds in the runtime's poller: 38 threads at 5000 containers (SPEC §32).
- **Network policy changes no longer list the whole nftables table.** Each
  sandbox's setup and removal listed every set of the edge's table under a
  lock. At 5000 sandboxes, adding one now takes 2.8 ms instead of 60 ms, and
  cleaning up 4900 takes 7 s instead of 2 min.
- **Forks occasionally failed with `no_capacity`** (5 of 219,000 in a 48-hour
  soak): the node's snapshot cache cleanup could remove a microVM snapshot
  in the moment between its arrival in the cache and its record reaching
  the image store. Young snapshots are now left alone. When every edge
  refuses a creation, the error now carries the last edge's reason instead
  of "no edge can host", and the apiserver logs each refusal.
- **Log growth on the root disk** (about 1.8 GB a day under load):
  - `deploy/node/install.sh` turns off networkd-dispatcher when it has no
    scripts (it ran networkctl for every sandbox link and flooded syslog),
    and keeps per-sandbox kernel and networkd messages out of
    /var/log/syslog and kern.log (they stay in the size-capped journal).
    Run it again on existing nodes.
  - The audit log keeps its newest `audit_keep` files (default 8) instead
    of every file.
- **Nodes sharing a hostname fought over the image store** (NFSv4): a
  client without an id identifies itself by hostname, so the NFS server took
  two cloned nodes for one client and dropped one node's state each time the
  other connected, hundreds of times a minute under load.
  `deploy/node/install.sh` now gives the NFS client the machine id
  (`nfs4_unique_id`); existing mounts pick it up only when mounted afresh,
  e.g. after a reboot. Overlay's per-mount `xino` message is also kept out
  of syslog.
- **Fleet**: retiring an edge that still has sandboxes is refused; a stored
  release cannot be overwritten.
- **Image import**: an import no longer stops after 5 minutes on large
  layers.

## 0.10.0

- **Rename**: the project is now OpenDsec (formerly DSec). This changes the
  protocol package (`opendsec.v1`), binaries, paths, environment variables,
  metrics and alert names.
- **Breaking**: 0.9 SDKs cannot reach 0.10 clusters. IAM restores backups
  taken before the rename (`dsec-iam-backup/1`).
