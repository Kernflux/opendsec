# Versioning and compatibility

This page says what stays compatible between OpenDsec releases, and what an
upgrade or a rollback needs. Changes are listed per release in
[CHANGELOG.md](../../CHANGELOG.md).

## Version numbers

- A release is `MAJOR.MINOR.PATCH`, from the `VERSION` file, tagged `v<version>`.
- Builds outside a release carry a timestamp: `make build` gives
  `0.11.0-202610180528`. `opendsecctl version` and the `opendsec_build_info`
  metric show it.
- **Before 1.0** (now), a minor release (0.11 → 0.12) may break compatibility.
  The changelog then lists every break under "Breaking" and says what to do.
  A patch release (0.11.0 → 0.11.1) never breaks anything.
- **From 1.0**, breaking changes need a new major version. Minor releases add
  features compatibly, and patch releases fix bugs.
- Security fixes go into the latest minor release only (see
  [SECURITY.md](../../SECURITY.md)).

## What is covered

| Surface | Compatibility |
|---|---|
| Public gRPC API (`opendsec.v1.DSec`, `proto/opendsec/v1/opendsec.proto`) and the Python SDK | Changes only add things: new RPCs, new fields, new enum values. Fields are not renumbered or reused. Error reasons (`no_capacity`, `quota_exceeded`, ...) are stable strings. An SDK works with clusters of its own minor version and the next one. Example: the 0.10 SDK runs against 0.11 clusters, and was tested under load during the 0.10 → 0.11 production upgrade. |
| Internal gRPC APIs: IAM, watcher and edge (`cluster.proto`), in-sandbox agents (`runtime.proto`), fleet | Compatible between consecutive minor versions, so that a rolling upgrade can run old and new components side by side (see below). They are not an API for other programs. |
| Cluster config (`opendsec.json`) | New fields are optional and have defaults. A field to be removed or renamed is deprecated for one minor release first. Validation may become stricter (for example, 0.11 rejects an `edge_template` zone that placement cannot use); the changelog lists such changes. |
| CLI (`opendsecctl`) | Commands and flags are kept; changes in how arguments are parsed are listed in the changelog. JSON output follows the protobuf JSON mapping of the API. |
| Metrics and alert names | May change in minor releases before 1.0; the changelog lists renames. |
| Go packages (`pkg/client`, `internal/...`) | Not covered. `internal/` cannot be imported from outside the module anyway. |

## Upgrades

**Supported path:** from one minor version to the next (0.10 → 0.11), and
between patch versions of one minor version. To go further, upgrade one
minor version at a time.

**Rolling upgrades keep running sandboxes.** The order is the same with the
fleet service (`opendsecctl fleet rollout create`) and with
`opendsecops upgrade`:

1. IAM followers, then the IAM leader. The followers can apply any command
   the old leader proposes. New kinds of commands are proposed only once the
   leader runs the new version, which by then all replicas do.
2. watchers, then apiservers, then fleet replicas.
3. edges, one at a time (or batch by batch with fleet), each drained first.

What carries over:

- **Edges**: an edge re-adopts the sandboxes the previous version left
  running. This needs `persist_state`, `keep_sandboxes_on_exit` and
  `KillMode=process` (the default units). The SDK resumes interrupted calls
  and output streams.
- **In-sandbox agents**: every release ships aether and chronus under its own
  `agents/` directory. A running sandbox keeps the agents it started with
  until it ends, and edges talk to agents from the previous minor version.
- **IAM state**: Raft logs and snapshots move forward. Backups restore across
  versions: 0.11 reads the formats `opendsec-iam-backup/2` and `/1`, and
  `dsec-iam-backup/1` from before the rename.
- **Guest kernel**: a new kernel in a release is used by new microVMs only.
  Running and paused VMs keep theirs.

**Runtime pins:**

- **Firecracker version**: a memory snapshot (a pause snapshot, a fork, an
  image created with `memory=true`) restores only under the Firecracker
  version that took it. Placement enforces this through the edges' reported
  runtime versions. A release that changes Firecracker therefore leaves
  older snapshots runnable only on edges still on the old version. The
  changelog says so whenever `deploy/deps.lock` moves Firecracker.
- **Image store formats**: layers, manifests and snapshots are read by later
  releases. Formats of derived files carry a version in their name (for
  example the EROFS disks under `vmdisks/`); a new format is built alongside
  the old one, and image GC removes the old one.

## Rollbacks

- **To the previous release**: run the same rolling procedure. With fleet,
  use `opendsecctl fleet rollout rollback <id>`, or roll out the old release;
  otherwise `opendsecops rollback <version>`.
- **State written by the newer release** may not be understood by the older
  one. In particular, a backup in a newer format does not restore into an
  older IAM. Take an IAM backup (`opendsecops backup`) before every upgrade,
  and keep the previous release's packages (fleet keeps them, and so does
  each node: the last 3, see `OPENDSEC_KEEP_RELEASES`).
- **A changelog entry marked "no rollback"** means the release changes
  stored state in a way the previous release cannot read. Such a change
  only comes in a minor release before 1.0, and never in a patch release.

## Deprecation

Something to be removed (an RPC, a field, a config key, a flag) is first
marked deprecated in the changelog, the proto comments or the config
reference. It keeps working for at least one more minor release.
