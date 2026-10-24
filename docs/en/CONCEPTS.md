# Concepts

This page introduces every concept you meet when using OpenDsec: sandboxes and their backends, lifecycle and timeouts, sessions, tasks, images and snapshots, networking, projects and permissions, and errors. The [Python SDK reference](PYTHON_SDK.md) and the [CLI reference](CLI.md) are easier to follow after it.

## 1. Architecture

```
 Python SDK / opendsecctl / E2B SDK
              |  gRPC + TLS, bearer token
              v
     +-----------------+  auth, quota  +-----------------+
     |  apiserver x N  | ------------> |   IAM x 3       |
     |  (stateless)    | <------------ |   (Raft)        |
     +-----------------+               +-----------------+
         |        ^     snapshot       +-----------------+
         |        +------------------- |   watcher       |
         |  create, exec, files        +-----------------+
         v
     +----------+   +----------+   +----------+
     |  edge    |   |  edge    |   |  edge    |   one per compute node
     | sandbox  |   | sandbox  |   | sandbox  |
     +----------+   +----------+   +----------+
           \             |             /
            shared image store (NFS / CephFS / JuiceFS)
```

- The **apiserver** is the only way in. It keeps no state, so you can run as many as you like behind a load balancer.
- **IAM** holds projects, principals, permissions, quotas and tokens, replicated over three replicas with Raft.
- The **watcher** probes every edge each second and aggregates each node's capacity and load into a snapshot the apiservers schedule from.
- An **edge** runs on every compute node and creates and manages that node's sandboxes. After the apiserver picks a node, its edge makes the final call based on the node's actual memory, disk and CPU pressure.
- The **shared image store** is mounted on every apiserver and edge node and holds image layers and snapshots.

How each component works inside is in [How the components work](COMPONENTS.md).

## 2. Sandboxes

A sandbox is an isolated environment with its own file system, process space, network and resource limits. You run commands in it, read and write its files, reach services running inside it, and stop it when you are done.

Each sandbox has:

| Field | Meaning |
|---|---|
| `id` | `<edge_id>.<random>`, e.g. `node-a1.k3m9x...`. The first part is the node that created it |
| `project` | The project it belongs to; its resources count against that project's quota |
| `principal` | Who created it |
| `edge_id` | The node it is on now. It changes when a paused sandbox moves to another node; the `id` does not |
| `spec` | What was requested: backend, image, resources, timeouts, network rules, task, labels |
| `state` | Current state; see below |
| `created_at`, `last_active_at`, `ended_at` | Unix timestamps (seconds) |
| `message` | Why it became `FAILED` or `STOPPED`, e.g. `idle timeout (ttl_running_stop) reached` |

### 2.1 Backends

A creation must name its backend (`backend`); the SDK does not choose one for you.

| Backend | Built on | Start | Isolation | When paused | Fork and snapshots | Use it for |
|---|---|---|---|---|---|---|
| `microvm` | Firecracker VM + jailer | cold start about 0.1 s; from a memory snapshot about 55 ms | strongest: its own kernel, a uid per VM | snapshotted and the process ends, all memory freed; resumes in about 50 ms | yes, with memory | the default; untrusted code |
| `container` | Linux container: overlayfs, cgroup v2, namespaces, seccomp | about 0.1 s | shares the host kernel | processes frozen; with `pause_reclaim`, memory goes to swap | fork copies files only; `pack_diff` builds images | building images; trusted, performance-sensitive code |
| `fncall` | a pool of pre-started containers | about 2 ms | as container | as container | as container | many short function calls |
| `fullvm` | QEMU full VM | about 0.23 s | VM | vCPUs stopped, memory kept | no | a full system (the image's own init) or PCI passthrough (GPUs) |
| `sim` | simulated lifecycle; runs nothing | — | — | — | — | tests and scheduling benchmarks |

Which backends a cluster offers depends on what the administrator enabled on each node ([configuration reference](CONFIGURATION.md#edges-backends)). A machine without `/dev/kvm` offers only `container` and `fncall`.

### 2.2 Resources

| Parameter | Meaning | Default |
|---|---|---|
| `cpu_cores_limit` | CPU cores; may be fractional | 1 |
| `memory_limit_mb` | Memory (MB). For a microVM this is the guest's memory | 2048 |
| `disk_mb` | Writable disk size (MB); 0 means the backend's default | the backend's `default_disk_mb`: microvm 2048 and container 1024 in the quickstart and example configs; 10240 when the config sets none |
| `gpus`, `gpu_mode` | Number of GPUs; `exclusive` or `shared` | 0 |
| `qos` | `LS` (latency-sensitive) or `BE` (best effort). BE sandboxes run at the lowest CPU priority (cgroup `cpu.idle`) and are reclaimed from first when the node is short of memory | `LS` |

Nodes admit sandboxes against their capacity **after overcommit**: CPU is overcommitted 8x by default (`cpu_overcommit`), memory not at all. Placement ranks nodes by whichever is higher, what is allocated or what is actually in use.

### 2.3 States

```
                create
                   |
                   v
               CREATING ---- error ----> FAILED
                   |
                   v
      +------> RUNNING -----------------+
      |            |                    |
  RESUMING      PAUSING              STOPPING
      ^            |                    |
      |            v                    v
      +-------- PAUSED -------------> STOPPED
```

| State | Meaning |
|---|---|
| `CREATING` | Being created: file system and network prepared, process or VM started |
| `RUNNING` | Running; commands and file calls work |
| `PAUSING`, `PAUSED` | Pausing, paused. **A runtime call to a paused sandbox (a command, a file call, HTTP) resumes it**; callers do not need to call `resume` first |
| `RESUMING` | Resuming |
| `STOPPING`, `STOPPED` | Stopping, stopped. Its file system and processes are cleaned up and its quota is returned at once |
| `FAILED` | Creation or the sandbox failed; the reason is in `message` |

Records of ended sandboxes (`STOPPED`, `FAILED`) stay on the node for 10 minutes (`stopped_retention`) and can still be looked up meanwhile; `list_sandboxes(include_ended=True)` lists them.

### 2.4 Timeouts

Each sandbox has two timeouts, set at creation, in seconds:

| Timeout | Meaning | Default | Limit |
|---|---|---|---|
| `ttl_running_stop` (idle timeout) | A running sandbox with no calls and no command running for this long is stopped | 3600 (1 hour) | none |
| `ttl_max` (lifetime) | Counted from **creation**, paused time included; the sandbox stops when it is reached | 86400 (1 day) | 604800 (7 days) |

- 0 means the cluster default. Defaults and the limit are set by the administrator under `admission` ([configuration reference](CONFIGURATION.md#admission)). A request whose `ttl_max` exceeds the limit is rejected (`invalid`).
- **Idle** means no runtime call is in progress and the last call is older than the idle timeout. A command running for two hours keeps the sandbox from being idle.
- Paused time does not count toward the idle timeout: it starts from zero again on resume.
- `touch()` resets the idle timer and does nothing else.
- **Pause instead of stop on timeout**: with `ttl_paused_s` set (used through the API and E2B's `autoPause` for now), a sandbox reaching its idle timeout or lifetime is paused and kept `ttl_paused_s` more seconds. Any call during that time resumes it.
- E2B's `set_timeout` maps to the API's `SetSandboxTimeout`: the lifetime becomes the sandbox's current age plus the timeout.

**`stop()` sandboxes when you are done**: a sandbox holds its project's quota until it stops.

## 3. Running commands: sessions

Commands run in **sessions**. A session is a long-lived shell in the sandbox:

- in one session, `cd` and `export` carry over from one command to the next;
- the default session is `default`; any other name opens a new session, independent of the others;
- a session's user is fixed by its first command (the `user` parameter: a name or `uid[:gid]`; default `init_user`, i.e. root) and cannot change afterwards;
- `close_session()` ends a session and kills every process it started.

**Keep the agent and the grader apart**: run the agent's commands in a session of an unprivileged user (e.g. `session="agent", user="1000"`) and grade in another, root session. An unprivileged session cannot reach other sessions, read their output records or change system files. Write the grader's secret files with strict permissions (e.g. `umask 077`).

**Output limits**:

- the first 64 MB of each command's stdout and stderr are recorded; the rest is read and dropped (the command keeps running), and the dropped byte count is in `ShellResult.dropped_bytes`;
- each session keeps the last 512 MB of output records; older ones are deleted and `get_output` can no longer fetch them.

**Timeouts**: when a command's `timeout` expires, the processes it started are killed; the session stays.

**Lost connections**: if the edge or apiserver restarts while a command runs, the SDK reconnects and fetches the result without running the command twice; streamed output continues where it broke off, with nothing repeated or lost.

Besides sessions, a sandbox can run standalone **processes** (the API's `StartProcess` and related calls; E2B's `commands.run` is built on them): each has its own pid, stdin and signals, optionally a PTY. A process keeps running when the caller disconnects, and the caller can attach to it again later.

## 4. Tasks

A sandbox can be created with a `task_id`, such as the name of an RL training job. All sandboxes of a task can then be acted on together:

| Action | Effect |
|---|---|
| `pause_task` | Pause every sandbox of the task, e.g. when training is preempted: microVMs free all their memory; containers with `pause_reclaim` push it to swap |
| `resume_task` | Resume every paused sandbox. Optional: the next call to a sandbox resumes it anyway |
| `stop_task` | Stop every sandbox, when the job ends |

The result counts the sandboxes that succeeded and failed, with the failures' reasons.

## 5. Batch creation and fork

- **Batch creation**: `run_sandboxes(args, count)` creates up to 32768 sandboxes in one call. The server queues them at the rate limit, so rate limiting never fails part of a batch. Results come back in index order; failed items are `DSecError`s.
- **Fork**: `sb.fork(count=N)` copies a running sandbox into N running sandboxes (up to 256).
  - The source pauses briefly (about 10 ms for a microVM) and carries on with its `id` and timeouts unchanged.
  - Copies inherit the source's spec; they can get extra labels, another `task_id` and timeouts of their own.
  - microVM copies include memory: processes continue from the moment of the fork. Each copy gets its own hostname, machine-id and random seed. Copies on the same node share memory pages.
  - Container copies get the file system only, not the processes.
  - Copies go to the source's node first; when it is full, to other nodes, which pull the snapshot straight from the source node.
  - Each copy counts against quota on its own.

Batch creation and fork carry idempotency keys: when a server restart breaks the connection, the SDK's retry creates only what is still missing, never extra sandboxes.

## 6. Images and snapshots

Sandboxes start from **images**, kept in the shared image store and named `<project>/<name>:<tag>`, e.g. `root/py:3.12` or `root/rl/swe-4821:v1`. The tag defaults to `latest`.

| Source | How | Notes |
|---|---|---|
| Imported from a registry | `opendsecctl image import` | Any OCI registry, Docker Hub and private registries included; `docker save` files too |
| Composed | `compose_image` | Several images stacked in order (base environment + repository + tools), without copying data |
| Made from a sandbox | `pack_diff` (container) | Saves only the sandbox's changes against the image it started from, minus build residue (`/tmp`, caches, shell history) |
| Snapshot | `create_snapshot` | Saved as is. microVMs must include memory (`memory=True`); sandboxes created from it continue from the moment of the snapshot |

Image permissions follow the project the image belongs to: publishing (import, compose, `pack_diff`, snapshot, delete) needs `layer.publish`, using (creating sandboxes, viewing) needs `layer.use`. See [Images and snapshots](IMAGES.md).

## 7. Network

Sandbox networking **denies by default**: nothing is reachable unless allowed. Allow destinations with `network_rules`, whose keys can be:

- the name of a rule set the administrator defined (e.g. `pypi` = `pypi.org` + `files.pythonhosted.org`);
- a domain, subdomains included, e.g. `github.com`;
- an IPv4 address or network, e.g. `1.2.3.4`, `10.20.0.0/16`;
- `*`: every public address.

Any of them can take `:port[/protocol]`, e.g. `pypi.org:443`, `10.0.0.0/8:5432/tcp`. `true` allows; `false` takes back something the cluster's default rules allow. `update_network()` changes the rules of a running sandbox.

Private, link-local and multicast addresses are reachable only through an address or network rule that names them; private addresses a domain resolves to are always blocked. See [Network policy](NETWORK.md).

## 8. Projects, principals and permissions

- **Projects** form a tree rooted at `root`, e.g. `root/team-a/rl`. Every sandbox and image belongs to a project.
- A **principal** is a caller, with one or more **tokens** (`dsk.<id>.<secret>`). Its kind is `user`, `service` or `agent`, a label only: permissions do not depend on it.
- **Permissions** are granted on a project and inherited by its subprojects:

| Permission | Allows |
|---|---|
| `sandbox.create` | Creating sandboxes in the project (forks included) |
| `sandbox.operate` | Operating the project's sandboxes: view, list, run commands, files, pause, resume, stop, network changes |
| `layer.use` | Using the project's images: create sandboxes from them, view them |
| `layer.publish` | Publishing the project's images: import, compose, `pack_diff`, snapshot, delete |
| `project.admin` | Managing the project: subprojects, principals, grants, tokens, usage; on root, cluster operations too |
| `fleet.view`, `fleet.operate` | On root: viewing and operating the cluster management service (upgrades, config changes) |

- **Quotas** are set on projects and checked up the tree: a subproject's usage also counts in every ancestor. Quota keys are `sandboxes`, `cpu_cores`, `memory_mb`, `gpus`.
- **Bounded delegation**: a project admin can grant only permissions they hold, and a subproject's quota cannot exceed any ancestor's.

See [Projects, principals and permissions](IAM.md).

## 9. Errors

Every error carries a stable reason string (`DSecError.reason` in the Python SDK):

| reason | Meaning | What to do |
|---|---|---|
| `unauthenticated` | Token invalid, expired or revoked | Use another token |
| `forbidden` | A permission is missing | The message names it; ask the project admin to grant it |
| `not_found` | No such sandbox, project or image, or the sandbox was cleaned up | — |
| `quota_exceeded` | Over the quota of the project or an ancestor | Stop sandboxes you no longer use, or ask for more quota |
| `rate_limited` | Over the rate limit | Back off and retry |
| `no_capacity` | The cluster cannot place it now (every candidate node full or under pressure) | Retry later, or lower concurrency |
| `invalid` | Bad arguments, e.g. a timeout over the limit, a malformed rule, an unknown backend | Read the message |
| `unavailable` | A server is restarting or failing over | The SDK already retried, for up to 60 s by default |
| `timeout` | The call timed out | Raise `timeout`, or check the cluster's load |
| `internal` | Server-side error | Note the time and sandbox id and check the server logs |

**Which calls are safe to retry**: creation, batch creation and fork carry idempotency keys, so retries create nothing extra; commands carry a request id, so a retry never runs one twice; queries can always be retried. The SDK retries `unavailable` by itself; other reasons are the caller's decision.

**Node failure**: when the machine a sandbox runs on fails, the sandbox is lost and later calls return `not_found` or `unavailable`. Take out results you need to keep.
