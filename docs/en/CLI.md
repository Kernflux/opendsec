# CLI reference: opendsecctl

`opendsecctl` is OpenDsec's command-line tool, for administrators and callers alike: create and operate sandboxes, manage images, projects, principals and tokens, inspect the cluster, issue certificates, and manage cluster releases (fleet).

```
opendsecctl <command> [arguments] [options]
opendsecctl help                 # every command
opendsecctl fleet                # help for the fleet subcommands
```

- It is installed as `/usr/local/bin/opendsecctl` (single-node install) or `/opt/opendsec/current/bin/opendsecctl` (cluster nodes); on the ops machine it is `$OPENDSEC_OPS/current/bin/opendsecctl`.
- Options may come before or after positional arguments: `opendsecctl sandbox stop <id> -addr x` and `opendsecctl sandbox stop -addr x <id>` are the same.
- Unless noted, output is JSON (protobuf's JSON form; fields at their default value are left out).
- Exit code 0 on success; on failure it prints `error: <reason>: <message>` and exits non-zero. `exec` exits with the command's own exit code.

## Connection and environment

| Option | Environment variable | Default | Meaning |
|---|---|---|---|
| `-addr` | `OPENDSEC_ADDR` | — | Apiserver address; several, comma separated |
| `-token` | `OPENDSEC_TOKEN` | — | Token. Prefer the variable, so it stays out of shell history and process lists |
| `-project` | `OPENDSEC_PROJECT` | `root` | Default project |
| `-ca` | `OPENDSEC_CA` | — | Cluster CA certificate; set, TLS is used |
| `-store` | `OPENDSEC_IMAGE_STORE` | — | Mount point of the image store (`image import`, `image gc`, `image store-check`) |
| `-deadline` | — | 5m | Time limit for the whole command; none for `image import` |

After a single-node install, the administrator's and the caller's environments are:

```sh
. /root/opendsec-ops/env         # administrator: admin token, project root
. /root/opendsec-ops/demo.env    # caller: a token for project root/demo, plus the E2B SDK's variables
```

## Sandboxes

### `sandbox create`

```
opendsecctl sandbox create -backend <backend> [-image I] [-cpu N] [-mem MB] [-disk MB] [-gpus N]
                           [-task T] [-ttl-idle S] [-ttl-max S] [-net rule,...] [-count N]
```

| Option | Default | Meaning |
|---|---|---|
| `-backend` | `sim` | `microvm`, `container`, `fncall`, `fullvm`, `sim`. **The default, `sim`, only simulates: always set it** |
| `-image` | — | Image, e.g. `root/py:3.12` |
| `-cpu` | 1 | CPU cores |
| `-mem` | 1024 | Memory, MB |
| `-disk` | 0 | Writable disk, MB; 0 for the backend's default |
| `-gpus` | 0 | GPUs |
| `-task` | — | Task name |
| `-ttl-idle` | 0 | Idle timeout (seconds); 0 for the cluster default |
| `-ttl-max` | 0 | Lifetime (seconds); 0 for the cluster default |
| `-net` | — | Network rules, comma separated; `!rule` takes back one of the cluster defaults, e.g. `-net 'pypi,github.com:443,!npm'` |
| `-count` | 1 | Number of sandboxes |

With `-count 1` the output is the sandbox's JSON. With a larger `-count`, each result is a line (`index<TAB>id`, or `index<TAB>error<TAB>reason: message` for a failure), followed by a summary:

```
$ opendsecctl sandbox create -backend microvm -image root/py:3.12 -count 3 -task job-1
0	node-a1.4k2m…
1	node-b1.9xq1…
2	node-a1.p0zz…
created 3/3 in 412ms; failures: map[]
```

The id in a script:

```sh
ID=$(opendsecctl sandbox create -backend microvm -image root/py:3.12 | grep -m1 '"id"' | cut -d'"' -f4)
```

### `sandbox get | stop | pause | resume | touch <id>`

View, stop, pause, resume, or reset the idle timer. Prints the updated sandbox.

### `sandbox list [-task T] [-all]`

Sandboxes of `-project` and its subprojects; `-task` narrows to a task, `-all` includes recently ended ones.

### `sandbox fork <id> [-count N] [-task T] [-ttl-idle S] [-ttl-max S]`

Copies a running sandbox into N (1 to 256); output as for batch creation.

### `sandbox network <id> <rule>... [-replace]`

Changes network rules: `pypi` allows, `!pypi` takes back. Merged into the current rules by default; `-replace` replaces them.

```sh
opendsecctl sandbox network $ID pypi github.com:443
opendsecctl sandbox network $ID '!github.com:443'
opendsecctl sandbox network $ID '*' -replace          # only the whole public internet
```

### `exec <id> [-session S] [-user U] [-timeout S] [--] <command...>`

Runs a command in a sandbox, streaming its stdout and stderr, and exits with its exit code.

- **One argument** is a whole shell command, interpreted by the sandbox's shell: `opendsecctl exec $ID 'cd /srv && make test | tail'`.
- **Several arguments** are each quoted and joined, as `ssh` and `docker exec` do: `opendsecctl exec $ID python3 -c 'print(6*7)'` runs exactly `python3 -c 'print(6*7)'` in the sandbox.
- If an argument starts with `-` (as in `ls -la`), put `--` before the command so opendsecctl does not take it as its own option: `opendsecctl exec $ID -- ls -la /`.
- `-session`: session name, default `default`; `-user`: the session's user when this command starts it; `-timeout`: seconds; on expiry it prints `opendsecctl: command timed out`.

> Before 0.11, several arguments were joined with spaces and no quoting. Scripts that added an extra layer of quotes to work around that (e.g. `"'print(6*7)'"`) must drop it.

### `cp <id>:<path> <local file>` / `cp <local file> <id>:<path>`

Copies one file between this machine and a sandbox, up to 64 MB; use the SDK's chunked reads and writes for larger files.

## Tasks

```
opendsecctl task pause|resume|stop <task>
```

Acts on every sandbox of the task in `-project` and prints how many succeeded and failed.

## Images

### `image import <source> -as <project>/<name>:<tag> -store <store>`

Imports an image into the shared store and registers it. Run it **as root on a machine that mounts the image store**; it needs `layer.publish` on the target project.

The source can be:

| Source | Example |
|---|---|
| Public registry | `docker.io/library/python:3.12`, `python:3.12`, `ghcr.io/org/image:tag` |
| Private registry | `harbor.example.com/team/app:1.0` |
| Registry without TLS | add `-plain-http` |
| OCI layout, directory or tar | `./python-3.12.oci.tar` |
| `docker save` tar | `./app.tar`; with several images in the file, `file#name` picks one |

Local paths must start with `/` or `.`; a missing file is an error (it is never looked up in a registry).

Private registry credentials are taken from, in order:

1. `-username U -password-stdin`: the password or access token is read from stdin, e.g. `echo "$TOKEN" | opendsecctl image import ... -username 'robot$ci' -password-stdin`;
2. `-registry-auth FILE`: a docker-format credentials file;
3. `$REGISTRY_AUTH_FILE`, `$DOCKER_CONFIG/config.json`, `~/.docker/config.json` (what `docker login` saved).

An import has no overall time limit (a large image can take long); progress goes to stderr.

### `image save <source> -out <file>`

Saves a registry image as an OCI tar, for machines without internet access to `image import ./file`. Needs no cluster. Takes `-plain-http`, `-username`, `-password-stdin`.

### `image compose <new image> <part>... [-overwrite]`

Stacks images bottom first into one, without copying data:

```sh
opendsecctl image compose root/rl/swe-4821:v1 root/rl/python:3.12 root/rl/django-ws:a1b2 root/tools/agent-kit:3
```

### `image list [-project P]`, `image get <name>`, `image delete <name>`

List the images of a project and its subprojects; show one image; delete an image's registration (`image gc` reclaims the layers).

### `image pack <sandbox-id> <new image> [-scrub a,b] [-overwrite]`

`pack_diff`: saves a container sandbox's changes against the image it started from as a new image. `/tmp`, caches and shell history are removed by default; `-scrub` adds paths (globs relative to `/`).

### `image snapshot <sandbox-id> <new image> [-memory] [-overwrite]`

Saves a sandbox as an image as it is. microVMs need `-memory` (memory included).

### `image gc -store <store> [-grace 24h] [-dry-run]`

Removes layers and snapshots no image refers to. Anything younger than `-grace` (default 24 hours) stays, so imports in progress and fresh snapshots are safe. Try `-dry-run` first to see what would go. It needs the connection settings but works on the store only.

### `image store-check -store <dir>`

Checks whether a file system (a newly mounted NAS, say) can hold the image store: permissions, hard links, renames, xattrs, sparse files and more. Every required item must be `ok`. Needs no cluster.

```
$ opendsecctl image store-check -store /mnt/opendsec-images
ok    write, sync and read back a file
ok    files a root process creates are root's (no root squash)
ok    chown to another user (image files keep their owners)
ok    exclusive create (one edge builds a VM disk at a time)
ok    rename a file over another (manifests, records)
ok    rename a directory (layers are published so)
ok    hard links (snapshots link their disks)
ok    symbolic links
ok    finds the holes of sparse files (snapshots move only their data; NFS needs vers=4.2)
ok    0:0 character devices (layer whiteouts)
ok    overlay over layers kept here, whiteouts honored
ok    trusted.* xattrs
ok    user.* xattrs
/mnt/opendsec-images can hold the image store
```

Items that are not required (sparse-file holes, `trusted.*` xattrs) only warn when they fail, and the store still works; a failed required item rules the file system out.

## Projects, principals, permissions and tokens

| Command | Meaning |
|---|---|
| `project create <parent> <name> [-quota k=v,...]` | Create a subproject, e.g. `project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000` |
| `project get <path>` | Quota, current usage, each principal's permissions, subprojects |
| `project delete <path>` | Delete an empty project |
| `principal create <project> <id> [-kind agent\|user\|service] [-ttl S]` | Create a principal; **the token in the output is shown only this once** |
| `principal delete <id>` | Delete a principal and all its tokens |
| `grant <project> <principal> <perm>[,<perm>...]` | Grant permissions, e.g. `grant root/team-a trainer sandbox.create,sandbox.operate` |
| `revoke <project> <principal> [<perm>,...]` | Revoke permissions; all of them when none are named |
| `token create [<principal>] [-ttl S] [-desc D]` | Issue a token, by default for yourself |
| `token list [<principal>]` | List tokens (no secrets) |
| `token revoke <principal> <token-id>` | Revoke; takes effect cluster-wide within about 1 s. `primary` is the legacy primary token |
| `whoami` | The principal of the current token |
| `usage [<project>] [-from YYYY-MM-DD] [-to YYYY-MM-DD] [-daily] [-csv]` | Usage: by default each project's total over the period; `-daily` per day and project; `-csv` CSV output |

Quota keys: `sandboxes`, `cpu_cores`, `memory_mb`, `gpus`. What the permissions mean: [Projects, principals and permissions](IAM.md).

## Cluster

| Command | Meaning | Needs |
|---|---|---|
| `status` | Cluster snapshot: each edge's health, draining state, capacity, allocations, sandbox counts, free memory and disk, pressure | — |
| `edge drain <edge-id> [-undo]` | Stop (`-undo`: resume) placing new sandboxes on an edge; its sandboxes keep running | `project.admin` on root |
| `iam backup -out FILE` | Back up IAM (gzipped JSON, mode 0600): principals, projects, grants, quotas, token hashes | as above |
| `iam restore FILE` | Replace IAM's contents with a backup (quota leases of running sandboxes are kept) | as above |
| `iam members` | List the IAM Raft replicas | as above |
| `iam member add <id> -raft-addr H:P -iam-addr H:P` | Add a replica started with `opendsec-iam -join` | as above |
| `iam member remove <id>` | Remove a replica (its machine is gone, say) | as above |
| `version` | This build's version | — |

## Certificates

These need no cluster.

| Command | Meaning |
|---|---|
| `pki init -config opendsec.json -out DIR [-days 365] [-ca-days 3650] [-hosts h1,h2]` | Create a cluster CA and a certificate for every component in the config. `-hosts` adds host names or IPs to every certificate |
| `pki ca -out DIR [-days N]` | A new CA only (CA rotation) |
| `pki issue -ca DIR -role <role> -id <id> [-hosts ip1,ip2] -out DIR [-days 365]` | A certificate for one component. Roles: `edge`, `apiserver`, `watcher`, `iam`, `fleet`, `node`, `ops` |

Production clusters usually use `opendsecops certs`, which calls these; see [Cluster deployment](CLUSTER.md).

## Local clusters and benchmarks

| Command | Meaning |
|---|---|
| `cluster up` | Run a whole cluster in this process, for development and tests |
| `bench` | Scheduling benchmark on an in-process simulated cluster; `-compare` compares random placement with power-of-2 |

`cluster up` options:

| Option | Default | Meaning |
|---|---|---|
| `-config` | a generated simulated cluster | Cluster config file |
| `-sim-edges` | 4 | Simulated edges without `-config` |
| `-apiservers` | 1 | Apiservers without `-config` |
| `-runtime` | `sim` | Runtime of the container backend in generated clusters: `sim` or `linux` (real containers, needs root) |
| `-microvm-kernel` | — | Also offer the `microvm` backend, with this guest kernel |
| `-image-store` | — | Shared image store directory (enables the store and `pack_diff`) |
| `-state-dir` | `/var/lib/opendsec` | Sandbox state directory (linux runtime) |
| `-host-image` | true | Offer the development image `host` (the host's `/` as a read-only lower layer: it exposes host files, development only) |
| `-disk-reserve-mb` | 512 | Reject creations while the state directory has less free space; -1 disables |
| `-tls` | false | Create a CA and certificates and run with mTLS |
| `-audit-dir` | — | Apiserver audit log directory |
| `-metrics` | — | Prometheus metrics address, e.g. `:9464` |
| `-write-config` | — | Write the effective config (with the bound addresses) to this file |
| `-log` | `info` | Log level |

```sh
./bin/opendsecctl cluster up -sim-edges 1 -runtime linux -image-store /mnt/opendsec-images \
    -microvm-kernel /opt/opendsec/vm/vmlinux-6.1.167-opendsec
# then set OPENDSEC_ADDR, OPENDSEC_TOKEN and OPENDSEC_PROJECT as it prints
```

## fleet: cluster releases and configuration

These go through an apiserver and need `fleet.view` (read) or `fleet.operate` (change) on root; `project.admin` includes both. Every action is audited.

| Command | Meaning |
|---|---|
| `fleet nodes [-state S] [-role R] [-domain D]` | Machines: state, failure domain, roles, desired and running release, units ready, last heartbeat |
| `fleet node get <name>` | One machine |
| `fleet node accept <name> -roles edge=<id>[,...] [-domain D] [-addr-ip IP] [-labels k=v,...]` | Accept a newly reporting machine: deliver the current release and config and start it |
| `fleet node set <name> [-roles ...] [-domain D] [-addr-ip IP] [-labels k=v,k=]` | Change roles, failure domain, labels (`k=` removes a label). Changes the record only; deploys nothing |
| `fleet node sync <name>` | Bring a machine to its desired release, config and roles |
| `fleet node cordon \| uncordon <name>` | Stop or resume placing sandboxes on it |
| `fleet node evacuate <name> [-deadline 1h]` | Cordon, then wait for its sandboxes to end |
| `fleet node retire <name>` | Take a machine out: stop and disable its components |
| `fleet node pin <name> [-reason R]`, `unpin <name>` | Pin or unpin: pinned machines are left out of rollouts |
| `fleet import -inventory FILE -release V [-config-gen G] [-domain D]` | Register machines already running release V (when moving from opendsecops) |
| `fleet releases` | Uploaded releases |
| `fleet release pack -bin DIR -units DIR [-deps DIR] -out DIR` | Package a release directory (usually done by `opendsecops release`) |
| `fleet release push <release dir> [-notes N]` | Upload a release to every fleet replica |
| `fleet config put <cluster.json> [-note N]` | Upload a new cluster config as a new config generation |
| `fleet config get [-gen N] [-out FILE]` | Fetch a config generation |
| `fleet rollout create [-release V] [-config-gen G] [...]` | Start an upgrade or config change; options below |
| `fleet rollout status [<id>] [-steps]` | Progress, of the newest rollout by default; `-steps` lists every machine |
| `fleet rollout pause \| resume \| abort \| rollback <id>` | Pause, continue, abort, roll back |
| `fleet rollouts` | Past rollouts |

`fleet rollout create` options:

| Option | Meaning |
|---|---|
| `-release V`, `-config-gen G` | Target release, target config generation (at least one) |
| `-roles`, `-domains`, `-nodes`, `-labels` | Only machines with these roles, domains, names, labels |
| `-canary N` | Machines upgraded alone first; default 1, -1 for none |
| `-bake S` | Observation time (seconds) after the canary and after each batch; default 300, -1 for none |
| `-batch N` | Machines per batch; default 5% of the non-control-plane machines (at least 1, at most 100) |
| `-max-per-domain N` | At most this many machines of one failure domain per batch; default half the batch (at least 1) |
| `-pause S` | Seconds between batches; default 60, -1 for none |
| `-max-failures N` | Failed machines tolerated before pausing; default 0, i.e. pause at the first failure |
| `-step-timeout S` | Timeout per machine (seconds), default 600 |
| `-note N` | A note |

With no apiserver available, connect to fleet directly from the ops machine with the ops certificate:

```sh
opendsecctl fleet nodes -direct -fleet 10.0.0.1:7300,10.0.0.2:7300 -pki $OPENDSEC_OPS/pki -ops-id ops
```

The full release procedure is in the [operations manual §6](OPERATIONS.md).
