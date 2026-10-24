# OpenDsec: sandbox infrastructure for agentic training

English | [中文](README.zh-CN.md) | [Website](https://kernflux.github.io/) | [Docs](https://kernflux.github.io/en/docs/)

OpenDsec runs large numbers of isolated sandboxes (Firecracker microVMs, containers, full QEMU VMs) for reinforcement-learning rollouts and code-executing agents.

> **Based on DeepSeek's DSec paper.** OpenDsec is an open-source implementation of the system described in [*DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*](https://arxiv.org/abs/2609.22978) (arXiv:2609.22978). Its architecture and most of its design come from that paper; see [Based on the DSec paper](#based-on-the-dsec-paper) below. It is an independent project: **not affiliated with, endorsed by, or maintained by DeepSeek**, and it contains no DeepSeek code.

- **Fast sandboxes**: a microVM cold-starts in about 0.1 s and restores from a memory snapshot in about 55 ms. `fork(count=N)` clones a running VM with its memory: the copies share pages on the same node and pull the snapshot from the source node otherwise.
- **Scale**: one 384-thread node took 5120 microVMs in one burst; a two-node cluster took 8192 containers in a burst with no failures. Placement is power-of-two-choices over actual CPU and memory use, with image- and snapshot-aware locality.
- **Images**: pull from any OCI registry (Docker Hub included), compose layers without copying, `pack_diff` a sandbox's changes into a new image. Image layers live in a shared store (NFS, CephFS, JuiceFS …) and are loaded lazily; microVMs read them as EROFS disks built once per image.
- **Isolation**: jailer with a uid per VM, core scheduling against SMT side channels, seccomp, read-only agents, per-session users, and a default-deny network policy with domain, CIDR and port rules.
- **Control plane**: multi-level projects with quotas and delegation, a Raft-replicated IAM, mTLS between components, short-lived revocable tokens, audit logs. Every component restarts without disturbing running sandboxes.
- **Operations**: Prometheus metrics and alerts, batch pause/resume of a whole task, staged fleet-wide rollouts with automatic rollback, and an async Python SDK that rides through apiserver and edge restarts.

The design, every decision and every measurement are in [docs/SPEC.md](docs/SPEC.md) (Chinese). How each component works inside is in [docs/COMPONENTS.md](docs/COMPONENTS.md) (Chinese).

## Based on the DSec paper

OpenDsec was built by following the DSec paper, which describes the sandbox infrastructure DeepSeek uses for agentic reinforcement-learning training. We are grateful to its authors for publishing the design in such detail.

**Taken from the paper:**
- The architecture and the names of its components:
  - a stateless apiserver;
  - IAM with multi-level projects, quotas and bounded delegation;
  - a watcher that aggregates scheduling state;
  - power-of-k placement, with the edge on each node having the final say on admission;
  - aether and chronus inside each sandbox.
- Layered images with on-demand loading, image composition and `pack_diff`.
- A default-deny network policy with per-sandbox rules.
- The sandbox backends: container, FnCall, microVM and full VM.
- The features for RL training:
  - batch pause and resume of a task, with memory pushed to swap;
  - GPU sharing and CPU QoS;
  - core scheduling;
  - EROFS image disks;
  - output limits and per-session users.
- The shape of the Python SDK.

[docs/SPEC.md](docs/SPEC.md) marks every design point as either **[论文]** (from the paper, with the section) or **[决定]** (our own decision).

**Our own, where the paper leaves things open or we chose differently:**
- **Network policy**: enforced with nftables and a DNS proxy, where the paper uses eBPF.
- **Image store**: any shared file system (NFS, CephFS, JuiceFS), where the paper uses 3FS.
- **Firecracker as the main backend**: with memory snapshots, pause-to-snapshot and `fork`. The API for these follows the open-source [E2B](https://github.com/e2b-dev/infra) infrastructure.
- **Operating the cluster**: the fleet service and node agents, `opendsecops`, and the single-node quickstart.
- **Numbers**: every number in this README and in SPEC.md is our own measurement on our hardware, not a figure from the paper.

**Citing:** if you use OpenDsec in research, please cite the paper it implements: *DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*, arXiv:2609.22978, 2026.

"DeepSeek" and "DSec" are names of their respective owners. OpenDsec uses them only to identify the paper it implements.

## Try it on one machine

You need a Linux x86_64 machine (tested on Ubuntu 24.04) with systemd and cgroup v2. MicroVMs also need `/dev/kvm`: use bare metal, or a cloud VM with nested virtualization; without it the script sets up containers only. Run every step below as root: the script installs system services, and the files it writes for you are in `/root/opendsec-ops`.

```sh
sudo -i                                    # the rest runs as root
apt update && apt install -y make git python3-venv   # Debian and Ubuntu
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz   # Go 1.27 or newer
git clone https://github.com/kernflux/opendsec && cd opendsec
deploy/quickstart.sh                       # or --no-microvm for containers only
```

The script checks the machine, builds the binaries, and downloads Firecracker and the guest kernel, checking each against `deploy/deps.lock`. Instead of the download, `--kernel FILE` uses a kernel you have, and `--build-kernel` builds it (a few more minutes; needs `build-essential flex bison bc libelf-dev libssl-dev`). It then does the following:

1. Installs IAM, watcher, apiserver, edge and the E2B gateway as systemd services, with their own CA and certificates.
2. Imports `python:3.12` from Docker Hub.
3. Creates the project `root/demo` and a caller for it.
4. Runs a container sandbox and a microVM sandbox as a check.

The whole run took about 11 minutes on a fresh 8-core VM, most of it building. The cluster comes back by itself after a reboot.

Then use it from Python, still as root in the same directory:

```sh
. /root/opendsec-ops/demo.env                 # OPENDSEC_ADDR, OPENDSEC_TOKEN, OPENDSEC_PROJECT, OPENDSEC_CA
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
.venv/bin/python sdk/python/examples/quickstart.py
```

```python
import asyncio
from opendsec import DSecClient, DSecRunArgs

async def main():
    async with DSecClient() as client:               # reads the OPENDSEC_* variables
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm", image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            network_rules={"pypi": True}))           # outbound traffic is denied unless allowed
        try:
            print((await sb.run_shell("python3 -c 'print(6*7)'")).stdout)
            forks = await sb.fork(count=4)           # four copies, memory included
            for f in forks:
                await f.stop()
        finally:
            await sb.stop()

asyncio.run(main())
```

The same `demo.env` points E2B's SDKs at the machine's E2B gateway (`pip install e2b`, then [docs/E2B.md](docs/E2B.md)). Admin commands use `. /root/opendsec-ops/env`, then `opendsecctl status` and `opendsecctl --help`. To remove everything, run `deploy/quickstart.sh --uninstall` as root.

**Machines without internet access**: build an offline bundle on a machine that has it (`deploy/offline/build-bundle.sh`) and install from it with `./install.sh`, for one machine or a cluster: see [deploy/offline/README.md](deploy/offline/README.md).

## Deploy a cluster

### Layout

A cluster has two kinds of machines:

- **Control-plane nodes**: three of them, one per failure domain. They run the cluster-wide services.
- **Compute nodes**: as many as you need. They run sandboxes.

Around them you need:

- a shared file system for images;
- a TCP load balancer in front of the apiservers;
- an *ops machine* that holds the cluster's secrets and installs everything over ssh. It can be one of the control-plane nodes.

| Component | Runs on | Instances | Port (metrics) | State |
|---|---|---|---|---|
| `opendsec-iam` | control-plane nodes | 3 (or 5), Raft | 7001, Raft 7011 (9461) | `/var/lib/opendsec/iam`, local SSD |
| `opendsec-watcher` | control-plane nodes | 2–3 | 7002 (9462) | none |
| `opendsec-apiserver` | control-plane nodes, behind the LB | 2+ | 7100 (9463) | none; audit log in `/var/log/opendsec/audit` |
| `opendsec-fleet` | control-plane nodes | 3 | 7300 (9465) | releases in `/var/lib/opendsec/fleet`; desired state in IAM |
| Prometheus + Alertmanager | one control-plane node | 1 | 9090, 9093 | local |
| `opendsec-edge` | every compute node, as root | 1 per node | 7201 (9464) | `state_dir`, local NVMe |
| `opendsec-nodeagent` | every machine, as root | 1 per node | (9466) | none |
| node_exporter | every machine | 1 per node | 9100 | none |
| `opendsec-aether` / `opendsec-chronus` | inside each sandbox | per sandbox / session | — | — |

In a small cluster the control-plane services can share machines with edge: put several roles on one inventory line. One machine can also run everything, which is what `deploy/quickstart.sh` sets up.

### Requirements

- **All nodes**:
  - Linux x86_64 with systemd and cgroup v2, kernel 5.15 or newer (tested on Ubuntu 24.04 with kernel 6.8);
  - root ssh from the ops machine (key `/root/.ssh/opendsec-ops`, or set `OPENDSEC_SSH_KEY`);
  - a private network between the nodes.
- **Control-plane nodes**: 4 cores and 8 GB of RAM to start with, an SSD for IAM's data.
- **Compute nodes**:
  - `/dev/kvm` for microVMs: bare metal, or nested virtualization;
  - the edge's `state_dir` on a local NVMe file system (default `/data/opendsec-state`; XFS gives reflink copies);
  - the packages the edge needs (erofs-utils, e2fsprogs, nftables, iproute2) are installed by `opendsecops install`.
- **Shared file system**, mounted at `/mnt/opendsec-images` on every apiserver and edge node. It holds image layers and snapshots.
  - NFS 4.1+, CephFS or JuiceFS all work.
  - Root squash must be off.
  - With NFS, mount it with `vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev` in fstab. NFS 4.1 works too, but cannot find the holes of sparse files, so moving a memory snapshot to another node reads its whole disk and memory size (about twice as slow in our tests). `lookupcache=positive` stops the client from caching "file not found": without it, a node that looked for an image before it was registered could keep missing it for up to a minute.
  - Check the file system with `opendsecctl image store-check -store /mnt/opendsec-images` before you use it.
- **Load balancer**: plain TCP on port 7100; the apiservers terminate TLS themselves.
  - Health check: HTTP on port 9463, path `/readyz`.
  - Keep the client's source address if the load balancer can.
  - Its idle timeout must be at least 30 s: the apiservers ping idle connections every 20 s, which keeps quiet streams (batch creates, long commands) open.
- **Ops machine**: a clone of this repository, Go 1.27+, and ssh access to every node.

### Install

```sh
# On the ops machine, in the repository.
export OPENDSEC_OPS=/root/opendsec-ops            # holds the inventory, config, admin token and CA
mkdir -p -m 0700 $OPENDSEC_OPS

# 1. Build, and package a release with Firecracker, jailer and the guest kernel (deploy/deps.lock).
make build && deploy/prod/opendsecops release bin/

# 2. Describe the cluster: machines and roles, then the cluster config.
cp deploy/prod/inventory.example $OPENDSEC_OPS/inventory        # edit: names, ssh and private addresses, roles
cp deploy/prod/cluster.example.json $OPENDSEC_OPS/opendsec.json  # edit: the addresses of IAM, watcher, apiserver, fleet
printf 'dsk.admin.%s\n' "$(openssl rand -hex 16)" > $OPENDSEC_OPS/admin.token
chmod 0600 $OPENDSEC_OPS/admin.token

# 3. The cluster CA and a certificate for every component. Name the load balancer's
#    address or DNS name, so that it is in the apiservers' certificates.
deploy/prod/opendsecops certs api.opendsec.internal,10.0.0.10

# 4. Install on every node: user, release, config, certificates, units, node settings.
#    Nothing starts yet.
deploy/prod/opendsecops install all

# 5. Mount the shared file system at /mnt/opendsec-images on every apiserver and edge node (fstab).

# 6. Start everything in order (IAM, watcher, apiserver, fleet, edge) and wait until each is ready.
deploy/prod/opendsecops start all
deploy/prod/opendsecops status

# 7. Monitoring: node_exporter everywhere, Prometheus and Alertmanager on the node with the
#    "monitor" role, alerts to a webhook.
deploy/prod/opendsecops monitor https://alerts.example/hook
```

Each node receives only the CA certificate and its own components' keys. The admin token goes only to the IAM nodes, and the CA's private key never leaves the ops machine. Keep `$OPENDSEC_OPS` private and back it up.

### Hand over to the fleet service

The fleet service runs releases and configuration from then on: it upgrades in staged rollouts with automatic rollback, and it adds machines. Start the node agents and register what is running:

```sh
deploy/prod/opendsecops install-agent all
export PATH=$PATH:$OPENDSEC_OPS/current/bin      # opendsecctl
export OPENDSEC_ADDR=10.0.0.10:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
V=$(basename $(readlink $OPENDSEC_OPS/current))
opendsecctl fleet release push $OPENDSEC_OPS/releases/$V
opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json
opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release $V -config-gen 1
opendsecctl fleet node set node-b1 -domain b      # failure domains, used to spread rollouts
opendsecctl fleet nodes                           # every machine reporting, units ready
```

### First image and first caller

```sh
# As root on a node that mounts the image store (opendsecctl is in /usr/local/bin there),
# with OPENDSEC_ADDR and OPENDSEC_TOKEN as above and OPENDSEC_CA=/etc/opendsec/pki/ca.crt:
opendsecctl image import docker.io/library/python:3.12 -as root/py:3.12 -store /mnt/opendsec-images
# A private registry: the credentials `docker login` saved on this machine are used, or pass them:
echo "$HARBOR_TOKEN" | opendsecctl image import harbor.example.com/team/app:1.0 -as root/app:1.0 \
    -store /mnt/opendsec-images -username 'robot$ci' -password-stdin

opendsecctl project create root team-a -quota sandboxes=1000
opendsecctl principal create root/team-a trainer -kind agent        # prints the token once
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl grant root trainer layer.use                            # may use images under root/
```

Give the caller the load balancer's address, the token, `ca.crt` and [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

### Network

Open only TCP 7100 (the load balancer) to callers. Keep every other port listed above inside the private network:

- 7001, 7011, 7002, 7201 and 7300 carry mTLS traffic between the components;
- 9461–9466 and 9100 are metrics;
- 9090 and 9093 are for operators.

### Add machines, upgrade, operate

| Task | How |
|---|---|
| Add a compute node | mount the shared file system on it (fstab, as above), then `opendsecops add-node node-a2 <ssh addr> <private addr> edge=node-a2` and `opendsecctl fleet node accept node-a2 -roles edge=node-a2 -domain a`; `opendsecops monitor` again adds it to Prometheus |
| Upgrade | `make build && opendsecops release bin/`, then `opendsecctl fleet release push …` and `opendsecctl fleet rollout create -release <version>` |
| Change the config | `opendsecctl fleet config put opendsec.json`, then `opendsecctl fleet rollout create -config-gen <n>` |
| Maintain a node | `opendsecctl fleet node cordon <name>` … `uncordon`; `node evacuate` waits for its sandboxes to end |
| Back up IAM | a daily timer (03:00) on each IAM node writes `/var/backups/opendsec`; `opendsecops backup` takes one into the ops machine |

Before upgrading, read [CHANGELOG.md](CHANGELOG.md) and [docs/VERSIONING.md](docs/VERSIONING.md) (what stays compatible, supported upgrade paths, rollbacks). The service level objectives, how they are measured and the Prometheus rules behind them are in [docs/SLO.md](docs/SLO.md) (Chinese). [docs/OPERATIONS.md](docs/OPERATIONS.md) (Chinese) covers the rest: certificate renewal and CA rotation, replacing an IAM replica, disaster recovery, alerts and what to check for each. Component and configuration details are in [deploy/README.md](deploy/README.md). The Kubernetes manifests in `deploy/k8s` are experimental.

### Binaries

| Binary | Role |
|---|---|
| `opendsec-apiserver` | Stateless public gRPC API, admission and placement |
| `opendsec-iam` | Projects, quotas, principals, tokens; Raft-replicated |
| `opendsec-watcher` | Edge health, cluster snapshot, quota reconciliation |
| `opendsec-edge` | Node runtime: microVM, container, fncall and QEMU backends, networking |
| `opendsec-fleet` / `opendsec-nodeagent` | Releases, config and staged rollouts |
| `opendsec-aether` / `opendsec-chronus` | In-sandbox agent and shell sessions (static, mounted read-only) |
| `opendsecctl` | CLI: cluster, sandboxes, images, IAM, fleet, PKI |

## Use E2B's SDKs

The E2B gateway (`opendsec-e2b`, SPEC §37) serves E2B's API, so programs written for E2B's SDKs, and agent frameworks built on them, run on OpenDsec unchanged:

```sh
export E2B_API_URL=http://<gateway>:7400 E2B_SANDBOX_URL=http://<gateway>:7400 E2B_API_KEY=<OpenDsec token>
python -c 'from e2b import Sandbox; print(Sandbox.create().commands.run("echo hi").stdout)'
```

- Enable it with an `e2b` section in the cluster config: the gateways' addresses, the project sandboxes go to, and the templates, i.e. which image, backend and resources an E2B template id means (SDKs default to `base`). Then give a node the fleet role `e2b=<index>`. See docs/OPERATIONS.md. `deploy/quickstart.sh` sets one up on its machine.
- Supported: sandboxes (create, info, list, kill, timeout, pause, connect), commands (output, exit codes, background, stdin, signals, envs, cwd), PTYs, files (read, write, list, mkdir, rename, remove), servers on other ports of a sandbox (HTTP, streamed responses, WebSocket), which E2B's code interpreter uses, fork and snapshots (`fork()`, `create_snapshot()`, `Sandbox.create(snapshot_id)`; with memory on microVMs), autoPause, and network options (`allow_internet_access`, `allow_out`, `deny_out` of all traffic, `update_network()`). E2B's Python (sync and async) and JS/TS SDKs pass the gateway's acceptance check.
- E2B's code interpreter (`e2b_code_interpreter`) works with a template built by `deploy/e2b/build-code-interpreter.py` (Python kernel; a memory snapshot, so `Sandbox.create()` takes about 280 ms and the first `run_code` about 45 ms).
- Not yet: watching directories, signed file URLs, unauthenticated (browser) access to sandbox ports, building templates.
- **Moving from E2B**: [docs/E2B.md](docs/E2B.md) lists what works, what differs, and timings.

## Develop

```sh
make build        # bin/: every binary (static)
make test         # Go tests; run as root for the real container/microVM tests
make proto        # after editing proto/ (needs protoc)
./bin/opendsecctl cluster up -sim-edges 4   # an in-process cluster with simulated edges, no root needed
```

The tests that need KVM, root or a guest kernel skip without them. `OPENDSEC_TEST_STATE`, `OPENDSEC_BENCH` and related variables select the heavier ones (see SPEC).

## Status and limits

The project runs on a small production cluster (two bare-metal nodes plus a control VM). Known limits:

- High availability of the image store is up to the shared file system you choose. Check it with `opendsecctl image store-check`.
- A host reboot loses that node's sandboxes, paused microVMs included.
- Registry credentials kept by a docker credential helper (`credsStore`, `credHelpers`) are not read; pass them with `-username` and `-password-stdin`.
- PCI passthrough (VFIO) in the QEMU backend has not been tested on real devices.
- Most of the documentation is in Chinese. English translations are welcome.

## License

- **The server and tools** (everything not listed below): [GNU AGPL-3.0](LICENSE). You can run, modify and redistribute OpenDsec freely, in your own data center or cloud account. If you modify it and let others use it over a network, the AGPL asks you to offer them the source of your modified version.
- **The client parts: Apache-2.0**, so that programs using OpenDsec are not bound by the AGPL. These are the Python SDK (`sdk/python/`), the Go client (`pkg/`), and the API definitions and generated code (`proto/`, `gen/`). Each of these directories has its own LICENSE.
- **Commercial license**: for uses the AGPL does not allow (keeping a modified version closed, offering OpenDsec as a service without publishing your changes), and for the enterprise edition. Contact zhyb1528@aliyun.com.

See [NOTICE](NOTICE). Release packages also contain Firecracker (Apache-2.0) and a Linux guest kernel (GPL-2.0). Contributions need a signed CLA, see [CONTRIBUTING.md](CONTRIBUTING.md).
