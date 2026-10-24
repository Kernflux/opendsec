# Cluster deployment

This page deploys a production cluster from scratch: planning, infrastructure, installation, handing over to fleet, the first caller, and acceptance. Day-to-day operations afterwards (upgrades, config changes, new machines, certificates, failures) are in the [operations manual](OPERATIONS.md).

The procedure was verified as written on a fresh cluster of 3 control-plane nodes, 3 compute nodes, NFS and HAProxy; installation took about 8 minutes (preparing the machines not included).

## 1. Planning

### Machines

| Role | Count | Suggested size | Runs |
|---|---|---|---|
| Control-plane node | 3 (one per failure domain) | 4 cores, 8 GB to start, local SSD | one replica each of IAM, watcher, apiserver and fleet; one of them also runs Prometheus and Alertmanager |
| Compute node | as needed | bare metal or a cloud VM with nested virtualization; local NVMe for sandbox state; memory decides how many sandboxes fit | edge, node agent |
| Ops machine | 1 (may be a control-plane node) | any | `opendsecops`; holds all of the cluster's secrets |

- The cluster keeps creating and serving sandboxes with any one control-plane node down. IAM is a 3-replica Raft group and tolerates one failure.
- When a compute node fails, its sandboxes are lost, and new ones go to other nodes.
- In a small cluster, control-plane services can share machines with edges (several roles on one inventory line).

### Components and ports

| Component | Where | Instances | Port (metrics) | State |
|---|---|---|---|---|
| `opendsec-iam` | control-plane nodes | 3 (or 5), Raft | 7001, Raft 7011 (9461) | `/var/lib/opendsec/iam`, local SSD |
| `opendsec-watcher` | control-plane nodes | 2–3 | 7002 (9462) | none |
| `opendsec-apiserver` | control-plane nodes, behind the load balancer | 2+ | 7100 (9463) | none; audit log in `/var/log/opendsec/audit` |
| `opendsec-fleet` | control-plane nodes | 3 | 7300 (9465) | releases in `/var/lib/opendsec/fleet`; desired state in IAM |
| Prometheus, Alertmanager | one control-plane node | 1 | 9090, 9093 | local |
| `opendsec-edge` | every compute node, as root | 1 per node | 7201 (9464) | `state_dir`, local NVMe |
| `opendsec-nodeagent` | every machine, as root | 1 per node | (9466) | none |
| `opendsec-e2b` (optional) | any node | as needed | 7400 (9467) | none |
| node_exporter | every machine | 1 per node | 9100 | none |

**Network**: open only the load balancer's 7100 to callers (and 7400 for the E2B SDK). Keep every other port inside the private network: 7001, 7011, 7002, 7201 and 7300 carry mTLS traffic between components, 9461–9467 and 9100 are metrics, 9090 and 9093 are for operators.

## 2. Infrastructure

### 2.1 Every node

- Linux x86_64, systemd, cgroup v2, kernel 5.15 or newer (verified on Ubuntu 24.04 with kernel 6.8).
- A private network between the nodes.
- Root ssh from the ops machine to every node, by default with the key `/root/.ssh/opendsec-ops` (`OPENDSEC_SSH_KEY` changes it):

```sh
ssh-keygen -t ed25519 -N '' -f /root/.ssh/opendsec-ops
# add /root/.ssh/opendsec-ops.pub to root's authorized_keys on every node
```

- Compute nodes: `/dev/kvm` present (`ls -l /dev/kvm`); local NVMe mounted at `/data` (the sandbox state directory defaults to `/data/opendsec-state`; XFS allows faster reflink copies). The packages the edge needs (erofs-utils, e2fsprogs, nftables, iproute2) are installed for you.

### 2.2 Shared storage

Mounted at `/mnt/opendsec-images` on every apiserver and edge node. A NAS (NFS), CephFS or JuiceFS all work:

- **Root squash must be off** (on a NAS, set the permission group to "no root restriction").
- NFS mount options, in `/etc/fstab`:

```
<nas address>:/<export path>  /mnt/opendsec-images  nfs4  vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev  0 0
```

An NFS server on a Linux machine (for tests or small clusters):

```sh
apt install -y nfs-kernel-server
mkdir -p /srv/opendsec-images
echo '/srv/opendsec-images 10.0.0.0/16(rw,sync,no_subtree_check,no_root_squash)' >> /etc/exports
exportfs -ra
```

Why these options: [Images and snapshots §5](IMAGES.md).

### 2.3 Load balancer

TCP forwarding of port 7100 to every apiserver:

- plain TCP, not HTTP or gRPC: the apiservers terminate TLS themselves;
- HTTP health check on port 9463, path `/readyz`, every 2 s, unhealthy after 2 failures;
- an idle timeout of at least 30 s: the apiservers ping idle connections every 20 s;
- keep the client's source address if the load balancer can (otherwise failed authentications are all charged to the load balancer's address).

HAProxy (appended to `/etc/haproxy/haproxy.cfg`):

```
frontend opendsec_api
    bind 10.0.0.10:7100
    mode tcp
    timeout client 120s
    default_backend opendsec_apiservers

backend opendsec_apiservers
    mode tcp
    balance roundrobin
    timeout server 120s
    option httpchk GET /readyz
    default-server check port 9463 inter 2s fall 2 rise 2
    server ctl-1 10.0.0.11:7100
    server ctl-2 10.0.0.12:7100
    server ctl-3 10.0.0.13:7100
```

In a cloud, use the provider's layer-4 load balancer (TCP listener) with the health check above.

A load balancer is optional: callers can put every apiserver's address in `OPENDSEC_ADDR`, comma separated, and the SDK round-robins and avoids one that is down.

### 2.4 Ops machine

```sh
apt update && apt install -y make git
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz
export PATH=$PATH:/usr/local/go/bin
git clone https://github.com/kernflux/opendsec && cd opendsec
export OPENDSEC_OPS=/root/opendsec-ops
mkdir -p -m 0700 $OPENDSEC_OPS
```

`$OPENDSEC_OPS` will hold the inventory, cluster config, admin token and the CA's private key. **It is the key to the whole cluster**: give only the people who need it access, and back it up somewhere safe.

## 3. Installation

### 3.1 Package a release

```sh
make build && deploy/prod/opendsecops release bin/
```

Packs the binaries, systemd units, Firecracker, jailer and the guest kernel (downloaded and checked per `deploy/deps.lock`) into a release under `$OPENDSEC_OPS/releases/<version>`.

- If the guest kernel cannot be downloaded: `OPENDSEC_KERNEL=<kernel file> deploy/prod/opendsecops release bin/`, or put the file into `~/.cache/opendsec-deps/vmlinux-6.1.167-opendsec.2` (its sha256 must match deps.lock).
- For a containers-only cluster: `OPENDSEC_DEPS_SKIP=guest-kernel`.

### 3.2 Describe the cluster

```sh
cp deploy/prod/inventory.example $OPENDSEC_OPS/inventory
cp deploy/prod/cluster.example.json $OPENDSEC_OPS/opendsec.json
```

**inventory**: one machine per line: name, ssh address, private address, roles.

```
ctl-1     203.0.113.11   10.0.0.11   iam=0 watcher=0 apiserver=0 fleet=0
ctl-2     203.0.113.12   10.0.0.12   iam=1 watcher=1 apiserver=1 fleet=1
ctl-3     203.0.113.13   10.0.0.13   iam=2 watcher=2 apiserver=2 fleet=2 monitor
node-a1   203.0.113.21   10.0.1.21   edge=node-a1
node-b1   203.0.113.22   10.0.1.22   edge=node-b1
node-c1   203.0.113.23   10.0.1.23   edge=node-c1
```

- Roles: `iam=<replica id>`, `watcher=<id>`, `apiserver=<index>`, `fleet=<id>`, `edge=<edge id>`, `e2b=<index>`, `monitor` (Prometheus and Alertmanager go on this machine).
- Every IAM replica, watcher, apiserver and edge in the cluster config must appear on exactly one inventory line.
- The ssh address `local` runs commands on this machine without ssh.

**opendsec.json**: replace the example's addresses with your private addresses (the IAM, watcher, apiserver and fleet sections), then adjust:

- `iam.root_quota`: the whole cluster's quota;
- `admission`: rate limits (the example raises them to 20000 creations and 100000 calls per second);
- `network.rule_sets`, `network.default_rules`: rule sets and default rules (the example has no default rules, so sandboxes reach no network by default);
- `edge_template.backends`: which backends compute nodes offer, how many sandboxes each, default disk sizes;
- `edges`: nodes that need their own settings. New machines need no entry; `edge_template` covers them.

Every field: [Configuration reference](CONFIGURATION.md). Validate the result:

```sh
bin/opendsecctl pki init -config $OPENDSEC_OPS/opendsec.json -out $(mktemp -d)
```

**Admin token**:

```sh
printf 'dsk.admin.%s\n' "$(openssl rand -hex 16)" > $OPENDSEC_OPS/admin.token
chmod 0600 $OPENDSEC_OPS/admin.token
```

### 3.3 Certificates

```sh
deploy/prod/opendsecops certs api.opendsec.internal,10.0.0.10
```

Creates the cluster CA (its private key stays in `$OPENDSEC_OPS/pki`) and every component's certificate. The argument is the load balancer's address or DNS name, which goes into the apiserver certificates; every apiserver certificate also carries `api.opendsec.internal` (the name the SDK checks when given several addresses).

### 3.4 Install on every node

```sh
deploy/prod/opendsecops install all
```

On each node: creates the user and directories, delivers the release, config, certificates and systemd units, installs the packages needed, and applies node settings (sysctl, kernel modules, NFS client identity, log filtering). **Nothing starts yet.**

Each node gets only the CA certificate and its own components' certificates and keys; the admin token goes only to the IAM nodes.

### 3.5 Mount the shared storage

On every apiserver and edge node, add the fstab line from §2.2 and mount it, then check on one of them:

```sh
mount /mnt/opendsec-images
/opt/opendsec/current/bin/opendsecctl image store-check -store /mnt/opendsec-images
```

Every required item must be `ok`. The NFS client identity is set by `install` and takes effect on a fresh mount: if a node mounted the share before `install`, reboot it once.

### 3.6 Start

```sh
deploy/prod/opendsecops start all
deploy/prod/opendsecops status
```

Starts IAM → watcher → apiserver → E2B gateway → fleet → edge in that order, waiting for each `/readyz` to return 200. IAM bootstraps with the admin token on its first start. `status` shows whether each component is ready and the current IAM leader, and exits 1 if any is not ready.

### 3.7 Monitoring

```sh
deploy/prod/opendsecops monitor https://alerts.example.com/hook
```

Installs node_exporter everywhere, and Prometheus and Alertmanager on the `monitor` node, loads the alert rules (`deploy/monitoring/alerts.yml`), and sends alerts to the webhook. Without a webhook, alerts go nowhere. Metrics and alerts: [Monitoring and alerts](MONITORING.md).

## 4. Hand over to fleet

From here on, upgrades, config changes and new machines go through fleet in staged rollouts with automatic rollback.

```sh
deploy/prod/opendsecops install-agent all              # start a node agent on every machine
export PATH=$PATH:$OPENDSEC_OPS/current/bin
export OPENDSEC_ADDR=10.0.0.10:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
V=$(basename $(readlink $OPENDSEC_OPS/current))
opendsecctl fleet release push $OPENDSEC_OPS/releases/$V
opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json -note "initial"
opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release $V -config-gen 1
opendsecctl fleet node set node-a1 -domain a           # failure domains: rollouts spread over them, at most half a batch per domain
opendsecctl fleet node set node-b1 -domain b
opendsecctl fleet node set node-c1 -domain c
opendsecctl fleet nodes
```

In `fleet nodes`, every machine should be reporting (`SEEN` a few seconds ago), with `RUNNING` equal to `RELEASE` and every `UNITS` ready.

After the handover, `opendsecops upgrade` and `restart` refuse to run; upgrades go through `opendsecctl fleet rollout` ([operations manual §6](OPERATIONS.md)). `opendsecops` stays for certificates, new machines and emergencies.

## 5. First image and first caller

As root on a node that mounts the image store:

```sh
export OPENDSEC_ADDR=10.0.0.10:7100 OPENDSEC_TOKEN=<admin token> OPENDSEC_CA=/etc/opendsec/pki/ca.crt
opendsecctl image import docker.io/library/python:3.12 -as root/py:3.12 -store /mnt/opendsec-images
```

Onboard a team (on the ops machine):

```sh
opendsecctl project create root team-a -quota sandboxes=1000
opendsecctl principal create root/team-a trainer -kind agent       # the token is shown only in this output
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl grant root trainer layer.use                           # may use the images under root/
```

Give the caller the load balancer's address, the token (separately, over a secure channel), `$OPENDSEC_OPS/pki/ca.crt`, the SDK (`sdk/python` or a packaged wheel) and the [caller guide](USER_GUIDE.md).

## 6. Acceptance

```sh
# smoke test: one sandbox per backend, running python3 -c 'print(6*7)'
OPENDSEC_TOKEN=<trainer's token> OPENDSEC_PROJECT=root/team-a \
    .claude/skills/opendsec-deploy/scripts/smoke.sh root/py:3.12 container,microvm

# features: creation, commands, files, network, pause, fork, batches, images, one by one
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
OPENDSEC_TOKEN=<trainer's token> OPENDSEC_PROJECT=root/team-a .venv/bin/python sdk/python/examples/test_features.py

# load test: 600 s at concurrency 8; prints successes, failures and latency percentiles at the end
OPENDSEC_TOKEN=<trainer's token> OPENDSEC_PROJECT=root/team-a .venv/bin/python sdk/python/examples/load_test.py 600 8
```

While the load test runs, try a failure drill: hard-reset a control-plane node, or stop the IAM leader's process, and check that the load test reports 0 failures.

## 7. Data centers without internet access

Use the offline bundle: build it on a connected machine with `deploy/offline/build-bundle.sh` and unpack it on the ops machine. The steps are the same as above, except:

- system packages come from the bundle's `debs/`: set `OPENDSEC_DEBS=<unpacked dir>/debs`;
- the release is the bundle's own: `<unpacked dir>/deploy/prod/opendsecops release-add <unpacked dir>/release/<version>`;
- images are imported from the bundle's `images/`, e.g. `opendsecctl image import <unpacked dir>/images/python-3.12.tar -as root/py:3.12 -store /mnt/opendsec-images`;
- the SDK and the E2B SDK come from the bundle's `wheels/`: `pip install --no-index --find-links wheels opendsec`.

Details in `deploy/offline/README.md`.

## 8. Next

- Upgrades, config changes, new machines, maintenance, certificates, failures: [operations manual](OPERATIONS.md)
- [Monitoring and alerts](MONITORING.md)
- Service levels: [SLO](SLO.md)
- Hardening: [Security model](SECURITY_MODEL.md)
- E2B SDK access: [operations manual §4, "E2B gateway"](OPERATIONS.md)
