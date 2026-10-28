# Single-node install in detail

`deploy/quickstart.sh` installs every OpenDsec component on one Linux machine. It uses the same tooling as a multi-node cluster (`opendsecops`), so the single-node cluster can later be upgraded and grow more machines. This page covers its requirements and options, what it does, where things end up, and common problems. The short version is [Get started](https://kernflux.github.io/en/docs/quickstart).

## 1. Requirements

| Item | Requirement | Check |
|---|---|---|
| Architecture | x86_64 | `uname -m` |
| Kernel | 5.15 or newer (fully verified on Ubuntu 24.04) | `uname -r` |
| Init | systemd | `ls /run/systemd/system` |
| cgroups | v2 (unified) | `stat -fc %T /sys/fs/cgroup` prints `cgroup2fs` |
| File systems | overlay | `grep overlay /proc/filesystems` |
| Commands | `curl`, `tar`, `sha256sum`, `mkfs.ext4`, `ip`, `awk` (in Ubuntu by default) | — |
| Build | Go 1.27 or newer and `make` (not needed with `--release`) | `go version` |
| Privileges | root | — |
| Ports | 7001, 7002, 7011, 7100, 7201, 7400, 9461–9464 and 9467 free | `ss -ltn` |
| microVMs | `/dev/kvm`: bare metal, or a cloud VM with nested virtualization. Without it, containers only | `ls /dev/kvm` |
| Resources | 4 cores, 8 GB of RAM and 40 GB of disk or more recommended | — |

The script first checks each item, printing `[ok]` or `[x]`, and stops on any `[x]` before changing anything.

## 2. Installing

```sh
sudo -i                                                   # everything below as root
apt update && apt install -y make git python3-venv
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz
git clone https://github.com/kernflux/opendsec && cd opendsec
deploy/quickstart.sh
```

On a fresh 8-core VM this takes 8 to 11 minutes, mostly building.

### Options

| Option | Meaning |
|---|---|
| (none) | container and microVM with `/dev/kvm`, container only without. The guest kernel is downloaded from the GitHub release and checked against the sha256 in `deploy/deps.lock` |
| `--no-microvm` | Containers only |
| `--kernel FILE` | Use this guest kernel instead of downloading one |
| `--build-kernel` | Build the guest kernel (a few more minutes; needs `build-essential flex bison bc libelf-dev libssl-dev`) |
| `--release DIR` | Install a packaged release directory instead of building (offline bundles use this) |
| `--uninstall` | Remove everything; see §6 |
| `--help` | Usage |

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `OPENDSEC_IMAGE` | `docker.io/library/python:3.12` | Base image to import; may be an image file |
| `OPENDSEC_ADDR_IP` | the default route's source address | Address the components listen on. Set it on a machine with several interfaces, or for access from other machines |
| `OPENDSEC_OPS` | `/root/opendsec-ops` | Ops directory |
| `OPENDSEC_DEBS` | — | An offline bundle's package repository (`debs/`), used for system packages instead of the apt sources |

For access from this machine only: `OPENDSEC_ADDR_IP=127.0.0.1 deploy/quickstart.sh`.

## 3. What the script does

1. **Checks the machine** (the items in §1) and settles the node name (the host name), address, sandbox state directory (`/data/opendsec-state` if `/data` is a mount point, else `/var/lib/opendsec/edge-state`) and whether to install microVMs.
2. **Builds and packages**: `make build`, then `opendsecops release` packs the binaries, systemd units, Firecracker, jailer and the guest kernel into a release under `/root/opendsec-ops/releases/<version>`.
3. **Writes the config**: an inventory (this machine, ssh address `local`), a cluster config `opendsec.json` and an admin token in the ops directory. The config:
   - a single-replica IAM (Raft, so it can grow to three later), a root quota of 10000 sandboxes, tokens valid for at most 90 days;
   - the image store at `/mnt/opendsec-images` (a local directory);
   - a `pypi` rule set and **no default network rules: sandboxes reach no network by default**;
   - the container backend (at most 2000 sandboxes, 1 GB default disk); with KVM, the microvm backend too (at most 1000, 2 GB default disk, EROFS image disks, pmem and memory reclaim on);
   - an E2B gateway for project `root/demo`, with template `base` = `root/py:3.12`.
4. **Issues certificates and installs**: `opendsecops certs` creates the CA and component certificates; `opendsecops install all` creates the user and directories, delivers the release, config, certificates and systemd units, and applies node settings (sysctl, modules, NFS client identity and so on).
5. **Starts** everything with `opendsecops start all`, in the order IAM → watcher → apiserver → E2B gateway → edge, waiting for each to be ready.
6. **Imports an image**: `OPENDSEC_IMAGE` as `root/py:3.12`.
7. **Creates a project and a caller**: project `root/demo` (quota 100 sandboxes), principal `demo`, granted `sandbox.create`, `sandbox.operate` and `layer.publish` on `root/demo` and `layer.use` on `root`.
8. **Checks**: as `demo`, creates one container and one microVM sandbox, runs `python3 -c 'print(6*7)'`, expects 42, and stops them.

Finally it prints how the administrator and the caller use the cluster.

## 4. Afterwards

### Environments

```sh
. /root/opendsec-ops/env         # administrator: admin token, project root
. /root/opendsec-ops/demo.env    # caller: a token for root/demo; also sets E2B_API_URL, E2B_SANDBOX_URL, E2B_API_KEY
```

### Files and directories

| Path | Contents |
|---|---|
| `/root/opendsec-ops/` | Ops directory: inventory, `opendsec.json`, `admin.token`, `pki/` (the CA private key included), `releases/`, `env`, `demo.env`. **It holds secrets: keep it private and back it up** |
| `/opt/opendsec/current` | The current release (pointing at `/opt/opendsec/releases/<version>`): `bin/`, `vm/` (guest kernel), `agents/`, `units/` |
| `/usr/local/bin/opendsec-*`, `opendsecctl` | Links to the current release's binaries |
| `/etc/opendsec/` | This machine's config, certificates and `admin.token` |
| `/var/lib/opendsec/iam` | IAM data (Raft log and snapshots) |
| `/data/opendsec-state` or `/var/lib/opendsec/edge-state` | Sandbox disks, snapshots and records |
| `/mnt/opendsec-images` | Image store |
| `/var/log/opendsec/audit` | Audit log |
| `/var/backups/opendsec` | Daily IAM backups |

### Services

| Unit | Port (metrics, `/readyz`) |
|---|---|
| `opendsec-iam@0` | 7001, Raft 7011 (9461) |
| `opendsec-watcher@0` | 7002 (9462) |
| `opendsec-apiserver@0` | 7100 (9463) |
| `opendsec-edge` | 7201 (9464) |
| `opendsec-e2b@0` | 7400 (9467) |
| `opendsec-iam-backup.timer` | backs up IAM daily at 03:00 |

```sh
systemctl status 'opendsec-*'
journalctl -u opendsec-edge -f
deploy/prod/opendsecops status          # is every component ready
opendsecctl status                      # cluster snapshot (after . /root/opendsec-ops/env)
```

### Access from other machines

- Install with `OPENDSEC_ADDR_IP` set to an address other machines reach (by default, the default route's address).
- Give callers `/root/opendsec-ops/pki/ca.crt`, a token and the address; they set `OPENDSEC_ADDR=<address>:7100` and `OPENDSEC_CA=<path to ca.crt>`.
- Open only 7100 in the firewall (and 7400 for the E2B SDK).

### Rebooting

Every service starts at boot. A reboot loses all sandboxes (paused ones included); images, projects, principals and tokens are kept.

## 5. Upgrading

A single-node cluster has no fleet; upgrade it with `opendsecops`:

```sh
cd opendsec && git pull
make build && deploy/prod/opendsecops release bin/
deploy/prod/opendsecops upgrade <new version>          # the version is in the previous command's output
deploy/prod/opendsecops status
```

Components restart one at a time; running sandboxes are unaffected. To go back: `deploy/prod/opendsecops rollback <old version>`. Read the "Breaking" section of `CHANGELOG.md` before upgrading.

## 6. Uninstalling

```sh
deploy/quickstart.sh --uninstall
```

Stops and disables every service, kills leftover sandboxes, removes the nftables tables, network interfaces and namespaces and mounts, and deletes `/etc/opendsec`, `/opt/opendsec`, `/var/lib/opendsec`, `/var/log/opendsec`, `/var/backups/opendsec`, the ops directory, the image store and the sandbox state directory.

Kept: the node settings (`/etc/sysctl.d`, udev rules, `/etc/modules-load.d`, networkd files) and software you installed yourself, such as Go and make.

## 7. Common problems

| Symptom | Cause and fix |
|---|---|
| `[x] command make` | `apt install -y make` |
| `[x] Go 1.27+ to build` | Install Go as in §2, or build elsewhere and copy `bin/` here |
| `[x] cgroup v2` | The system still uses cgroup v1: add `systemd.unified_cgroup_hierarchy=1` to the kernel command line and reboot |
| `[x] port 7100 is in use` | Another program holds the port, or an earlier install: `--uninstall` first |
| `[x] /root/opendsec-ops already holds a cluster` | An earlier install: `--uninstall` first, or manage the existing cluster with `opendsecops` |
| `warning: no /dev/kvm: containers only` | No KVM on this machine. Enable nested virtualization on the cloud VM, or use bare metal |
| `could not fetch the guest kernel pinned in deploy/deps.lock` | GitHub is unreachable: `--kernel FILE`, `--build-kernel` or `--no-microvm` |
| Importing `python:3.12` is slow or fails | Docker Hub is slow from here: point `OPENDSEC_IMAGE` at a mirror, or `docker save` the image to a file and pass its path |
| `python3 -m venv` says ensurepip is unavailable | `apt install -y python3-venv` |
| The final check says `... sandbox ... python printed '...', want 42` | The sandbox was created but the command did not print the expected output: look at `journalctl -u opendsec-edge` and `opendsecctl status`, then run `opendsecctl exec <id> python3 -c 'print(6*7)'` yourself to see the error |
| microVM creation fails | `journalctl -u opendsec-edge` has the reason; check `ls -l /dev/kvm`; on a cloud VM, check nested virtualization is on |

More in [Troubleshooting](TROUBLESHOOTING.md).
