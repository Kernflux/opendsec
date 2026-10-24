# Troubleshooting

Find the symptom, then the cause and the fix. Every entry comes from a problem we actually hit. If yours is not here, collect the information in §1 and [open an issue](https://github.com/Kernflux/opendsec/issues).

## 1. Collect this first

```sh
opendsecctl version                                   # client version
deploy/prod/opendsecops status                        # is every component ready (ops machine)
deploy/prod/opendsecops versions                      # versions each component runs
opendsecctl status                                    # cluster snapshot: each edge's health, capacity, pressure
opendsecctl fleet nodes                               # with fleet: each machine's state
journalctl -u 'opendsec-*' -p warning --since -1h     # on the nodes: warnings and errors of the last hour
curl -s <node>:9463/readyz                            # the reason when not ready (ports per role: Monitoring and alerts)
```

When a call fails, note the error's `reason` and full message, the time and the sandbox id. The first part of a sandbox id is its node: look at `journalctl -u opendsec-edge` there.

## 2. Installation

| Symptom | Cause | Fix |
|---|---|---|
| quickstart reports `[x] command make`, `[x] Go 1.27+` | A fresh machine without build tools | See [Single-node install §2](INSTALL.md) |
| `apt install` says `has no installation candidate` | Fresh cloud images have no package lists | `apt update` first |
| `python3 -m venv` says ensurepip is unavailable | `python3-venv` is missing | `apt install -y python3-venv` |
| `pip install` says externally-managed-environment | Ubuntu 24.04 keeps pip out of the system Python | Use a virtual environment: `python3 -m venv .venv && .venv/bin/pip install ...` |
| `could not fetch the guest kernel pinned in deploy/deps.lock` | GitHub releases are unreachable | `--kernel FILE`, `--build-kernel` or `--no-microvm`; for clusters, `OPENDSEC_KERNEL=<file>` |
| `[x] port 7100 is in use`, `already holds a cluster` | An earlier install | `deploy/quickstart.sh --uninstall`, then install again |
| IAM fails to start; its log calls the admin token a placeholder | The config still has the example's `change-me` | Generate a real token (`dsk.admin.$(openssl rand -hex 16)`) |
| Config validation says `zone ... must be "onprem" or "cloud"` | `edges` or `edge_template` has another `zone` | Only these two values are allowed |
| edge fails to start: `erofs_images needs mkfs.erofs` | The node lacks erofs-utils | `apt install erofs-utils`; newer `opendsecops install` installs it |
| `opendsecops release` cannot download the kernel | As above, GitHub unreachable | Set `OPENDSEC_KERNEL`, or put the file into `~/.cache/opendsec-deps/` |
| ssh never returns (the ops machine running remote commands) | A background process on the node is still tied to the session | `ssh -f host 'setsid nohup cmd > log 2>&1 < /dev/null &'` |

## 3. Creating sandboxes

| Error | Cause | Fix |
|---|---|---|
| `quota_exceeded: root/team-a: sandboxes 100+1 > 100` | The project's (or an ancestor's) quota is used up | Stop sandboxes you no longer need (find them with `list_sandboxes`), or ask for more quota. The message names the level and key |
| `no_capacity` | Every candidate node is full, under memory, disk or CPU pressure, or draining | `opendsecctl status`: look at each node's `alloc`, `under_pressure`, `draining`; add capacity or retry later |
| Every creation is `no_capacity` though the edges are healthy | An edge's `zone` is not `onprem` (older versions did not check) | Set it to `onprem` |
| `invalid: ... ttl_max ... exceeds` | The requested lifetime is over `max_ttl_max_s` | Ask for less, or have the administrator raise the limit |
| `invalid: backend "microvm" ...` / unknown backend | The cluster lacks that backend (nodes without KVM, say) | `opendsecctl status` shows each node's `backends` |
| `not_found: image ...` | A typo in the image name, or the image was never imported | `opendsecctl image list -project root` |
| An edge reports `image ... not found` for about a minute after the image was registered | The NFS client cached "file not found" | Add `lookupcache=positive` to the NFS mount options |
| `forbidden: ... lacks sandbox.create on ...` | No permission to create in the project | The project admin grants it |
| `forbidden: ... lacks layer.use on root` | No permission to use the image's project | `grant root <principal> layer.use` |
| `invalid: memory ... snapshot` / creating from a snapshot fails | `memory_limit_mb` differs from the snapshot's | Use the snapshot's memory size |
| Creating from a snapshot keeps waiting | The snapshot is still being published to the store (made moments ago, used on another node) | Wait for the publish; a slow store makes it take longer |
| Only some nodes can use a snapshot | Snapshots go only to nodes with the same Firecracker version | Make snapshots again after upgrading Firecracker |
| Batch creations through a load balancer fail with `Stream removed`; the load balancer logs `cD` | The load balancer's idle timeout cut a quiet stream | Set the idle timeout to 30 s or more; newer servers ping every 20 s |
| `rate_limited` | Over the per-principal rate | Back off and retry; for batches use `run_sandboxes` (the server queues them and they never fail on the rate) |

## 4. Commands and files

| Symptom | Cause | Fix |
|---|---|---|
| `invalid: sandbox ... is STOPPED` | The sandbox stopped: stopped by a caller, or it reached its idle timeout or lifetime | `get_sandbox` shows the `message` (e.g. `idle timeout (ttl_running_stop) reached`); raise the timeouts if you need longer |
| `not_found` | The sandbox was cleaned up (10 minutes after it ended), or its node failed or rebooted | A node reboot loses its sandboxes; create new ones |
| `ShellResult.timed_out` is True | The command ran past its `timeout` | Raise `timeout`, or use a background command and `get_output` |
| Output incomplete, `truncated` is True | One call returns at most 16 MB per stream | Fetch the rest with `get_output(cmd_id, stdout_offset=...)` |
| `dropped_bytes` above 0 | The output exceeded the 64 MB per-stream record limit | Write the output to a file and read it in pieces |
| Writing or reading files over 4 MB fails with `quota_exceeded: grpc: received message larger than max` | In older code a message was limited to 4 MB (the first entry under "Fixed" in CHANGELOG 0.11.0 fixed it) | Upgrade; meanwhile read and write in pieces under 3 MB |
| A command printing more than 4 MB fails as a whole | As above | As above; meanwhile redirect the output to a file and read it in pieces |
| `opendsecctl exec $ID python3 -c "'print(1)'"` prints nothing | 0.11 changed how `exec` handles arguments, and the old workaround's extra quotes now reach Python | Write `opendsecctl exec $ID python3 -c 'print(1)'` |
| Arguments of `exec` are taken as opendsecctl's options | The command has arguments starting with `-` | Put `--` before it: `opendsecctl exec $ID -- ls -la` |
| A session of an unprivileged user cannot write system directories | The session runs as its `user` | Expected; run root work in another session |
| Another `user` for the same session had no effect | The session's user was fixed by its first command | Use a new session name |

## 5. Network

See [Network policy §6](NETWORK.md). The two most common:

- A name does not resolve: the domain is not allowed (the DNS proxy answers "no such domain" when no rule matches).
- An internal service times out: private addresses need an explicit address or network rule, and private addresses a domain resolves to are always blocked.

## 6. microVMs

| Symptom | Cause | Fix |
|---|---|---|
| Nodes do not offer the microvm backend | No `/dev/kvm` | Bare metal, or nested virtualization |
| Every resume after a pause fails (Ubuntu 24.04, kernel 6.8.0-1xx) | This kernel kills processes started later in a cgroup that has been through `cgroup.kill`. Fixed in the code of 2026-10-24 (CHANGELOG 0.11.0, "Fixed") | Upgrade OpenDsec |
| VMs never come up; the log has `connect: invalid argument` | The state directory's path is too long: vsock's unix socket path exceeds 108 bytes | Use a shorter `state_dir` |
| The node runs short of memory | VMs do not hand memory back to the host | Turn on `free_page_reporting`, `cold_age_s` and `image_pmem` (needs OpenDsec's guest kernel); lower `paused_mem_charge` so paused VMs count for less |
| Creating from a memory snapshot on another node is slow | NFS 4.1 cannot find the holes of sparse files and reads the whole memory file | Mount NFS with `vers=4.2` (`umount -l`, then `mount`) |

## 7. Images

| Symptom | Cause | Fix |
|---|---|---|
| `image import` fails halfway with `context deadline exceeded` | Older CLIs had a 5-minute overall limit | Upgrade; imports now have no overall limit |
| `image import ./x.tar` tries to download from `registry-1.docker.io` | Older CLIs took a missing local file for an image name | Check the path; newer CLIs report the missing file |
| `image import` fails on permissions | Not root, or the store has root squash on | Run as root on a node that mounts the store; turn root squash off on the NAS |
| `store-check` fails a required item | The file system does not meet the requirements | Adjust the NAS (root squash, hard links, xattrs, …) for the failing item |
| The image store keeps growing | Deleting an image only removes its registration | Run `opendsecctl image gc` regularly |
| The NFS server logs `client attached/detached` over and over | Nodes share an NFS client identity (same host name) | `deploy/node/install.sh` sets the identity from machine-id; reboot the nodes for it to take effect |

## 8. Cluster and upgrades

| Symptom | Cause | Fix |
|---|---|---|
| `too many colons in address` | opendsecctl before 0.11 does not take comma-separated addresses | Upgrade, or give a single address for now |
| TLS says `not api.opendsec.internal` with several addresses | Older certificates lack that name | `opendsecops certs <names>` to reissue → `push-config all` → rolling restart |
| A few calls fail with `unknown edge` during an upgrade | A restarted watcher does not yet know some edges. Fixed in the code of 2026-10-24; it can still happen a few times while upgrading from an older version | Retry; it stops once the upgrade is done |
| `opendsecops upgrade` says `this cluster has fleet replicas` | The cluster is run by fleet | Use `opendsecctl fleet rollout create` |
| A rollout paused with a machine pinned | The machine did not become ready after upgrading and was rolled back | `fleet rollout status -steps` and the machine's logs for the cause; after fixing it, `fleet node unpin`, then resume or roll back |
| A rollout hangs after roles were added to two machines at once | fleet before 2026-10-23 made them wait for each other | Add roles one machine at a time: `fleet node set`, then `fleet node sync` |
| A config change did not reach the E2B gateway | Older `opendsecops restart` skipped the gateway | Upgrade; or `systemctl restart opendsec-e2b@<index>` on that machine |
| The disk alert keeps firing on machines with small disks | Older alert rules used a fixed threshold | Use the new `alerts.yml` (alerts below 10% free); `opendsecops monitor` reloads it |
| `OpenDsecEdgeUnhealthy` | The edge stopped, the machine is down, or the network is cut | Once back, the edge re-adopts sandboxes still running (unless the machine rebooted) |
| All sandboxes are gone after a machine reboot | Sandboxes (paused ones too) do not survive a machine reboot | Expected; snapshot state you need to keep |

## 9. E2B SDK

| Symptom | Cause | Fix |
|---|---|---|
| `401: ... API key is malformed: expected the "e2b_" prefix` | `E2B_API_URL` is not set, so the SDK talks to E2B's own service | Point `E2B_API_URL` and `E2B_SANDBOX_URL` at the gateway |
| The JS SDK fails with a syntax error or does not start | Node is too old | E2B's JS SDK needs Node 22.19 or newer |
| `pause(mode="filesystem")` does a full pause instead of failing | E2B's Python SDK 2.46 does not know `mode` and drops it silently | Use E2B SDK 2.59 or newer; OpenDsec refuses filesystem-only pauses |
| E2B sandboxes cannot reach the internet | Gateways before 0.11 used the cluster's default network rules | Upgrade; gateways now allow the internet by default, as E2B does |
| Building the code interpreter template fails | The build needs internet access and `layer.publish` | The newer build script allows internet for its build sandbox; check the permission |
| `Sandbox.create(snapshot_id)` times out | Using a fresh snapshot on another node waits for it to reach the image store | Raise `timeout`, especially with a slow store |
