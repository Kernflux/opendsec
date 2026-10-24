# Security model

OpenDsec runs untrusted code: commands a model generates during RL, scripts an agent runs. This page explains what isolates sandboxes from each other, from their host and callers from each other, how traffic and secrets inside the cluster are protected, and a hardening checklist for production.

To report a vulnerability, see `SECURITY.md` in the repository root; do not open a public issue.

## 1. Threat model

| Assumption | Meaning |
|---|---|
| Code in sandboxes is fully untrusted | It may run as root, try to escape, scan networks, exhaust resources |
| Callers do not trust each other | Callers of different projects cannot see or operate each other's sandboxes and images |
| Cluster nodes and the private network are trusted | Components still use mTLS, but a compromised node is out of scope |
| The ops machine is the most sensitive | It holds the CA's private key and the admin token |

## 2. Sandbox isolation

### microVM (recommended for untrusted code)

- Each sandbox is a Firecracker virtual machine **with its own kernel**: root in the sandbox is root of the guest kernel only, and the attack surface is Firecracker's few virtual devices instead of every system call of the host kernel.
- Firecracker is started by jailer: chrooted into its own directory and running as **a uid of its own per VM** (from `uid_base`, default one billion), so even a compromised VMM cannot touch other VMs' files.
- Each VM is in its own cgroup, limited to the guest memory plus `vm_overhead_mb`.
- Core scheduling (`core_sched`) is on by default: two sandboxes never run on the two hardware threads of one core at the same time, which closes SMT side channels.

### container

- Linux namespaces (mount, pid, net, uts, ipc, cgroup) + overlayfs + cgroup v2, sharing the host kernel.
- **Capabilities**: Docker's default set only, without `CAP_MKNOD` (without a device cgroup, a device node could reach the host's disks).
- **seccomp**: these system calls return EPERM: mounting and namespace switching (`mount`, `umount2`, `pivot_root`, `setns`, the new mount API), kernel modules and kexec, `bpf`, keyrings, file handles (`open_by_handle_at`, the "shocker" escape), `userfaultfd`, `perf_event_open`, raw I/O ports, swap, quotas, reboot. `clone` and `unshare` with `CLONE_NEWUSER` are refused (a user namespace would give the dropped capabilities back); `clone3` returns ENOSYS so libc falls back to `clone`.
- A process limit `pids_max` (default 4096); CPU, memory and disk I/O limited by cgroups.
- Core scheduling on by default.

**Containers share the host kernel**, so a kernel vulnerability can lead to an escape. Prefer microVMs for untrusted code.

### Both backends

- **Read-only agents**: the agents in the sandbox (aether, chronus) are mounted read-only; code in the sandbox cannot change them.
- **Session users**: commands can run in sessions of an unprivileged user (`user="1000"`). An unprivileged session cannot reach other sessions' channels, read their output records or change system files. With the agent's commands and the grader in different sessions, the agent cannot tamper with grading.
- **Path restrictions** (API fields `readonly_paths`, `masked_paths`): make paths in the sandbox read-only, or hide them (an empty directory or file in their place). In containers root cannot undo them; in a microVM the guest's root can, so pair them with a non-root `init_user`.
- **Resource limits**: CPU, memory, disk size and disk I/O (`disk_io`) are all bounded; a node short of memory or disk rejects new sandboxes to protect the running ones.
- **Output limits**: at most 64 MB of each command's output is recorded, at most 512 MB per session, so output cannot fill a node's disk.

## 3. Network isolation

See [Network policy](NETWORK.md). In short:

- Outbound traffic is denied by default and allowed by rules, enforced in the host's nftables, which root in the sandbox cannot change.
- Inbound connections are always refused: sandboxes cannot reach each other or services on the host (except DNS).
- Packets with forged source addresses are dropped.
- Private, link-local (cloud metadata `169.254.169.254` included) and multicast addresses are reachable only through network rules that name them; private addresses a domain resolves to are always blocked, so DNS cannot be used to get around the rules.
- Taking an allowance back cuts existing connections at once.

## 4. Isolation between callers

- Every call carries a token; IAM stores only token hashes.
- Permissions are granted per project and inherited downwards; bounded delegation keeps admins from handing out more permissions or quota than they have ([Projects, principals and permissions](IAM.md)).
- Operating a sandbox needs `sandbox.operate` on the sandbox's project, so callers of one project can operate each other's sandboxes: **put callers who must be isolated from each other in different projects**.
- Images are authorized by project: the principal running jobs can have `layer.use` only, so it cannot change the images training relies on.
- Tokens can expire (the cluster can enforce a limit with `max_token_ttl_s`), and a revocation takes effect cluster-wide within about 1 s.
- After too many failed authentications from one address, new tokens from it are not checked for a while, against brute force.

## 5. Inside the cluster

- **mTLS**: all traffic between components is mutual TLS. Each component's certificate carries its role and id (e.g. `edge-node-a1`), and each internal service accepts only certain roles: an edge's sandbox operations only from apiservers, its status queries from watchers, apiservers and fleet, and snapshot fetches from other edges; IAM's management calls only from apiservers.
- **Public API**: apiservers serve TLS, and clients verify it against the cluster CA. Apiserver certificates carry the load balancer's address and `api.opendsec.internal`.
- **Where secrets live**:

| Secret | Where | Not where |
|---|---|---|
| CA private key | only on the ops machine, `$OPENDSEC_OPS/pki` | any node |
| Admin token | the ops machine; `/etc/opendsec/admin.token` on IAM nodes (IAM needs it to bootstrap) | the cluster config holds only `admin_token_file`; other nodes do not have it |
| Component certificates and keys | only on the nodes running those components | other nodes |
| Caller tokens | the callers | the server stores only hashes |

- **Audit logs**: each apiserver records every call that changes something (creations, stops, pauses, forks, network changes, image publishing, projects, principals, permissions, tokens, cluster operations): time, principal, method, project, object, outcome, source address. Commands are recorded as their length and SHA-256, never their text. With `audit_runtime`, runtime calls and read-only queries are recorded too.
- **fleet's node agent** runs as root. It connects to fleet itself (with its node certificate, checking fleet's certificate) and performs only a fixed set of actions: download and verify a release, switch releases, write the config, restart OpenDsec's services. A new node agent replaces the old one only after passing a self-check.

## 6. Hardening checklist

Check each item when deploying a production cluster:

- [ ] Only the load balancer's 7100 (and 7400 with the E2B SDK) is reachable by callers; every other port only from the private network.
- [ ] Untrusted code runs on the `microvm` backend.
- [ ] Default network rules (`network.default_rules`) are as narrow as possible; internal services are allowed by exact address and port only.
- [ ] `iam.max_token_ttl_s` is set (e.g. 90 days) and tokens are rotated.
- [ ] Callers are split into projects by team or purpose, with only the permissions they need; principals running jobs do not get `layer.publish`.
- [ ] Audit logging is on (`audit_dir`) and the logs are shipped elsewhere regularly.
- [ ] `$OPENDSEC_OPS` is accessible to operators only and has an offline backup (it holds the CA's private key).
- [ ] `opendsecops monitor <webhook>` has an alert receiver; watch `OpenDsecCertExpiringSoon` and `OpenDsecIAMBackupStale`.
- [ ] The development `host` image (which exposes the host's `/` to sandboxes) is not used in production, and `service_token` is not set.
- [ ] Agents' commands run in unprivileged sessions, grading in another session.
- [ ] The NAS holding the image store is reachable from cluster nodes only.
