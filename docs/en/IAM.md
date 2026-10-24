# Projects, principals and permissions

OpenDsec organizes resources in a **project tree**, authenticates callers as **principals** holding **tokens**, controls who may do what with **permissions** granted on projects, and limits each project's resources with **quotas**. This page describes those rules and a few common setups.

## 1. Projects

- Projects form a tree rooted at `root`, with paths separated by `/`, e.g. `root/team-a/rl`.
- Project names cannot contain `/` or spaces.
- Every sandbox and image belongs to a project: a sandbox to the project it was created in, an image to the project in its name (`root/team-a/py:3.12` belongs to `root/team-a`).
- Listings of sandboxes and images include all subprojects.

```sh
opendsecctl project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000
opendsecctl project create root/team-a rl
opendsecctl project get root/team-a
```

`project get` shows the quota (`quota`), current usage (`usage`), the permissions each principal holds directly on the project (`policies`) and its subprojects (`children`). It needs any permission on the project.

`opendsecctl project delete root/team-a/rl` deletes a project. Only empty projects can be deleted: no subprojects, no usage (no running sandboxes) and no principals of their own. Root cannot be deleted.

## 2. Principals and tokens

A **principal** is whatever calls the API: a person, a service or an agent.

```sh
opendsecctl principal create root/team-a trainer -kind agent
```

- Principal ids are unique across the cluster and cannot contain `.`, `/` or spaces.
- A principal belongs to the project it was created in, whose admins manage it (issue and revoke its tokens, delete it).
- `kind` is `user`, `service` or `agent` (default `agent`): a label only, with no effect on permissions.
- Creation issues the first token, **shown only in that output**.
- A new principal has no permissions; grant them separately (§3).

A **token** is a principal's credential, sent as `authorization: Bearer <token>` (the SDK and opendsecctl do this):

- Format `dsk.<principal>.<token id>.<secret>`. The older format `dsk.<principal>.<secret>` is the principal's primary token with id `primary`; the administrator's bootstrap token has this form.
- The server keeps only a hash of the secret: a lost token cannot be recovered, only replaced.
- A principal can hold many tokens, e.g. one per training machine, so a leaked one can be revoked alone.

```sh
opendsecctl token create trainer -ttl 2592000 -desc "gpu-node-07"     # 30 days
opendsecctl token list trainer
opendsecctl token revoke trainer <token-id>
```

| Rule | Detail |
|---|---|
| Who manages tokens | Every principal manages its own; `project.admin` on a principal's project manages that principal's |
| Lifetime | `-ttl` seconds. With the cluster's `max_token_ttl_s` set: left out, the limit applies; above the limit, `invalid`. Without it: left out means never expiring |
| Revocation | Takes effect on every apiserver within about 1 s: each revocation makes every apiserver drop its authentication cache |
| After expiry | Calls get `unauthenticated` |

**Replacing a token**: issue a new one → give it to the caller → the caller switches → confirm the old one is no longer used → revoke the old one.

**Failed authentication limit**: once one client address fails more than `auth_fail_rate` authentications per second (default 5), new tokens from it are not checked for a while, against brute force.

## 3. Permissions

Permissions are granted on a project and apply to it and **all its subprojects**:

```sh
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl revoke root/team-a trainer sandbox.operate
opendsecctl revoke root/team-a trainer              # all of them
```

| Permission | Allows |
|---|---|
| `sandbox.create` | Creating sandboxes, batch creation, fork (copies are created in this project) |
| `sandbox.operate` | Getting and listing sandboxes; commands, files, HTTP, processes, ports; pause, resume, stop, touch; network rule changes; task actions |
| `layer.use` | Creating sandboxes from the project's images; viewing and listing them; using them as parts of `compose` |
| `layer.publish` | Publishing the project's images: import, compose, `pack_diff`, snapshot, delete |
| `project.admin` | Creating, setting quotas on and deleting subprojects; creating and deleting principals; granting and revoking permissions; managing its principals' tokens; usage |
| `fleet.view` | On root: viewing the cluster management service (machines, releases, rollouts) |
| `fleet.operate` | On root: releases, config changes, starting and controlling rollouts, managing machines |

Notes:

- Permissions **do not include each other**: `project.admin` alone does not let you create sandboxes; grant each permission needed. The exception is cluster management: `project.admin` on root works as `fleet.view` and `fleet.operate` too.
- **Cluster-wide operations** need `project.admin` on root: draining an edge (`edge drain`), IAM backup and restore, IAM replica management.
- Operating a sandbox checks `sandbox.operate` on **the sandbox's project**, whoever created it. Principals with `sandbox.operate` on the same project can operate each other's sandboxes; put callers who must be isolated from each other in different projects.
- Creating a sandbox needs two permissions: `sandbox.create` on the target project and `layer.use` on the image's project.
- The bootstrap administrator (the config's `admin_id`, default `admin`) holds every permission on root and cannot be deleted.

### Bounded delegation

Project admins can hand management down, but never more than they have:

- **Granting** needs `project.admin` on the project and every permission granted, held on that project. An admin without `layer.publish` cannot grant `layer.publish`.
- **Quotas**: a subproject's quota cannot exceed any ancestor's. Setting it needs `project.admin` on the **parent** project; a project's own admins cannot raise their own quota.
- So a whole subproject can safely be handed to a team or an agent: they create projects, principals, quotas and grants inside it, but cannot break the bounds set above them.

## 4. Quotas

| Key | Meaning |
|---|---|
| `sandboxes` | Sandboxes existing at once (running or paused) |
| `cpu_cores` | Sum of CPU cores |
| `memory_mb` | Sum of memory (MB) |
| `gpus` | Sum of GPUs |

- A creation must fit the quota of its project **and of every ancestor**: a subproject's usage counts in each of them. Going over any level is `quota_exceeded`, and the message names the level and key.
- Keys left out when a project is created or its quota set take the tightest ancestor limit at that moment, stored in the project. Root's quota is set by operators (`iam.root_quota`); unset, unlimited.
- Lowering an ancestor's quota later takes effect at once: every ancestor is checked again at each creation, so the effective limit is always the smallest along the path.
- Setting a quota replaces it as a whole: keys left out of `set_quota` take the tightest ancestor limit again.
- Paused sandboxes keep their quota: the capacity they need to resume is still theirs.
- Stopping a sandbox returns its quota at once. When a node fails, the watcher releases its sandboxes' quota after `lost_edge_grace` (default 120 s).
- Quotas bound what is held **at once**, not cumulative use; for that, see §5.

```sh
opendsecctl project create root/team-a eval -quota sandboxes=200,cpu_cores=400
# SDK:
await client.set_quota("root/team-a/eval", {"sandboxes": 300, "cpu_cores": 600})
```

## 5. Usage

```sh
opendsecctl usage root/team-a -from 2026-10-01 -to 2026-10-31          # each project's total over the period
opendsecctl usage root -from 2026-10-01 -daily -csv > usage.csv        # per day and project
```

```python
report = await client.get_usage("root/team-a", start="2026-10-01", end="2026-10-31")
for row in report.rows:
    print(row.day, row.project, row.sandboxes_started, row.sandbox_hours, row.cpu_core_hours, row.memory_gb_hours, row.gpu_hours)
```

- Covers the project and all its subprojects: sandboxes started, sandbox-hours, CPU core-hours, memory GB-hours, GPU-hours.
- Per UTC day. Each row counts the project's own sandboxes only; subprojects get rows of their own. Without `-daily`, the last row is the total.
- What is counted is the time quota is held: running and paused alike. Sandboxes still running count up to the time of the query.
- Needs `project.admin` on the project.
- Kept for 400 days in IAM and replicated with Raft, so node restarts and failovers lose nothing.

## 6. Common setups

### Onboarding a team

```sh
export OPENDSEC_ADDR=<LB>:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
opendsecctl project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000
opendsecctl principal create root/team-a team-a-admin -kind user        # the team's admin
opendsecctl grant root/team-a team-a-admin project.admin,sandbox.create,sandbox.operate,layer.use,layer.publish
opendsecctl grant root team-a-admin layer.use                          # may use the shared images under root/
```

The team admin then creates subprojects and principals and hands out permissions up to their own.

### A training job's caller

```sh
opendsecctl principal create root/team-a trainer -kind agent
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl grant root trainer layer.use
```

### Separate build and run accounts

```sh
# the build account may publish images under root/team-a
opendsecctl principal create root/team-a builder -kind service
opendsecctl grant root/team-a builder sandbox.create,sandbox.operate,layer.use,layer.publish
# the run account may only use them
opendsecctl grant root/team-a trainer layer.use
```

Even if the code running jobs is compromised, it cannot tamper with the images training uses.

### Agents managing their own subproject

Agents use the same API (the SDK's `create_project`, `create_principal`, `grant`, `create_token`) to give subtasks principals and quotas in their own subproject:

```python
async with DSecClient(token=agent_admin_token, project="root/team-a/agent-7") as c:
    await c.create_project("root/team-a/agent-7", "sub-1", quota={"sandboxes": 10})
    tok = await c.create_principal("root/team-a/agent-7/sub-1", "agent-7-sub-1", ttl=3600)
    await c.grant("root/team-a/agent-7/sub-1", "agent-7-sub-1", ["sandbox.create", "sandbox.operate"])
```

Bounded delegation keeps the subtasks within the agent's own quota and permissions.

### E2B gateway callers

The E2B gateway calls OpenDsec with the caller's own token, which needs `sandbox.create` and `sandbox.operate` on `e2b.project` and `layer.use` on the template images' project; snapshots (`create_snapshot()`) also need `layer.publish` on `e2b.project`.

## 7. Backup and restore

IAM's whole content (principals, projects, permissions, quotas, token hashes, usage) can be backed up:

```sh
opendsecctl iam backup -out iam-$(date +%F).json.gz     # gzipped JSON, mode 0600
opendsecctl iam restore iam-2026-10-24.json.gz
```

- Needs `project.admin` on root.
- On a deployed cluster, every IAM node backs up daily at 03:00 to `/var/backups/opendsec` (`opendsec-iam-backup.timer`); `opendsecops backup` takes one onto the ops machine right away.
- Restoring replaces IAM's content. Quota leases of running sandboxes are not in backups; the next reconciliation (default 30 s) registers them again from the edges.
- Principals, tokens and projects created after the backup do not exist after a restore and must be recreated.

Full disaster recovery steps: [operations manual §5](OPERATIONS.md).
