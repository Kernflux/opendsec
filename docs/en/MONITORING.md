# Monitoring and alerts

Every OpenDsec component serves Prometheus metrics and health checks. `opendsecops monitor` sets up node_exporter, Prometheus, Alertmanager and the alert rules. This page lists every metric and every alert, and what to do about each alert. Service level objectives and how they are computed are in [SLO](SLO.md).

## 1. Endpoints

Every component is started with `-metrics <address>` (the systemd units do this) and serves there:

| Path | Meaning |
|---|---|
| `/metrics` | Prometheus metrics |
| `/healthz` | 200 while the process is alive |
| `/readyz` | 200 while it can serve, else 503 with the reason (IAM without a leader, an apiserver without a cluster snapshot yet, shutting down, …) |

| Role | Metrics port | Prometheus job |
|---|---|---|
| iam | 9461 | `opendsec-iam` |
| watcher | 9462 | `opendsec-watcher` |
| apiserver | 9463 | `opendsec-apiserver` |
| edge | 9464 | `opendsec-edge` |
| fleet | 9465 | `opendsec-fleet` |
| node agent | 9466 | `opendsec-nodeagent` |
| E2B gateway | 9467 | `opendsec-e2b` |
| node_exporter | 9100 | `node` |

Load balancer health checks use the apiserver's `9463/readyz` (the E2B gateway's `9467/readyz`). On SIGTERM, an apiserver fails `/readyz` first and keeps serving 6 more seconds, so the load balancer takes it out before it stops.

## 2. Setup

```sh
deploy/prod/opendsecops monitor https://alerts.example.com/hook
```

- Installs node_exporter on every machine, and Prometheus (9090) and Alertmanager (9093) on the `monitor` node.
- Scrape targets come from the inventory; the alert rules are `deploy/monitoring/alerts.yml`.
- Alerts go out as webhooks (Alertmanager's webhook format). **Without a webhook, the receiver is reset to "send nothing"**: before running it again, look up the existing receiver in `/etc/prometheus/alertmanager.yml` and pass it along.
- Run it again after adding machines or changing roles, to scrape the new ones.

With a Prometheus of your own, add scrape targets on the ports above and load `deploy/monitoring/alerts.yml`.

## 3. Metrics

### Every component

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `opendsec_build_info` | gauge | `version` | Always 1; the running version |
| `opendsec_ready` | gauge | — | 1 while `/readyz` returns 200 |
| `opendsec_rpc_server_handled_total` | counter | `service`, `method`, `reason` | RPCs served; `reason` is `ok` or the error reason (`quota_exceeded`, …) |
| `opendsec_rpc_server_handling_seconds` | histogram | `service`, `method` | Time to serve an RPC (streams: until they end) |
| `opendsec_tls_cert_expiry_timestamp_seconds` | gauge | `identity` | When the certificates the process loaded expire (Unix time); `ca` is the CA |
| `opendsec_host_mounts` | gauge | — | Entries in the process's mount table |

### apiserver

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `opendsec_apiserver_create_seconds` | histogram | `backend`, `reason` | Sandbox creation through the apiserver (placement, admission, edge), by outcome |
| `opendsec_apiserver_placement_retries_total` | counter | `reason` | Creations retried on another node after an edge rejected them, by the edge's reason |
| `opendsec_apiserver_fork_seconds` | histogram | `held` | Fork time from the snapshot to the last copy; `held`: whether the snapshot stayed on the source node |
| `opendsec_apiserver_move_seconds` | histogram | `reason` | Paused sandboxes moved to another node |

### edge

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `opendsec_edge_sandboxes` | gauge | `edge`, `backend`, `state` | Sandboxes per state |
| `opendsec_edge_capacity` | gauge | `edge`, `resource` | Schedulable capacity (overcommit applied): `cpu_cores`, `memory_mb`, `gpus`, `disk_mb` |
| `opendsec_edge_allocated` | gauge | `edge`, `resource` | Resources allocated to sandboxes |
| `opendsec_edge_mem_available_mb` | gauge | `edge` | The node's MemAvailable |
| `opendsec_edge_disk_available_mb` | gauge | `edge` | Free space on the state directory's file system |
| `opendsec_edge_under_pressure` | gauge | `edge`, `pressure` | 1 while creations are rejected under memory, disk or CPU pressure |
| `opendsec_edge_draining` | gauge | `edge` | 1 while draining (no new sandboxes) |
| `opendsec_edge_moved_in` | gauge | `edge` | Sandboxes that moved here from another node |
| `opendsec_edge_created_total` | counter | `edge` | Sandboxes created |
| `opendsec_edge_rejected_total` | counter | `edge` | Creations rejected (no capacity, draining, pressure) |
| `opendsec_edge_create_seconds` | histogram | `backend`, `reason` | Creation on the node (admission to running) |
| `opendsec_edge_create_phase_seconds` | histogram | `backend`, `phase` | Creation phases (prepare, network, config, start, …), to find what is slow |
| `opendsec_edge_op_seconds` | histogram | `backend`, `op`, `reason` | Pause, resume, stop, snapshot |
| `opendsec_edge_runtime_info` | gauge | `edge`, `component`, `version` | Versions of the runtime programs the node uses (e.g. firecracker) |
| `opendsec_snapshot_transfer_seconds` | histogram | `kind` | Snapshots moved between nodes: fetched from another edge, pulled from or published to the store |
| `opendsec_snapshot_transfer_bytes_total` | counter | `kind` | Snapshot data received from other edges (holes and zero runs excluded) |

### IAM and watcher

| Metric | Meaning |
|---|---|
| `opendsec_iam_leader` | 1 on the IAM replica that leads |
| `opendsec_iam_leases` | Quota leases held (one per live sandbox) |
| `opendsec_iam_backup_last_success_timestamp_seconds` | Last successful IAM backup (from the backup script, through node_exporter's textfile collector) |
| `opendsec_watcher_edges_healthy` | Edges answering |
| `opendsec_watcher_edges_unhealthy` | Edges not answering |
| `opendsec_watcher_edges_draining` | Edges draining |

### fleet (on the leader only)

| Metric | Labels | Meaning |
|---|---|---|
| `opendsec_fleet_leader` | `replica` | 1 on the leading replica |
| `opendsec_fleet_nodes` | `state`, `domain` | Machines per state and failure domain |
| `opendsec_fleet_node_release` | `release` | Machines per running release |
| `opendsec_fleet_heartbeat_age_seconds` | — | Age of the oldest heartbeat among active machines |
| `opendsec_fleet_rollout_active` | `state` | 1 while a rollout is in this state |
| `opendsec_fleet_rollout_progress` | — | Share of the active rollout's steps done |

### Useful queries

```promql
# creations per second, by outcome
sum by (reason) (rate(opendsec_apiserver_create_seconds_count[5m]))

# p99 creation time, by backend
histogram_quantile(0.99, sum by (le, backend) (rate(opendsec_apiserver_create_seconds_bucket[5m])))

# server-side error ratio (caller errors such as quota and bad arguments excluded)
sum(rate(opendsec_rpc_server_handled_total{reason=~"internal|unavailable|timeout"}[5m]))
  / sum(rate(opendsec_rpc_server_handled_total[5m]))

# running sandboxes per node and backend
sum by (edge, backend) (opendsec_edge_sandboxes{state="RUNNING"})

# share of memory allocated
sum(opendsec_edge_allocated{resource="memory_mb"}) / sum(opendsec_edge_capacity{resource="memory_mb"})

# which creation phase is slow
histogram_quantile(0.99, sum by (le, phase) (rate(opendsec_edge_create_phase_seconds_bucket{backend="microvm"}[10m])))

# versions running
count by (version) (opendsec_build_info)
```

## 4. Alerts

The rules are in `deploy/monitoring/alerts.yml`, 25 of them. Severities: `critical` needs action now, `warning` the same day, `info` is worth a look.

### Control plane

| Alert | Severity | For | Meaning | What to do |
|---|---|---|---|---|
| `OpenDsecComponentDown` | critical | 1m | Prometheus cannot scrape a component | `opendsecops status`; on that machine, `systemctl status <unit>` and `journalctl -u <unit>` |
| `OpenDsecComponentNotReady` | critical | 2m | A component reports not ready | `curl <ip>:<port>/readyz` returns the reason |
| `OpenDsecIAMNoLeader` | critical | 30s | IAM has no leader: creations and authentication fail | Are fewer than 2 IAM replicas up? Is port 7011 open between them? |
| `OpenDsecIAMQuorumAtRisk` | warning | 2m | Fewer than 3 IAM replicas up; one more failure loses the quorum | Bring the replica back soon; do not maintain another IAM node meanwhile |
| `OpenDsecWatcherDegraded` | warning | 2m | Fewer than 2 watchers up | Bring the watcher back |
| `OpenDsecAPIServerDegraded` | warning | 2m | Fewer than 2 apiservers ready | Bring the apiserver back; check the load balancer's health checks |
| `OpenDsecCertExpiringSoon` | warning | 1h | A certificate expires within 30 days | Renew it: [operations manual §4, "Certificates"](OPERATIONS.md) |
| `OpenDsecIAMBackupStale` | warning | — | No successful IAM backup for 36 hours | `systemctl status opendsec-iam-backup`; check `/var/backups/opendsec` and disk space |
| `OpenDsecVersionSkew` | info | 2h | More than one version running for over 2 hours | An upgrade that stopped halfway? `opendsecctl fleet rollout status` |

### Sandboxes

| Alert | Severity | For | Meaning | What to do |
|---|---|---|---|---|
| `OpenDsecEdgeUnhealthy` | critical | 1m | Edges not answering the watchers; their quota is released after `lost_edge_grace` | Is the machine up and `opendsec-edge` running? |
| `OpenDsecCreateErrors` | critical | 5m | Too many creations fail for server-side reasons | Break `opendsec_apiserver_create_seconds` down by `reason`; check edge logs |
| `OpenDsecCreateSlow` | warning | 10m | p99 creation time of a backend is too high | Find the slow phase with `opendsec_edge_create_phase_seconds`; check the image store and node disks |
| `OpenDsecEdgeUnderPressure` | warning | 5m | An edge rejects creations under memory, disk or CPU pressure | See the `pressure` label; free resources, add capacity or lower quotas |
| `OpenDsecCapacityLow` | warning | 15m | Most of the cluster's sandbox memory is allocated | Add compute nodes or lower quotas |
| `OpenDsecEdgeDiskLow` | warning | 10m | An edge's state file system has under 10% free | Clean up; look for many snapshots or large sandbox disks |
| `NodeFilesystemAlmostFull` | warning | 10m | A file system on a node is almost full | Which mount point: logs, audit logs, state directory? |
| `NodeImageStoreMissing` | critical | 5m | An edge node does not have the image store mounted | `mount /mnt/opendsec-images` on it; check the NAS |

### fleet

| Alert | Severity | For | Meaning | What to do |
|---|---|---|---|---|
| `OpenDsecFleetNoLeader` | warning | 1m | No fleet replica leads: no heartbeats are taken and rollouts stand still (components keep running) | Check the fleet replicas and IAM |
| `OpenDsecFleetNodeSilent` | warning | 2m | A node agent has not reported for a while | `opendsecctl fleet nodes` shows which; `systemctl status opendsec-nodeagent` |
| `OpenDsecFleetRolloutPaused` | warning | 30m | A rollout has been paused for 30 minutes | `opendsecctl fleet rollout status -steps` for the reason, then resume, roll back or abort |
| `OpenDsecFleetDrift` | info | 10m | Machines run different releases while no rollout is active | Pinned machines, or one out of sync: `fleet node sync <name>` |

### SLO

| Alert | Severity | For | Meaning |
|---|---|---|---|
| `OpenDsecSLOCreateBurnFast` | critical | 2m | Creation errors burn the error budget 14.4x too fast: 2 days of this spend the 30-day budget |
| `OpenDsecSLOCreateBurnSlow` | warning | 15m | 6x: 5 days spend it |
| `OpenDsecSLORuntimeBurnFast` | critical | 2m | Runtime calls (commands, files, stop, pause, resume, fork), 14.4x |
| `OpenDsecSLORuntimeBurnSlow` | warning | 15m | As above, 6x |

What to do: break the errors down by `reason` and `method` and find when they started; was there a release, a config change or a node failure at that time? How the SLOs are computed: [SLO](SLO.md).

## 5. Logs

| What | Where |
|---|---|
| Component logs | journald: `journalctl -u opendsec-edge`, `journalctl -u 'opendsec-apiserver@*'`, … |
| Warnings and errors only | `journalctl -u 'opendsec-*' -p warning --since -1h` |
| Audit log | `audit_dir` on apiserver nodes (default `/var/log/opendsec/audit`), JSON lines, one per call: time, principal, method, project, sandbox, outcome, latency, source address. Commands are recorded as their length and SHA-256 only |
| IAM backups | `/var/backups/opendsec` on IAM nodes |

Log levels are set with each component's `-log` flag (`debug`, `info`, `warn`, `error`); the default is `info`.
