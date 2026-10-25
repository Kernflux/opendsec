# 监控与告警

每个 OpenDsec 组件都提供 Prometheus 指标和健康检查。`opendsecops monitor` 会装好 node_exporter、Prometheus、Alertmanager 和告警规则。这一页列出全部指标和告警，以及每条告警该怎么处理。服务目标和它们的计算方法见 [SLO](SLO.md)。

## 1. 接口

每个组件以 `-metrics <地址>` 启动（systemd unit 已经配好），在这个地址上提供：

| 路径 | 说明 |
|---|---|
| `/metrics` | Prometheus 指标 |
| `/healthz` | 进程存活即返回 200 |
| `/readyz` | 能正常服务时返回 200，否则返回 503 和原因（例如 IAM 还没有 leader、apiserver 还没拿到集群快照、正在关闭） |

| 角色 | 指标端口 | Prometheus job |
|---|---|---|
| iam | 9461 | `opendsec-iam` |
| watcher | 9462 | `opendsec-watcher` |
| apiserver | 9463 | `opendsec-apiserver` |
| edge | 9464 | `opendsec-edge` |
| fleet | 9465 | `opendsec-fleet` |
| 节点代理 | 9466 | `opendsec-nodeagent` |
| E2B 网关 | 9467 | `opendsec-e2b` |
| node_exporter | 9100 | `node` |

负载均衡的健康检查用 apiserver 的 `9463/readyz`（E2B 网关用 `9467/readyz`）。apiserver 收到 SIGTERM 后先让 `/readyz` 失败，再继续服务 6 秒，等负载均衡把它摘掉。

## 2. 安装

```sh
deploy/prod/opendsecops monitor https://alerts.example.com/hook
```

- 每台机器装 node_exporter；`monitor` 角色的节点装 Prometheus（9090）和 Alertmanager（9093）。
- 抓取目标按 inventory 生成；告警规则是 `deploy/monitoring/alerts.yml`。
- 告警以 webhook 发出（Alertmanager 的 webhook 格式）。**不带 webhook 时会把接收方重置为「不发送」**：重新执行前，先看 `/etc/prometheus/alertmanager.yml` 里原来的接收方，照原样带上。
- 加了机器、改了角色之后，重新执行一次，把新机器加进抓取目标。

已有自己的 Prometheus 时，按上表的端口添加抓取目标，再加载 `deploy/monitoring/alerts.yml` 即可。

## 3. 指标

### 所有组件

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `opendsec_build_info` | gauge | `version` | 恒为 1，标签是运行中的版本 |
| `opendsec_ready` | gauge | — | `/readyz` 返回 200 时为 1 |
| `opendsec_rpc_server_handled_total` | counter | `service`、`method`、`reason` | 处理的 RPC 数，`reason` 是 `ok` 或错误原因（`quota_exceeded` 等） |
| `opendsec_rpc_server_handling_seconds` | histogram | `service`、`method` | RPC 处理耗时（流式调用算到结束） |
| `opendsec_tls_cert_expiry_timestamp_seconds` | gauge | `identity` | 进程加载的证书的到期时间（Unix 时间），`ca` 是 CA |
| `opendsec_host_mounts` | gauge | — | 进程挂载表的条目数 |

### apiserver

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `opendsec_apiserver_create_seconds` | histogram | `backend`、`reason` | 经 apiserver 创建 sandbox 的耗时（调度、准入、edge），按结果分 |
| `opendsec_apiserver_placement_retries_total` | counter | `reason` | 被 edge 拒绝后换节点重试的次数，按拒绝原因 |
| `opendsec_apiserver_fork_seconds` | histogram | `held` | fork 从快照到最后一个副本的耗时；`held` 表示快照是否一直留在源节点 |
| `opendsec_apiserver_move_seconds` | histogram | `reason` | 暂停的 sandbox 迁移到其他节点的耗时 |

### edge

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `opendsec_edge_sandboxes` | gauge | `edge`、`backend`、`state` | 各状态的 sandbox 数 |
| `opendsec_edge_capacity` | gauge | `edge`、`resource` | 可调度容量（已乘超配倍数）：`cpu_cores`、`memory_mb`、`gpus`、`disk_mb` |
| `opendsec_edge_allocated` | gauge | `edge`、`resource` | 已分配给 sandbox 的资源 |
| `opendsec_edge_mem_available_mb` | gauge | `edge` | 节点的 MemAvailable |
| `opendsec_edge_disk_available_mb` | gauge | `edge` | 状态目录所在文件系统的剩余空间 |
| `opendsec_edge_under_pressure` | gauge | `edge`、`pressure` | 因内存、磁盘或 CPU 压力拒绝创建时为 1 |
| `opendsec_edge_draining` | gauge | `edge` | 排空（不接新 sandbox）时为 1 |
| `opendsec_edge_moved_in` | gauge | `edge` | 从其他节点迁移过来的 sandbox 数 |
| `opendsec_edge_created_total` | counter | `edge` | 创建的 sandbox 数 |
| `opendsec_edge_rejected_total` | counter | `edge` | 拒绝的创建数（容量不足、排空、压力） |
| `opendsec_edge_create_seconds` | histogram | `backend`、`reason` | 节点上创建 sandbox 的耗时（准入到运行） |
| `opendsec_edge_create_phase_seconds` | histogram | `backend`、`phase` | 创建的各阶段耗时（prepare、network、config、start 等），用来定位慢在哪 |
| `opendsec_edge_op_seconds` | histogram | `backend`、`op`、`reason` | 暂停、恢复、停止、快照的耗时 |
| `opendsec_edge_runtime_info` | gauge | `edge`、`component`、`version` | 节点使用的运行时程序的版本（如 firecracker） |
| `opendsec_snapshot_transfer_seconds` | histogram | `kind` | 快照在节点之间传输的耗时：从其他 edge 拉取、从镜像库拉取、发布到镜像库 |
| `opendsec_snapshot_transfer_bytes_total` | counter | `kind` | 从其他 edge 收到的快照数据量（不含空洞和全零区域） |

### IAM 与 watcher

| 指标 | 说明 |
|---|---|
| `opendsec_iam_leader` | 当前是 leader 的 IAM 副本上为 1 |
| `opendsec_iam_leases` | 持有的配额租约数（每个存活的 sandbox 一个） |
| `opendsec_iam_backup_last_success_timestamp_seconds` | 最近一次成功备份 IAM 的时间（由备份脚本经 node_exporter 的 textfile 提供） |
| `opendsec_watcher_edges_healthy` | 应答正常的 edge 数 |
| `opendsec_watcher_edges_unhealthy` | 不应答的 edge 数 |
| `opendsec_watcher_edges_draining` | 排空中的 edge 数 |

### fleet（只在 leader 上）

| 指标 | 标签 | 说明 |
|---|---|---|
| `opendsec_fleet_leader` | `replica` | 是 leader 的副本上为 1 |
| `opendsec_fleet_nodes` | `state`、`domain` | 各状态、各故障域的机器数 |
| `opendsec_fleet_node_release` | `release` | 运行各版本的机器数 |
| `opendsec_fleet_heartbeat_age_seconds` | — | 在用机器里最旧的心跳距今多久 |
| `opendsec_fleet_rollout_active` | `state` | rollout 处于这个状态时为 1 |
| `opendsec_fleet_rollout_progress` | — | 当前 rollout 已完成的步数占比 |

### 常用查询

```promql
# 每秒创建数，按结果
sum by (reason) (rate(opendsec_apiserver_create_seconds_count[5m]))

# 创建耗时 p99，按后端
histogram_quantile(0.99, sum by (le, backend) (rate(opendsec_apiserver_create_seconds_bucket[5m])))

# 服务端错误率（不含调用方的错误，如配额、参数）
sum(rate(opendsec_rpc_server_handled_total{reason=~"internal|unavailable|timeout"}[5m]))
  / sum(rate(opendsec_rpc_server_handled_total[5m]))

# 运行中的 sandbox，按节点和后端
sum by (edge, backend) (opendsec_edge_sandboxes{state="RUNNING"})

# 内存分配率
sum(opendsec_edge_allocated{resource="memory_mb"}) / sum(opendsec_edge_capacity{resource="memory_mb"})

# 创建慢在哪个阶段
histogram_quantile(0.99, sum by (le, phase) (rate(opendsec_edge_create_phase_seconds_bucket{backend="microvm"}[10m])))

# 正在运行的版本
count by (version) (opendsec_build_info)
```

## 4. 告警

规则在 `deploy/monitoring/alerts.yml`，共 25 条。严重程度：`critical` 需要立即处理，`warning` 当天处理，`info` 留意即可。

### 管控面

| 告警 | 级别 | 持续 | 含义 | 处理 |
|---|---|---|---|---|
| `OpenDsecComponentDown` | critical | 1m | Prometheus 抓不到某个组件 | `opendsecops status`；在那台机器上 `systemctl status <unit>`、`journalctl -u <unit>` |
| `OpenDsecComponentNotReady` | critical | 2m | 组件报告未就绪 | `curl <ip>:<端口>/readyz` 返回未就绪的原因 |
| `OpenDsecIAMNoLeader` | critical | 30s | IAM 没有 leader：创建和认证都会失败 | 在线的 IAM 副本是否不足 2 个；副本之间 7011 端口是否通 |
| `OpenDsecIAMQuorumAtRisk` | warning | 2m | 在线的 IAM 副本少于 3 个，再坏一个就失去多数派 | 尽快恢复宕机的副本；这期间不要维护其他 IAM 节点 |
| `OpenDsecWatcherDegraded` | warning | 2m | 在线的 watcher 少于 2 个 | 恢复宕机的 watcher |
| `OpenDsecAPIServerDegraded` | warning | 2m | 就绪的 apiserver 少于 2 个 | 恢复宕机的 apiserver；检查负载均衡的健康检查 |
| `OpenDsecCertExpiringSoon` | warning | 1h | 证书 30 天内到期 | 续期，见[运维手册 §4「证书」](OPERATIONS.md) |
| `OpenDsecIAMBackupStale` | warning | — | 36 小时没有成功备份 IAM | `systemctl status opendsec-iam-backup`；查看 `/var/backups/opendsec` 和磁盘空间 |
| `OpenDsecVersionSkew` | info | 2h | 两个以上的版本同时运行超过 2 小时 | 有没有中途停下的升级；`opendsecctl fleet rollout status` |

### sandbox

| 告警 | 级别 | 持续 | 含义 | 处理 |
|---|---|---|---|---|
| `OpenDsecEdgeUnhealthy` | critical | 1m | 有 edge 不应答 watcher；超过 `lost_edge_grace` 后它的配额被释放 | 那台机器是否在线，`opendsec-edge` 是否在运行 |
| `OpenDsecCreateErrors` | critical | 5m | 服务端原因的创建失败率过高 | 按 `reason` 看 `opendsec_apiserver_create_seconds` 的失败分布；看 edge 日志 |
| `OpenDsecCreateSlow` | warning | 10m | 某个后端创建耗时的 p99 过高 | 用 `opendsec_edge_create_phase_seconds` 找慢的阶段；检查镜像库和节点磁盘 |
| `OpenDsecEdgeUnderPressure` | warning | 5m | 某个 edge 因内存、磁盘或 CPU 压力拒绝创建 | 看 `pressure` 标签；释放资源、扩容，或调低项目配额 |
| `OpenDsecCapacityLow` | warning | 15m | 集群的 sandbox 内存大部分已分配 | 扩容计算节点，或调低配额 |
| `OpenDsecEdgeDiskLow` | warning | 10m | 某个 edge 的状态目录剩余空间低于 10% | 清理；检查是否有大量快照或大盘 sandbox |
| `NodeFilesystemAlmostFull` | warning | 10m | 节点上某个文件系统快满了 | 看是哪个挂载点：日志、审计日志、状态目录 |
| `NodeImageStoreMissing` | critical | 5m | 有 edge 节点没有挂载镜像库 | 在那台机器上 `mount /mnt/opendsec-images`；检查 NAS |

### fleet

| 告警 | 级别 | 持续 | 含义 | 处理 |
|---|---|---|---|---|
| `OpenDsecFleetNoLeader` | warning | 1m | 没有 fleet 副本是 leader：不接收心跳，rollout 停住（组件照常运行） | 检查 fleet 副本和 IAM |
| `OpenDsecFleetNodeSilent` | warning | 2m | 有节点代理一段时间没有上报 | `opendsecctl fleet nodes` 看是哪台；`systemctl status opendsec-nodeagent` |
| `OpenDsecFleetRolloutPaused` | warning | 30m | rollout 暂停了 30 分钟 | `opendsecctl fleet rollout status -steps` 看原因，然后 resume、rollback 或 abort |
| `OpenDsecFleetDrift` | info | 10m | 没有进行中的 rollout，但机器运行的版本不一致 | 有锁定（pinned）的机器，或某台没同步：`fleet node sync <名字>` |

### SLO

| 告警 | 级别 | 持续 | 含义 |
|---|---|---|---|
| `OpenDsecSLOCreateBurnFast` | critical | 2m | 创建的错误率以 14.4 倍的速度消耗错误预算：持续 2 天就用完 30 天的预算 |
| `OpenDsecSLOCreateBurnSlow` | warning | 15m | 6 倍速度：持续 5 天用完 |
| `OpenDsecSLORuntimeBurnFast` | critical | 2m | 运行时调用（执行命令、文件、停止、暂停、恢复、fork）的错误率，14.4 倍 |
| `OpenDsecSLORuntimeBurnSlow` | warning | 15m | 同上，6 倍 |

处理：按 `reason` 和 `method` 看是哪类错误、从什么时候开始；同一时间有没有发版、改配置或节点故障。计算方法见 [SLO](SLO.md)。

## 5. 日志

| 内容 | 位置 |
|---|---|
| 组件日志 | journald：`journalctl -u opendsec-edge`、`journalctl -u 'opendsec-apiserver@*'` 等 |
| 只看警告和错误 | `journalctl -u 'opendsec-*' -p warning --since -1h` |
| 审计日志 | apiserver 节点的 `audit_dir`（默认 `/var/log/opendsec/audit`），JSON lines，每行一次调用：时间、身份、方法、项目、sandbox、结果、耗时、来源地址。执行命令只记录命令长度和 SHA-256 |
| IAM 备份 | IAM 节点的 `/var/backups/opendsec` |

日志级别用各组件的 `-log` 参数（`debug`、`info`、`warn`、`error`），默认 `info`。

由 systemd 启动时，每行日志前带 syslog 优先级（如 `<4>`），journald 按它记录级别，所以 `-p warning` 能筛出警告和错误。2026-10-25 之前构建的版本没有这个前缀，全部记成普通级别，要用 `journalctl -u 'opendsec-*' --since -1h | grep -E 'level=(WARN|ERROR)'`。
