# OpenDsec 服务目标（SLO）

本文定义 OpenDsec 集群对调用方承诺什么、怎么测、没达到时怎么办。目标值是建议的起点，运维方可以按自己的业务调整，但调整后要同步改 `deploy/monitoring/alerts.yml` 里 `opendsec-slo` 组的数字。

实测记录在 SPEC §33：故障注入，以及 48 小时稳定性测试。

## 1. 指标（SLI）

| SLI | 好的事件 | 全部事件 | 数据来源 |
|---|---|---|---|
| 创建可用性 | 成功的创建 | 全部创建，扣除调用方自己的错误 | apiserver `opendsec_apiserver_create_seconds_count` |
| 创建延迟 | 成功且在阈值内完成的创建 | 成功的创建 | apiserver `opendsec_apiserver_create_seconds_bucket` |
| 运行时可用性 | 成功的 Exec、ExecStream、ReadFile、WriteFile 和生命周期调用（Stop、Pause、Resume、Fork） | 同上，扣除调用方自己的错误 | apiserver `opendsec_rpc_server_handled_total` |
| 端到端成功率 | 一个完整的调用方循环成功 | 全部循环 | 调用方：`sdk/python/examples/soak.py` |

**错误怎么归类**：
- **调用方的错误**：`invalid`、`unauthenticated`、`forbidden`、`not_found`、`quota_exceeded`、`rate_limited`、`conflict`。这些按调用方自己的问题处理，不计入 SLI。
- **服务端的错误**，计为坏事件：
  - 两类 SLI 都算：`unavailable`、`internal`；
  - 只在创建里算：`timeout`（排队等创建名额或限速等到超时）和 `no_capacity`（容量规划不足，也算服务端的责任）。
  - 运行时调用里的 `timeout` 不算：它多数是调用方自己的超时，或者命令还没执行完。

**服务端指标和调用方指标的区别**：服务端按每次尝试计数，SDK 遇到 `unavailable` 会重试，所以一次故障在服务端可能记了多次失败，调用方却只看到变慢。最终以调用方的端到端成功率为准，服务端指标用于告警和定位。

## 2. 目标

统计窗口为 30 天滚动。

| SLI | 目标 | 30 天错误预算 |
|---|---|---|
| 创建可用性 | 99.9% | 0.1%：每 100 万次创建可以失败 1000 次 |
| 创建延迟（container） | 99% 在 5 秒内 | 1% |
| 创建延迟（microvm） | 99% 在 3 秒内 | 1% |
| 运行时可用性 | 99.95% | 0.05% |
| 端到端成功率（`soak.py`） | 99.9% | 0.1% |

**前提**：
- 集群分配出去的内存不超过容量的 70%；
- 单个 edge 上的容器少于 3000 个。

  超过时创建会明显变慢，原因是内核的 `pivot_root` 串行（SPEC §32），延迟目标不再适用，应该先扩容。

**单点故障时的行为承诺**（由故障注入测试验证，见 SPEC §33）：

| 故障 | 承诺 |
|---|---|
| 任何一个组件进程崩溃或被重启（IAM、apiserver、watcher、edge、fleet、nodeagent） | 调用方不失败，可能变慢，最多 60 秒 |
| 一台控制节点和其他节点断网 | 调用方不失败 |
| edge 进程卡住或崩溃 | 它上面已有的 sandbox 继续运行，edge 恢复后可以继续操作 |
| 3 个 IAM 中 2 个不可用 | 允许失败：创建和登录需要 IAM 多数派；恢复后 60 秒内回到正常 |
| 一台 edge 节点断网或整机故障 | 允许失败：对它上面 sandbox 的操作会失败，整机故障时这些 sandbox 丢失，属于预期；新的创建不受影响，会放到其他节点 |
| 镜像库（NFS）中断 | 运行中的 sandbox 不受影响（容器用层的本地副本，`layer_cache`）。允许新建失败：新建会一直等到镜像库恢复，中断超过调用超时就会失败 |
| edge 进程卡住 | 发往它的创建约 15 秒后改到其他 edge；它上面 sandbox 的操作要等它恢复 |

**不在 SLO 里的**：
- sandbox 里调用方自己程序的失败；
- 节点重启后丢失的 sandbox（设计如此，见 OPERATIONS §5）；
- 镜像导入的耗时。

## 3. 怎么测

**服务端**：Prometheus 规则在 `deploy/monitoring/alerts.yml` 的 `opendsec-slo` 组里，包括：
- 记录规则 `opendsec:create_availability:ratio_rate5m` 等；
- 两条燃烧率告警（多窗口多燃烧率，参考 Google SRE workbook）：

  | 告警 | 条件 | 含义 |
  |---|---|---|
  | `OpenDsecSLOCreateBurnFast` | 1 小时和 5 分钟的错误率都超过预算的 14.4 倍 | 照这个速度，2 天会耗光 30 天的预算 |
  | `OpenDsecSLOCreateBurnSlow` | 6 小时和 30 分钟的错误率都超过预算的 6 倍 | 照这个速度，5 天会耗光预算 |

  运行时可用性有同样的两条。

在 Prometheus 里看过去 30 天的可用性：
```promql
1 - sum(increase(opendsec_apiserver_create_seconds_count{reason=~"unavailable|internal|timeout|no_capacity"}[30d]))
  / sum(increase(opendsec_apiserver_create_seconds_count{reason!~"invalid|unauthenticated|forbidden|not_found|quota_exceeded|rate_limited|conflict"}[30d]))
```

**调用方**：用调用方的接入包长时间运行 `soak.py`，再用 `soak_report.py` 汇总，可以按小时或按时间段统计：
```sh
python soak.py 172800 8 soak.csv     # 48 小时，8 个并发
python soak_report.py soak.csv
```
每次发版和改配置时都跑一遍 `load_test.py` 或 `soak.py`，看失败数（OPERATIONS §4）。

## 4. 错误预算用完时

- **预算剩余不到一半**：暂停非紧急的发版和配置变更，先查清楚错误的来源。
- **预算用完**：
  - 只做修复稳定性的变更，每次变更都要带压测；
  - 把原因和改进写进事故记录。
- **燃烧率告警触发**：按 OPERATIONS §5 的步骤排查，先看 `opendsec_apiserver_create_seconds_count` 按 `reason` 分组的变化，再看 edge 的 `opendsec_edge_rejected_total`。
