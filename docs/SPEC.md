# OpenDsec 复现实现规划 (Spec v0.1)

> 依据论文：*DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*（arXiv:2609.22978）。
> 本文先厘清系统组件与边界，再按阶段实现。**第一阶段只做「管控面 + sandbox 调度」**，节点侧真实运行时（容器/microVM 等）放到后续阶段。
>
> **技术栈**：服务端与 sandbox 内 agent 用 **Go**（单仓库、单 module，每个组件一个二进制）；**opendsec SDK 用 Python**（RL 框架生态），另附 Go client 供 CLI/测试使用。组件间协议为 **gRPC + protobuf**。
>
> 标注约定：**[论文]** = 论文明确给出；**[决定]** = 论文未说明、由本实现做出的设计决定（可讨论）。
>
> **实测环境**：文中的测量记录提到的机器，bm1、bm2 是两台裸金属（2× AMD EPYC 9Y24，384 线程，1.5 TB 内存，`/data` 是两块 NVMe 组的 RAID0，Ubuntu 24.04，宿主机内核 6.8）；ctl3 是一台 2 核 8G 的云主机。三台在同一个 VPC 里，§25 起镜像库是 bm2 导出的 NFS。

---

## 1. 目标与非目标

### 1.1 第一阶段 (P1) 目标
1. 跑通完整的控制链路：`opendsec SDK → apiserver → IAM → placement → edge`，以及后续操作路由 `apiserver → edge`。
2. 调度可验证：在单机上模拟数十到数百个 edge、上万 sandbox（edge 可单进程起多个实例），测出创建吞吐、负载均衡度、拒绝率。
3. 生命周期正确：创建 / 查询 / 停止 / TTL 回收 / 任务级批量 pause·resume·stop，配额占用与释放一致。
4. 组件可独立重启：apiserver、watcher、placement 无持久状态，重启后自愈 **[论文]**。

### 1.2 P1 非目标（后续阶段）
- 真实隔离运行时（容器 overlayfs/cgroup/bwrap、Firecracker、QEMU）、aether/chronus、命令执行。
- 镜像分层与按需加载（EROFS/3FS 的替代实现）、`pack_diff`。
- 网络策略执行（eBPF 的替代实现）、CPU QoS、内存回收。
- FnCall 后端、云上弹性的真实对接（P1 只做调度决策，云节点用模拟 edge 表示）。

P1 中 edge 用 **`sim` 后端**：完整实现 edge 的准入、状态机、TTL、统计上报，只是「启动 sandbox」是一段可配置延迟、不起真实进程。这样调度和管控逻辑与运行时彻底解耦，后续换成真实后端时管控面不改。

---

## 2. 总体架构

```
            训练侧 (trusted)                              集群 (sandbox 网络隔离)
 ┌──────────────────────────┐
 │ RL framework / harness   │
 │   opendsec SDK            │
 └────────────┬─────────────┘
              │ RPC (token)
   ┌──────────▼───────────┐  authn/authz/quota   ┌─────────┐
   │ apiserver × N        │─────────────────────▶│  IAM    │ (唯一有持久状态的管控组件)
   │  (无状态, ingress)    │                      └────▲────┘
   │  └ placement engine  │◀──── snapshot ────┐        │ reconcile leases
   │     (内嵌库, 无状态)   │                   │        │
   └──────────┬───────────┘             ┌─────┴────────┴┐
              │ forward (按 sandbox id    │  watcher       │ 周期探测 edge 健康 + 负载
              │  解析出 edge)              │  (无持久状态)   │
              ▼                          └─────┬──────────┘
   ┌───────────────────────────────────────────▼──────────────┐
   │ edge (每节点一个)                                          │
   │  准入控制 · 生命周期/TTL · 统计 · [P2+] 存储/网络/运行时        │
   │  backends: sim (P1) | container | microvm | fullvm | fncall │
   │        └── [P2+] aether ── chronus (sandbox 内)               │
   └──────────────────────────────────────────────────────────┘
```

**管控面组件（P1 范围）**：IAM、apiserver、placement engine、watcher、edge 的管控部分（edge-core）、opendsec SDK。
**节点运行时组件（P2+）**：edge 的运行时部分（存储/网络/后端）、aether、chronus。

---

## 3. 组件规格

### 3.1 通用：协议与错误码
- 所有跳统一用 **gRPC**（proto 定义在 `proto/opendsec/v1/`），Go 与 Python 由同一份 proto 生成代码。
  - 流式：`run_shell` 输出、watcher 快照订阅等用 server streaming。
  - 传输：TCP（集群内）、Unix socket（edge ↔ aether，P2）、vsock（edge ↔ VM 内 aether，P5）。
- 服务划分（proto service）：
  | service | 实现者 | 调用者 |
  |---|---|---|
  | `opendsec.v1.DSec` | apiserver | SDK / CLI（对外唯一入口）|
  | `opendsec.v1.IAM` | iam | apiserver、watcher、edge |
  | `opendsec.v1.Watcher` | watcher | apiserver、edge（注册）|
  | `opendsec.v1.Edge` | edge | apiserver、watcher |
- 认证：
  - 对外：metadata `authorization: Bearer <token>`，token 格式 `dsk.<principal>.<secret>`。
  - 内部：metadata `x-opendsec-service-token: <shared secret>`。**[决定]** 后续可换 mTLS。
- 错误映射到 gRPC status code，并在 `ErrorInfo.reason` 携带稳定原因字符串：
  | reason | gRPC code |
  |---|---|
  | `unauthenticated` | Unauthenticated |
  | `forbidden` | PermissionDenied |
  | `not_found` | NotFound |
  | `quota_exceeded` | ResourceExhausted |
  | `no_capacity` | Unavailable（可重试）|
  | `invalid` | InvalidArgument |
  | `timeout` | DeadlineExceeded |
  | `internal` | Internal |

### 3.2 IAM **[论文 §3]**
| 概念 | 说明 |
|---|---|
| Principal | user / service / agent，同一套管理 API 和鉴权模型 **[论文]** |
| Project | 任意深度嵌套，路径形如 `root/rl/job-42/agent-7` **[论文：多级嵌套]** |
| Policy | principal 在 project 上的权限集合，自动继承到所有子项目 **[决定]** |
| Quota | `sandboxes / cpu_cores / memory_mb / gpus`，缺省 = 继承父项目上限 |

**权限**：`sandbox.create` `sandbox.operate` `layer.publish` `layer.use` `project.admin`。

**有界委托** **[论文]**：
- 只能授予自己在该 project 上实际持有的权限。
- 子项目 quota 每一项 ≤ 所有祖先的对应 quota。

**配额占用（lease）** **[决定]**：
- 创建时 `reserve(lease, project, resources)`：沿祖先链逐级检查 `usage + req ≤ quota`，全部通过才一起扣减（原子，不部分扣减）。
- `lease` = sandbox id 的随机后缀 `R`（见 §4），与选到哪个 edge 无关，因此重试换节点时不用迁移 lease。
- 释放的两条路径：① edge 在 sandbox 终止时调用 `iam.release(R)`；② watcher 周期性用全集群存活集合调用 `iam.reconcile(live, min_age=60s)`，回收「edge 崩溃/消息丢失」导致的泄漏；`min_age` 用来保护创建中的 lease。
- usage 不持久化；IAM 重启后，watcher 的下一次 reconcile 会带上全集群存活 lease（含 project 与资源），IAM 据此重建 usage。重建完成前 quota 检查可能偏松，这一点可以接受。

**RPC**：`Admit`（创建热路径：认证 + 鉴权 + 预留，一次往返）、`Authenticate`、`Authorize`、`Release`、`Reconcile`、管理类 `CreateProject / CreatePrincipal / Grant / Revoke / SetQuota / GetProject`。
`Reconcile(live_leases, min_age)` 同时承担两件事：释放不在存活集合中、且年龄超过 `min_age` 的 lease；把存活但 IAM 不知道的 lease 补记（IAM 重启后据此重建 usage）。
**持久化**：P1 用 JSON 文件（principal、project、policy、quota），原子 rename 写入。**[决定]** 后续可换 sqlite。

### 3.3 apiserver **[论文 §3]**
- 唯一入口：训练侧与 sandbox 网络之间唯一允许的路径。
- **不保存任何 per-sandbox 状态**：sandbox id 编码所属 edge，任一实例都能直接转发。
- 周期从 watcher 拉 edge 列表 + 负载快照（默认 1s **[决定]**），交给内嵌的 placement engine。
- 可水平扩展 N 个实例，彼此不通信。

**创建流程** **[论文]**：
```
SDK ──create(args)──▶ apiserver
  1. placement.pick(req)                       → edge E，选中即记入本实例的在途叠加  (无候选 → no_capacity)
  2. iam.admit(token, project, perms=[sandbox.create], lease=R, resources, edge=E)   # 失败 → cancel，直接返回
  3. edge[E].sandbox.create(id=E.R, ...)       # edge 做最终准入
       ├ ok        → 返回 sandbox 描述
       └ no_capacity / unavailable → placement.cancel + penalize(E)，排除 E 重选，同一个 lease 改绑，最多 3 次 **[决定]**
  4. 全部失败 → iam.release(R)，返回 no_capacity
```
**[实现中修订]** 原方案先 admit 再选点。现在先选点，admit 时把 lease 绑定到选中的 edge（§15.2）：这台 edge 崩溃时，它的配额不用等下一轮对账就能释放。
**操作流程**：`sandbox.<op>(id)` → 解析出 `edge_id` → 鉴权（`sandbox.operate` on 该 sandbox 的 project；project 从 edge 返回的 sandbox 元数据读取，apiserver 设短 TTL 本地缓存 **[决定]**）→ 转发给 edge → P2 起 edge 再转给 aether/chronus。

**任务级操作**（RL 抢占/结束时整批处理）**[论文 §5]**：`task.pause|resume|stop(task_id)` → 向**所有健康 edge** 扇出，由 edge 按 project 子树 + task 过滤。**[实现中修订]** 原方案按快照里的 `by_task` 只发给相关 edge，但快照会滞后于其他 apiserver 实例刚完成的放置，可能漏掉 sandbox；edge 数量为百级，全量扇出的成本可以接受。

**对外 API（SDK 可见）**：
| 方法 | 说明 |
|---|---|
| `sandbox.create` / `sandbox.create_batch` | 单个/批量创建（批量用于一个 job 申请上万 sandbox **[论文：单 job ≤32K]**）|
| `sandbox.get` / `sandbox.list` | 查询（list 支持 project / task 过滤，扇出到 edge）|
| `sandbox.stop` / `sandbox.pause` / `sandbox.resume` / `sandbox.touch` | 生命周期；`touch` 刷新 idle TTL |
| `task.pause` / `task.resume` / `task.stop` / `task.stats` | 任务级 |
| `iam.*` | 管理 API，透传到 IAM，actor = 已认证 principal |
| `cluster.status` | 集群概况（edge 数、各后端用量、利用率）|
| `sandbox.exec` 等运行时操作 | P2 实现，P1 在 sim 后端返回 `invalid` |

### 3.4 placement engine **[论文 §3]**
以库的形式内嵌在每个 apiserver 中 **[决定：论文把它列为独立组件，但它无状态、而且「每个实例叠加自己的近期放置」这一点说明实例与 apiserver 一一对应，所以内嵌更简单；接口保持独立，需要时可单独部署]**。

**两阶段**：
1. **Filter**：edge `healthy`、未 `draining`，支持请求的 `backend`，硬件满足（`gpus`、`gpu_mode`），剩余容量 ≥ 请求，`zone` 符合（onprem/cloud，见 bursting）。
2. **Rank：power-of-k choices** **[论文，引 Mitzenmacher；k 未给出]**：在候选中均匀随机取 k 个（默认 `k=2` **[决定]**），选 load 最小者；平局随机。

**load 定义** **[决定，论文未定义]**：
```
load(E) = max( cpu_alloc/cpu_cap, mem_alloc/mem_cap, n_sandboxes/max_sandboxes )
cpu_cap = 物理核 × cpu_overcommit   (默认 8.0，依据论文「~90% sandbox 平均只用 ≤5% 申请 CPU」)
mem_cap = 物理内存 × mem_overcommit (默认 1.0；microVM 有 pmem/balloon 后可调高)
```
超卖系数配置在 **edge** 上（edge 是准入的最终决定方），edge 上报的 capacity 已是乘过系数的「可分配容量」，placement 直接使用，避免两处配置不一致。
**实际用量（2026-10-17）**：上面的 load 只看分配量。CPU 超卖 8 倍时，一台机器上的 sandbox 真把 CPU 用满，分配量看不出来，新 sandbox 还会继续放过来。所以 edge 在快照里另外上报宿主机的实际用量，load 取两者中较高的：
```
load(E) = max( 上面的分配量各项, cpu_used, mem_used )
cpu_used     = /proc/stat 里忙碌时间占全部 CPU 的比例，按 10 秒时间常数平滑（同 PSI 的 avg10）
mem_used     = 1 - MemAvailable / MemTotal
cpu_pressure = /proc/pressure/cpu 的 some avg10（%，有可运行的任务在等 CPU 的时间比例）
```
- 实际用量只影响排序，不进过滤：在途叠加只能叠加分配量，实际用量要等 sandbox 跑起来才看得到。不上报的旧版本 edge 等于 0，可以混跑。
- **底线 `placement.usage_floor`（默认 0.2）**：实际用量低于它时不参与。空闲时各机器的底噪不同（bm1 内存 1.6%，bm2 跑着 NFS 服务，3%），没有底线时 load 被底噪定死，空闲集群会把新 sandbox 一边倒地放到底噪低的机器上，直到它的分配量追上对方的底噪（线上每台 8000 个容器的配置下约 110 个）。设成 -1 表示不设底线。
- 硬限制用 CPU 压力：edge 配置 `cpu_pressure_limit`（%），超过就和内存压力一样拒绝新建、在快照里标为 `under_pressure`（`pressure: "cpu"`）。默认关闭：一大批创建本身就会推高 PSI，阈值要按节点的实测定。
- bm1 实测（384 线程，nice 19 的空循环，各 20 秒）：

  | 空循环数 | cpu_used | cpu_pressure | load average |
  |---|---|---|---|
  | 192（半数 CPU） | 0.50 | 0 | 55 |
  | 384（刚好占满） | 1.00 | **0** | 143 |
  | 768（2 倍超订） | 1.00 | **约 41–44**，20 秒时仍在上升 | 298 |

  利用率到 100% 就不再变化，PSI 只在任务开始排队等 CPU 后才上升；所以前者用来排序，后者用来做硬限制。
- **端到端实测**（2026-10-17，在 bm1、bm2 上临时起一套独立的测试集群：1 个 IAM、watcher、apiserver，每台机器一个容器 edge；线上集群不动，烧 CPU 期间线上 e1 排空）：
  - 两台都空闲：每轮新建 20 个，三轮都是 10 : 10。没有底线时是 13 : 7 和 15 : 5，底线就是因此加的。
  - bm1 跑 384 个 nice 19 空循环：开烧 2 秒时（`cpu_used` 0.20）还是 5 : 5，5 秒起（0.40）每批 10 个全部去 bm2。从机器变忙到被避开约 3–5 秒：10 秒平滑，加上 watcher 和 apiserver 各 1 秒的刷新。
  - `cpu_pressure_limit: 30`、768 个空循环：开烧 12 秒时 PSI 到 30.7，edge 标为 CPU 压力，新建返回 `no_capacity`，信息里写明「1 edge(s) under cpu pressure」；停烧 4 秒后 PSI 降到 25.9，压力解除，又能新建。
按后端分别有 `max_sandboxes`（论文：单节点稳定支持 3200 容器 / 800 microVM）。

**本地叠加（in-flight overlay）** **[论文]**：**选中节点时就**记入 `(edge, res, t)`（预占），edge 拒绝或不可达时撤销（`Cancel`）。计算 load 时只叠加 `t > edge.last_seen` 的记录（`last_seen` 为 watcher 向该 edge 发出探测的时间，之前的放置已包含在 edge 的上报里）；`t < last_seen - grace(2s)` 的记录丢弃。每个 edge 维护叠加量的累加和，单次选点的开销与放置速率无关。无需实例间协调。
**[实现中修订]** 最初只在创建成功后才记入叠加；批量创建时 256 个并发请求都看到同一份负载，全挤到同几个节点上，接近满载时 edge 大量拒绝（e2e 测试复现）。改为选点时预占后问题消失。
**失败反馈** **[决定]**：edge 拒绝后，该 edge 在本实例内冷却 `penalty=2s`，期间不进入候选。
**最终准入权在 edge** **[论文]**：placement 只做尽力而为的选择。

**云上弹性 (cloud bursting)** **[论文 §4.5]**：
- `u = Σ alloc / Σ cap`（只统计同后端、健康的 onprem edge）。
- 请求「可上云」⇔ `backend == container` 且镜像所有层都在 `burst_eligible_images` 集合中 **[论文：去重 EROFS 集合约 30TB，覆盖 70% 容器任务]**。
- `u > 0.8` **[论文阈值]** 时，可上云请求以概率 `p = min(1, (u-0.8)/(1-0.8))` 走 cloud edge 池 **[决定：论文只说「offload 一部分」]**；cloud 池也用 power-of-k。onprem 无候选时，可上云请求直接走 cloud。

### 3.5 watcher **[论文 §3]**
- 配置中给出静态 edge 列表（`edges: [{id, addr, zone}]`）；P1 同时支持 edge 启动时 `watcher.register` 自注册 **[决定]**。
- 每 `probe_interval`（默认 1s）对每个 edge 调 `edge.status`（带超时 0.5s），连续 3 次失败标记 `unhealthy`，成功 1 次恢复 **[决定]**。
- 收集调度状态 **[论文]**：每 edge 各后端运行 sandbox 数，并按 user / project / task 细分；每 edge 的 capacity、alloc、实际压力指标（P1 sim 中等于 alloc）。
- 对外：`GetSnapshot`（apiserver 拉取；带 `version`、`taken_at`）、`Register`（edge 自注册，周期重发以便 watcher 重启后恢复）。
- 无持久状态，重启后重新轮询 edge 重建视图 **[论文]**。
- 周期（默认 30s）驱动一次 IAM lease reconcile **[决定]**。

快照结构：
```json
{"version": 1042, "taken_at": 1739.2,
 "edges": [{"id": "e003", "addr": "10.0.0.3:7000", "zone": "onprem", "healthy": true,
            "draining": false, "backends": ["container", "sim"],
            "capacity": {"cpu_cores": 192, "memory_mb": 1572864, "gpus": 0,
                         "max_sandboxes": {"container": 3200, "microvm": 800}},
            "alloc": {"cpu_cores": 812.0, "memory_mb": 401408, "gpus": 0},
            "count": {"container": 211}, "by_task": {"job-42": 180}, "by_project": {"root/rl": 211}}]}
```

### 3.6 edge（P1：edge-core）**[论文 §3]**
P1 实现与运行时无关的部分；后端通过统一接口插入。

**职责**：
- **准入** **[论文]**：在本地重新检查容量（防止 placement 快照过期造成超卖）；实际压力达到临界（P2：内存 PSI / `memory.current`）也拒绝 → `no_capacity`。
- **sandbox 状态机** **[决定]**：
  ```
  CREATING ─▶ RUNNING ⇄ PAUSED  (PAUSING / RESUMING 为过渡态)
      │          │
      └─▶ FAILED  └─▶ STOPPING ─▶ STOPPED
  ```
  对 PAUSED sandbox 发起任何操作会先透明 resume **[论文]**。
- **TTL** **[论文：显式 stop 或 TTL 到期回收]**：
  - `ttl_running_stop`：空闲超时（距最后一次操作的秒数）**[论文示例注释为 idle timeout]**；PAUSED 期间不计时 **[决定]**。
  - `ttl_max`：绝对生命周期上限（可选）**[决定]**。
  - 后台 reaper 每秒扫描。
- **资源释放**：终止时释放本地资源并 `iam.release(R)`（失败交给 reconcile 兜底）。
- **健康** **[论文]**：P2 起监控 aether 通道，断开即标 FAILED。
- **draining**：运维摘除节点，不再接收新建 **[决定]**。

**后端接口**（P1 只实现 `sim`）：
```python
class Backend:
    name: str
    async def create(sb: SandboxRecord) -> None
    async def stop(sb) -> None
    async def pause(sb) -> None
    async def resume(sb) -> None
    async def probe(sb) -> bool          # 存活检查
    def capacity() -> dict               # max_sandboxes 等
```
`sim` 参数：创建延迟分布（默认 lognormal，中位数 50ms）、失败率、可选「崩溃」注入，用于测试。

**RPC**（apiserver/watcher 调用）：`edge.status`、`sandbox.create`、`sandbox.get`、`sandbox.list`、`sandbox.stop`、`sandbox.pause`、`sandbox.resume`、`sandbox.touch`、`task.pause|resume|stop`、`edge.drain`。

### 3.7 opendsec SDK **[论文 §3，示例代码]**
保持与论文示例一致：
```python
client = DSecClient(endpoint="127.0.0.1:7100", token=..., project="root/rl")
await client.open()
args = DSecContainerRunArgs(
    container_image="registry.../sphinx-9658:official",
    memory_limit_mb=4096, cpu_cores_limit=4,
    ttl_running_stop=300,                      # idle timeout
    network_rules={"npm": False, "pypi": True},
    init_user="root",
    task_id="job-42", qos="LS",                # [决定] 扩展字段
)
sandbox = await client.run_container(args, timeout=120)   # timeout = 创建超时 [决定]
result = await sandbox.run_shell("echo hello world")     # P2
await sandbox.stop()
```
- 论文说明 SDK **不**试图抽象所有后端，由调用方选后端 **[论文]**：`run_container` / `run_microvm` / `run_vm` / `fncall`，各有自己的 `*RunArgs`。
- P1 提供：`run_container`（选 `backend="sim"` 时走模拟）、`run_containers`（批量）、`Sandbox.{stop,pause,resume,status,touch}`、`client.{pause_task,resume_task,stop_task,list_sandboxes,iam}`。

---

## 4. 标识与路由
- **edge id**：`[a-z0-9-]{1,32}`，配置给定，集群内唯一。
- **sandbox id**：`<edge_id>.<R>`，`R` 为 16 字节随机数的 base32（小写、无填充）。**[论文：id 编码所属 edge]**
- apiserver 根据 watcher 拿到的 `edge_id → addr` 映射转发；未知 edge → `not_found`。
- `R` 同时作为 IAM lease key（§3.2）。

---

## 5. 故障与一致性
| 场景 | 处理 |
|---|---|
| apiserver 崩溃 | 无状态，SDK 重连其他实例；进行中的创建若 edge 已成功但响应丢失 → sandbox 存在但调用方不知道，依赖 idle TTL 回收 **[决定]**；SDK 可凭 `R` 幂等重试（edge 对已存在 id 返回原记录）|
| watcher 崩溃 | apiserver 继续用最后一次快照（标记 stale，超过 10s 后只用 overlay + 随机）；watcher 重启后重新轮询 |
| IAM 崩溃 | 新建失败（fail closed）；已有 sandbox 不受影响；重启后 rebuild usage |
| edge 崩溃 | watcher 标 unhealthy → 不再被选；其 sandbox 视为丢失；lease 由 reconcile 回收 |
| 放置竞争超卖 | edge 本地准入兜底，apiserver 换节点重试 |

---

## 6. 配置（单个 YAML/JSON，P1 用 JSON）
```json
{
  "service_token": "...",
  "iam":       {"addr": "127.0.0.1:7001", "state": "./state/iam.json", "admin_token": "dsk.admin.xxx"},
  "watcher":   {"addr": "127.0.0.1:7002", "probe_interval": 1.0, "reconcile_interval": 30},
  "apiserver": [{"addr": "127.0.0.1:7100"}],
  "placement": {"k": 2, "burst_threshold": 0.8, "burst_eligible_images": ["..."], "max_attempts": 3},
  "edges": [{"id": "e001", "addr": "127.0.0.1:7201", "zone": "onprem",
             "backends": {"sim": {"max_sandboxes": 3200}},
             "capacity": {"cpu_cores": 192, "memory_mb": 1572864, "gpus": 0},
             "cpu_overcommit": 8.0, "mem_overcommit": 1.0}]
}
```
`opendsecctl cluster up --config ... [--sim-edges 100]`：本地一键起整套（多个 edge 可跑在同一进程内，便于规模测试）。

---

## 7. 代码结构
```
go.mod                        # module opendsec (单 module)
proto/opendsec/v1/*.proto         # 所有服务与消息定义
gen/go/opendsec/v1/               # protoc 生成的 Go 代码（入库）
cmd/
  opendsec-iam/                   # IAM 服务
  opendsec-watcher/               # watcher
  opendsec-apiserver/             # apiserver（内嵌 placement）
  opendsec-edge/                  # edge（P1: sim 后端，可单进程起多个 edge）
  opendsecctl/                    # CLI：cluster up、iam 管理、sandbox 操作、bench
internal/
  ids/                        # sandbox id / lease
  config/                     # 配置加载
  rpcutil/                    # 认证 interceptor、错误映射、客户端连接池
  iam/                        # 纯逻辑 + gRPC service + JSON 持久化
  watcher/
  placement/                  # 纯逻辑，可独立单测/基准
  apiserver/
  edge/                       # core: 准入、状态机、TTL、统计
  edge/backend/               # 后端接口 + sim（P1）；container/fncall/microvm/fullvm（P2+）
  cluster/                    # 本地一键启动（多进程或单进程多实例）
pkg/client/                   # Go client（opendsecctl 与 e2e 测试使用）
sdk/python/opendsec/           # Python SDK（DSecClient / DSecContainerRunArgs / Sandbox）
test/e2e/                     # 多进程端到端测试
bench/                        # 调度基准
```
P2+ 的 sandbox 内 agent：`cmd/opendsec-aether`、`cmd/opendsec-chronus`（静态编译，挂载进 sandbox）。

## 8. 测试与验收（P1）
**单元**
- IAM：嵌套继承、越权授予被拒、子 quota 超父被拒、reserve 原子性、release 幂等、reconcile 的 min_age。
- placement：filter 各条件；k=1 退化为随机；overlay 叠加与过期；冷却；bursting 阈值与可上云判定。
- edge-core：准入超限拒绝、状态机非法转换、idle TTL 与 pause 不计时、ttl_max、终止时调用 release。

**端到端**（真实多进程：IAM + watcher + 2 个 apiserver + 若干 sim edge）
- SDK 创建 → 停止，quota 回到 0。
- 杀掉一个 edge：watcher 标记 unhealthy，新请求不再落到该节点；其 lease 被 reconcile 回收。
- 重启 apiserver / watcher 不影响已存在 sandbox 的操作。
- 任务级 pause/resume/stop 只触达相关 edge。

**基准**（单机，100 个 sim edge，同进程）
- 指标：创建吞吐（目标：单 apiserver ≥ 5000/s 模拟创建，对齐论文集群级 >5000/s **[决定]**）、`max_load / mean_load`（power-of-2 应明显优于随机）、edge 拒绝率。
- 运行：`opendsecctl bench -edges 100 -n 20000 -c 256 -compare`。

**P1 实测**（开发机：**1 vCPU**，压测客户端、apiserver、IAM、100 个 edge 全部共用这一个核；每次创建走完整链路，3 次 gRPC 往返）：
| | 吞吐 | p50 / p99 延迟 | 每 edge sandbox 数 max/mean | 标准差 | edge 拒绝 |
|---|---|---|---|---|---|
| k=1（随机）| 1582/s | 152 / 408 ms | 1.225 | 14.6 | 0 |
| k=2 | 1535/s | 157 / 297 ms | **1.015** | **1.17** | 0 |
- 均衡度达标；power-of-2 同时降低了尾延迟。
- 吞吐未达到 5000/s。CPU profile 显示时间主要花在 gRPC 传输（系统调用）、GC 和 goroutine 栈扩张上，OpenDsec 自身逻辑（placement、edge 统计）约占 1–2%；延迟主要是 256 并发在单核上的排队时间。这个目标需要在多核机器、apiserver 多实例下重新测量。

---

## 9. 阶段路线
| 阶段 | 内容 | 依赖 |
|---|---|---|
| **P1 管控 + 调度** | §3 全部组件 + sim 后端 + SDK 生命周期 + 测试/基准 | — |
| P2 容器运行时 | container 后端（overlayfs + cgroup v2 + 命名空间）、aether/chronus、`run_shell`/文件/流式 I/O、aether 通道健康检测 | P1 |
| P3 环境与网络 | 分层镜像（base/workspace/toolkit）、按需加载 vs 全量拉取、`pack_diff` 与 builder/runtime 账号分离、网络策略（默认拒绝 + 动态更新）、文件访问限制 | P2 |
| P4 RL 协同 | 容器 pause/resume（freeze + swap + `memory.reclaim` / `MADV_WILLNEED`）、CPU QoS（LS/BE）、FnCall 后端（预建池、GPU 共享/独占）、解耦 rollout 示例 | P2 |
| P5 VM 类后端 | Firecracker microVM（快照式 pause）、QEMU full VM、vsock 通道、pmem/balloon | P2，需要硬件 |

---

## 10. P1 实现状态
- 已完成：§3 全部管控组件（IAM、apiserver + 内嵌 placement、watcher、edge-core + sim 后端）、Go client、`opendsecctl`、Python SDK（`sdk/python/opendsec`，接口与论文示例一致）、单元测试、e2e 测试、基准、多进程部署示例（`deploy/opendsec.example.json`）。
- `cluster.Backends` 在 P1 中把配置里的**每个**后端名（container / microvm …）都映射到 sim 后端，因此按后端划分的调度现在就能测；P2 起逐个替换为真实运行时。
- 已知局限（留待后续阶段）：
  - 组件间未加 TLS，内部认证只靠共享 service token。
  - IAM 持久化为 JSON 文件，单实例。
  - edge 重启会丢失其 sandbox 记录（sim 后端本来也没有真实进程）；P2 起需要从运行时恢复。
  - `ListSandboxes` 遇到不可达的 edge 时返回部分结果，只记日志，不报错。

## 11. P2 设计：容器运行时 + aether / chronus

### 11.1 范围
- **container 后端**（Linux）：overlayfs 组装 rootfs，独立 ext4 可写盘，cgroup v2 限额，namespace 隔离，cgroup freeze 实现 pause。
- **aether**（sandbox 内代理）与 **chronus**（shell 会话），都用 Go 写、静态编译，挂载进 sandbox。
- 对外运行时 API：执行命令（阻塞 / 后台 / 流式）、异步取输出、文件读写与目录操作、sandbox 内 HTTP 请求、会话管理。
- edge 通过 aether 通道检测健康：**通道断开 → 标记 FAILED** **[论文]**。
- 不在 P2：分层镜像与按需加载、`pack_diff`（P3）；网络策略（P3，P2 的 sandbox **完全无外网**，只有 lo）；swap + `memory.reclaim`、CPU QoS（P4）。

### 11.2 sandbox 结构（container 后端）
```
host: <state_dir>/<edge_id>/sb/<lease>/
        disk.img   稀疏 ext4 镜像，大小 = disk_mb（默认 10 GiB），loop 挂载到 disk/   ← 磁盘配额 [决定]
        disk/upper disk/work                                           ← overlay 可写层（宿主机可见，便于 P3 pack_diff）
        run/       aether.sock、chronus-<session>.sock、会话输出记录      ← 挂载到 sandbox 内 /.opendsec/run
cgroup: /sys/fs/cgroup/opendsec/<edge_id>/<lease>/   memory.max  cpu.max  pids.max  (BE: cpu.idle=1)
sandbox 内:  / = overlay(lower = 镜像各层, upper = disk/upper)
             /.opendsec/bin  aether + chronus（只读 bind）
             /proc /dev(最小集) /dev/pts /dev/shm /sys(只读)
             /sys/fs/cgroup  cgroup2 只读，经 cgroup namespace 只看到本 sandbox 的 cgroup
        image.json 创建时解析出的层列表（快照 / fork 叠在它上面，不受镜像 tag 之后被覆盖影响）
namespaces:  mnt pid uts ipc net（仅 lo）cgroup
```
- 镜像解析：P2 用 edge 配置里的静态映射 `images: {"<name>": ["<lowerdir 顶层>", ..., "<底层>"]}`；内置 `host` 镜像（以宿主机 `/` 只读作为 lower）。P3 换成分层镜像库，接口不变。
- 启动方式：edge 用 `CLONE_NEW*` 重新执行自身（`opendsec-sandbox-init`，与 runc / docker reexec 思路相同），进程在创建时直接放入 cgroup（`CgroupFD`）。
- sandbox 内能读到自己的 cgroup（`/sys/fs/cgroup/memory.max`、`cpu.max`），Go、JVM 等运行时据此按 sandbox 的限额而不是宿主机的核数设置自己；init 在挂载之前就已启动，edge 直接给它设置 `GOMAXPROCS = max(2, ceil(cpu_cores))`。缺了这一步，在 384 线程的宿主机上，64 MB 的 sandbox 中 aether 自身的 Go 运行时就会超出内存上限被 OOM 杀掉（在裸金属测试机上发现）。init 在新 mount ns 中挂 overlay 和 /proc /dev 等，`pivot_root`，拉起 lo，然后 exec `/.opendsec/bin/opendsec-aether --init`。
- **PID 1 = `opendsec-aether --init`**：只负责回收孤儿进程并转发信号，它 fork 出 aether 服务进程；aether 退出时 init 也退出，sandbox 随之结束。**[决定]**
- 停止：关闭 aether 通道 → `cgroup.kill` → 等待 init 退出 → 卸载可写盘（loop 设备 autoclear）→ 删除 sandbox 目录与 cgroup。
- 暂停 / 恢复：`cgroup.freeze` = 1 / 0。P4 补上 swap + `memory.reclaim` / `MADV_WILLNEED`。
- edge 启动时清理本 edge 遗留的 sandbox（杀掉 cgroup、卸载磁盘、删除目录）。P2 不做 edge 重启后的状态恢复。**[决定]**

### 11.3 aether / chronus **[论文 §3]**
- edge ↔ aether：gRPC over Unix socket（`run/aether.sock`）。VM 后端（P5）同一套 `Runtime` 服务改走 vsock。
- aether 按 `session`（默认 `default`）查找或创建 chronus 进程（每个会话一个独立进程，`run/chronus-<session>.sock`），把请求原样转发；`CloseSession` 时杀掉该 chronus 的**整棵进程树**。
- edge 与 aether 保持一条 `Watch` 心跳流；流断开且 sandbox 应处于运行中 → FAILED。
- chronus = **一个持久 shell 会话**（优先 bash，没有就用 sh）：`cd`、`export` 的状态在命令之间保留。
  - 同一会话内命令串行执行；需要并发就开多个会话。**[决定]**
  - 每条命令的 stdout/stderr 记录到 `run/sessions/<session>/<id>.{out,err}`，可以断开后再按偏移量取（`GetOutput`）。
  - 超时：先对 shell 的所有子孙进程发 SIGTERM，3 秒后 SIGKILL；如果是 shell 内建命令的死循环，就重启 shell。
  - 文件 API 直接在 chronus 进程里执行（不经过 shell），相对路径以会话的初始工作目录为基准。
  - `init_user` 不是 root 时，shell 以该用户身份运行（读取 sandbox 内的 `/etc/passwd`）。

### 11.4 API（`proto/opendsec/v1/runtime.proto`）
同一组消息在三层复用：`OpenDsec`（对外，带 `sandbox_id`）→ `Edge`（转发）→ `Runtime`（aether 与 chronus 都实现这个服务）。

| RPC | 说明 |
|---|---|
| `Exec` | 阻塞执行；`background=true` 时立即返回 `cmd_id` |
| `ExecStream` | 流式事件：`started` → `stdout` / `stderr` 片段 → `exit` |
| `GetOutput` | 按 `cmd_id` 和偏移量取记录的输出，可选等待命令结束 |
| `ReadFile` / `WriteFile` / `ListDir` / `Stat` / `Remove` | 文件操作 |
| `Http` | 从 sandbox 内部发起 HTTP 请求（P2 只能访问 sandbox 内的服务）|
| `ListSessions` / `CloseSession` | 会话管理 |

edge 处理每个运行时请求时：先透明 resume（如果 sandbox 处于暂停状态），再刷新 idle TTL，然后转发。apiserver 的鉴权与生命周期操作相同（需要 `sandbox.operate`）。
单次 `Exec` 返回的输出上限 16 MiB（超出时 `truncated=true`），其余部分用 `GetOutput` 分段取。

### 11.5 配置增量
```json
"edges": [{
  "state_dir": "/var/lib/opendsec", "agent_dir": "/opt/opendsec/bin",
  "images": {"python:3.12": ["/srv/images/python312"]},
  "backends": {"container": {"runtime": "linux", "max_sandboxes": 3200, "default_disk_mb": 10240}}
}]
```
`runtime` 默认为 `sim`，P1 的配置因此保持兼容。

### 11.6 测试
- chronus 单元测试（直接在宿主机上跑）：状态保持、后台执行与取输出、超时杀进程、流式输出、文件 API、shell 意外退出后自动重启。
- container 后端测试（需要 root + cgroup v2 + overlayfs，条件不满足时 skip）：rootfs 与隔离（pid ns 下 PID 1、只有 lo、主机名）、cgroup 限额生效、可写盘配额、pause 冻结、stop 后资源清理、杀掉 aether 后 edge 标记 FAILED。
- e2e：SDK → apiserver → edge → aether → chronus 全链路 `run_shell`。

### 11.7 P2 实现状态
- 已完成：container 后端（`internal/edge/backend/container`）、aether / chronus（`cmd/opendsec-aether`、`cmd/opendsec-chronus`，静态编译）、edge / apiserver 的运行时转发、Python SDK 运行时接口（`run_shell` / `stream_shell` / `run_shell_background` + `get_output` / 文件 / `http` / 会话）、`opendsecctl exec` / `cp`、`opendsecctl cluster up -runtime linux`。
- 测试：chronus 单元测试；container 后端测试（隔离、限额、磁盘配额、冻结、清理、aether 死亡上报、遗留清理）；全链路 e2e；SDK 测试。全部在 `-race` 下多次重复运行稳定，跑完后没有残留的挂载、loop 设备、cgroup 或进程。
- **实现中修订**（测试或实测发现，均已修复）：
  1. **daemon 进程逃出会话进程树**：`(server &)` 这种两次 fork 的进程会被托管给 PID 1，`CloseSession` 杀不到。修复：chronus 设为 child subreaper（`PR_SET_CHILD_SUBREAPER`），并自行回收托管来的孤儿进程。
  2. **socket 文件出现 ≠ 服务已就绪**：`bind()` 先于 `listen()`，edge→aether、aether→chronus 两处偶发 `connection refused`。修复：以第一次心跳或连接成功为准，在超时内重试。
  3. **edge 退出时遗留 sandbox**：edge 停止时没有停掉自己的 sandbox。修复：`Edge.Shutdown` 停止全部 sandbox 并删除 edge 的 cgroup。edge 被强杀（无法执行清理）时，同一 `state_dir` 下次启动会自动清理，实测一次清掉 162 个遗留 sandbox，耗时 4 秒。
  4. **主机 OOM（实测事故）**：在 950 MB 内存的开发机上压测时，主机被打到全局 OOM。原因有两个：`cluster up` 给 edge 填的是虚构容量（1.5 TB 内存）；edge 准入只看已分配量，不看实际内存压力。修复：
     - 未配置容量时**从主机自动探测**（CPU 数、MemTotal）。
     - edge 增加**内存压力准入**：`MemAvailable` 低于预留值（`mem_reserve_mb`，默认取内存的 10%，至少 128 MB）时拒绝新建 **[论文：edge 在资源压力临界时拒绝放置]**。
     - edge 状态里上报 `under_pressure` / `mem_available_mb`，placement 跳过处于压力状态的 edge。
     - 复测：请求 30 个、只放得下 7 个时，其余 23 个返回 `no_capacity`，主机剩余 641 MB 可用。
- **实测**（1 vCPU / 950 MB 开发机，宿主机镜像，时间都包含 `opendsecctl` 进程启动约 20–30 ms）：
  | 指标 | 数值 |
  |---|---|
  | 创建（SDK→apiserver→IAM→placement→edge→rootfs + 磁盘 + cgroup + namespace→aether 就绪）| 160–300 ms |
  | 会话第一条命令（拉起 chronus + shell）| 100–300 ms |
  | 之后的命令 | 30–60 ms |
  | 每个 sandbox 内存（cgroup `memory.current`）| 空闲 4.6 MB；有 1 个会话时 9.9 MB |
- 已知局限：
  - 镜像目前只有静态配置的 lowerdir（以及开发用的 `host` 镜像，它会把宿主机文件暴露给 sandbox），P3 换成分层镜像。
  - sandbox 没有外网，P3 加网络策略。（已完成，§20）
  - 没有 seccomp / AppArmor，sandbox 内是 root（P3 的防护措施）。（§21 加上了 capability 限制和 seccomp；AppArmor 仍然没有。）
  - edge 重启后不恢复 sandbox，只做清理。

## 13. 管控加固 H1：edge 状态持久化与重新接管

### 13.1 目标
- edge 进程重启（升级、崩溃、被 OOM 杀掉）**不影响**正在运行的 sandbox：重启后 sandbox 继续可用，状态、会话、配额都不变。
- 这是滚动升级 edge 的前提（RL sandbox 寿命的 p99 超过 3 小时 **[论文]**）。

### 13.2 持久化
- 位置：`<state_dir>/<edge_id>/records/<lease>.json`，每个 sandbox 一个文件，用「临时文件 + fsync + rename」原子写入。
- 内容：sandbox 记录（id、project、principal、spec、state、created_at）。
- 写入时机：
  - 进入 CREATING 时**先写**，这样崩溃发生在创建中途时，重启后也知道这个 sandbox 存在，可以清理并释放它。
  - 状态稳定后（RUNNING / PAUSED）再写一次。
  - 进入终态时删除文件。
- **不持久化** `last_active`：恢复时重置为恢复时刻，相当于给每个 sandbox 一个新的空闲窗口，只会推迟回收，不会误回收。**[决定]**
- 开关 `persist_state`：有 linux 运行时的 edge 默认开启；sim 默认关闭（sim 没有真实资源需要恢复）。

### 13.3 后端运行时状态（container）
- `sb/<lease>/state.json`：记录 init 进程的宿主机 pid 和 `starttime`（取自 `/proc/<pid>/stat` 第 22 列，用来防止 pid 被复用后认错进程）。
- edge 进程死后，sandbox init 进程被系统 init 接管（创建时已经 `setsid`，不受 SIGHUP 影响）；可写盘挂载在宿主机 mount namespace 里，也随之保留。
- 接管（`Adopt`）步骤：
  1. 确认 init 进程仍然存活且 `starttime` 一致，并且仍在本 sandbox 的 cgroup 里。
  2. 确认可写盘仍处于挂载状态。
  3. 重连 aether 的 Unix socket，收到第一个心跳为止。
  4. 从 `cgroup.events` 读出是否处于冻结状态，从而得知 sandbox 是 PAUSED 还是 RUNNING。
- 存活判断：自己拉起的 sandbox 等待子进程退出；接管来的 sandbox（不是 edge 的子进程）检查 pid + `starttime`，再结合 aether 心跳流是否断开。

### 13.4 恢复流程（edge 启动时，开始服务之前）
1. 读取全部记录，逐个交给后端 `Adopt`：
   - RUNNING / PAUSED：接管成功则恢复原状态，并重新计入分配量；失败则标记 FAILED，清理资源并释放 lease。
   - CREATING / STOPPING 等过渡态：一律清理并释放 lease，因为 apiserver 那边的创建调用早已失败，或者调用方本来就要停止它。
2. 后端清理：删除没有对应记录、或接管失败的 sandbox 目录、cgroup 和挂载。
3. 然后才开始监听端口。watcher 探测成功后，这个 edge 重新被视为健康。

### 13.5 退出语义
- `keep_sandboxes_on_exit`：生产环境设为 true，edge 退出时只关闭连接，不停 sandbox。默认 false，因此开发集群和测试退出时会停掉 sandbox，不留残留。
- edge 重启期间：apiserver 发给该 edge 的请求返回 `unavailable`；对客户端而言，进行中的流式调用会断开。但 sandbox 内的命令继续执行，输出照常记录，重连后可以按 `cmd_id` 用 `GetOutput` 取回。

### 13.6 测试
- edge-core（sim + 持久化）：模拟崩溃后恢复，RUNNING / PAUSED 状态和分配量都正确；CREATING 状态的记录被清理，lease 被释放。
- container 后端：不经关闭流程直接丢弃 backend 对象来模拟崩溃 → 新 backend 接管 → 同一个 shell 会话里之前 `export` 的变量还在，崩溃前启动的后台命令输出可以取回；崩溃期间 aether 死掉的 sandbox 接管失败并被清理；PAUSED 的 sandbox 恢复后仍是 PAUSED。
- e2e：在不停 sandbox 的情况下重启 edge 组件 → GetSandbox、exec 正常，配额不变，没有资源残留。

### 13.7 实现状态
- 已完成：
  - edge 记录持久化（`internal/edge/store.go`）与启动时恢复（`internal/edge/recover.go`）。
  - container 后端的 `Adopt`、`CleanupExcept`、`Detach`，以及 init 进程的 pid 和 `starttime` 持久化。
  - `persist_state`、`keep_sandboxes_on_exit` 两个配置项。
- 测试：
  - edge-core 恢复测试（sim）。
  - container 接管测试：会话状态和跨重启的命令都保留；PAUSED 的 sandbox 恢复后仍是 PAUSED；停机期间死掉的 sandbox 被清理；接管来的 sandbox 也能检测到丢失。
  - e2e 不停 sandbox 重启 edge，重复多次稳定。
  - **多进程冒烟测试：`kill -9` 掉 `opendsec-edge` 进程后重启**，sandbox 进程一直存活；约 200 ms 后恢复服务（`adopted=1`），连 shell 进程都是同一个；崩溃时正在执行的命令在 sandbox 内继续跑完，输出可以取回；配额不变。
- 实测：单个 sandbox 接管耗时约 7 ms。
- **实现中修订**：
  1. **gRPC 重连退避**：edge 重启后，apiserver 和 watcher 到它的连接还在 gRPC 默认退避里（最长 120 秒），edge 已恢复，请求却继续失败。修复：内部连接的退避上限设为 2 秒；watcher 报告 edge 由不健康转为健康时，apiserver 立即重置该连接的退避。实测 edge 重启后约 110 ms 即可重新访问到 sandbox。
  2. `container.New` 不再自动清理遗留 sandbox，改由 edge 先接管有记录的，再对其余调用 `CleanupExcept`。
- 仍未覆盖：
  - edge 停机期间，客户端进行中的流式调用会断开，需要客户端重连后用 `GetOutput` 取回（SDK 尚未自动重试）。
  - 记录文件 rename 后没有对所在目录做 fsync，主机掉电时有极小概率丢失最近一次写入；丢失的后果只是遗留 sandbox 被清理，不会造成状态错乱。

## 14. 管控加固 H2：mTLS、token 生命周期、审计日志

### 14.1 组件间 mTLS（替代共享 service token）
- **集群 CA**：`opendsecctl pki init -config opendsec.json -out <dir>` 生成 CA（ECDSA P-256），并为配置里的每个组件签发证书：`iam`、`watcher`、`apiserver-<i>`、`edge-<id>`。
  - 证书身份写在 URI SAN 里：`opendsec://<role>/<id>`，例如 `opendsec://edge/e001`、`opendsec://apiserver/0`。
  - 所有证书带 DNS SAN `opendsec.internal`，加上各自监听地址的主机名或 IP。
- 配置：`"tls": {"dir": "<dir>"}`，目录下放 `ca.crt` 和 `<name>.crt` / `<name>.key`。配置了 `tls` 就启用 mTLS；不配置时退回 service token 模式（仅限开发）。
- **双向校验**：
  - 服务端要求客户端证书（`RequireAndVerifyClientCert`），并从证书里取出调用方身份。
  - 客户端连接 edge 时校验对方证书身份必须是 `edge/<要连的 id>`，防止有人在别的地址冒充某个 edge。
- **按方法授权**（同时只允许必要的调用方）：

  | 服务 | 方法 | 允许的调用方 |
  |---|---|---|
  | IAM | `Release` | edge、apiserver |
  | IAM | `Reconcile` | watcher |
  | IAM | 其余 | apiserver |
  | Watcher | `GetSnapshot` | apiserver |
  | Watcher | `Register` | edge，且**只能注册自己证书里的 id** |
  | Edge | `Status` | watcher、apiserver |
  | Edge | 其余 | apiserver |
- edge ↔ aether 仍走本地 Unix socket，只靠文件权限（0600，root）保护，不加 TLS **[决定]**。

### 14.2 对外 TLS
- 启用 `tls` 时，apiserver 对外端口也走 TLS（服务端证书即 `apiserver-<i>`，不要求客户端证书）。
- SDK 和 `opendsecctl` 增加 `ca_file` / `-ca` 参数。

### 14.3 token 生命周期
- token 格式 `dsk.<principal>.<token_id>.<secret>`，IAM 只存 secret 的哈希。
  - 旧的三段式 `dsk.<principal>.<secret>` 视为该主体的「主 token」，继续兼容（例如配置文件里的 bootstrap admin token）。
- 每个 token 带过期时间（`ttl_s`，0 表示不过期）。IAM 配置 `max_token_ttl_s` 限制最长有效期，设置后不能再签发永不过期的 token。
- 新增 RPC：
  - `CreateToken(principal, ttl_s, description)`：本人可以为自己签发；对该主体所属项目有 `project.admin` 的人也可以签发（所属项目即创建它时指定的项目）。
  - `ListTokens(principal)`：不返回 secret。
  - `RevokeToken(principal, token_id)`。
  - `DeletePrincipal(principal)`：同时作废它的全部 token，删除它在所有项目上的授权。
  - `DeleteProject(path)`：要求没有子项目，并且当前用量为 0。
- **吊销及时生效**：IAM 维护一个安全版本号 `security_epoch`，在吊销 token、撤销权限、删除主体或项目时递增。apiserver 每秒读取一次，发现变化就清空认证和鉴权缓存，因此吊销在约 1 秒内对全部 apiserver 实例生效，不再是原来最长 30 秒的缓存期。

### 14.4 审计日志
- 由 apiserver 记录，因为它是唯一的对外入口。格式是 JSON Lines，追加写入 `<audit_dir>/audit-<apiserver>-<启动时间>.log`，单个文件超过 `audit_max_mb`（默认 256）就换新文件，只保留最新的 `audit_keep` 个（默认 8，§33.2）。需要更久的审计记录，要把它们转存到别处。
- 每条记录：时间、请求 id、principal、方法、project、sandbox_id / task_id、结果（状态码和原因）、耗时、客户端地址。
- 记录范围：
  - 管理操作和生命周期操作（创建、停止、暂停、恢复、任务级操作、IAM 管理）**总是记录**。
  - 运行时操作（exec、文件、http）数量极大，与只读查询（GetSandbox、ListSandboxes、ClusterStatus、WhoAmI、GetProject、ListTokens）一起由 `audit_runtime` 控制，默认关闭；开启时 `exec` 只记命令长度和 SHA-256，不记命令原文。**[实现中修订：只读查询也归入这一类，避免 RL 框架频繁轮询状态把审计日志刷满]**
- 认证失败也要记录：principal 为空，原因记为 `unauthenticated`。
- 异步写入，带缓冲。缓冲满时宁可阻塞请求，也不丢审计记录 **[决定]**。

### 14.5 测试
- 单元测试：证书签发与身份解析；ACL 的放行和拒绝；token 过期、吊销、主 token 兼容、签发权限；安全版本号递增；审计记录的格式与切换文件。
- e2e（启用 TLS 的集群）：
  - 不带证书的客户端、带错误身份证书的客户端（例如用 edge 证书去调用 IAM 的 `Admit`）都被拒绝。
  - 冒充其他 id 注册 edge 会被拒绝。
  - 吊销 token 后约 1 秒失效；过期 token 失效。
  - 审计文件里有对应的记录。
- SDK 测试：通过 TLS 连接 apiserver 并完成操作。

### 14.6 实现状态
- 已完成：
  - `internal/pki`：CA 与组件证书的签发、身份解析。
  - `rpcutil`：mTLS 与按方法授权的拦截器，连接 edge 时校验对方身份。
  - watcher 只允许 edge 注册自己的 id。
  - 对外 TLS。
  - IAM 的 token 生命周期：签发、列出、吊销、过期、`max_token_ttl_s`、删除主体和项目、安全版本号；apiserver 据版本号清空缓存，缓存也不会超过 token 本身的有效期。
  - 审计日志：请求 id 通过响应头 `x-opendsec-request-id` 返回给客户端，日志按大小切换文件，写入不丢记录。
  - `opendsecctl pki init`、`token create/list/revoke`、`principal delete`、`project delete`、`-ca`；`cluster up -tls -audit-dir`。
  - Python SDK 的 `ca_file` 以及 token 管理接口。
- 测试：
  - 单元测试：PKI、token、审计切换文件。
  - e2e（TLS 集群）：不加密的客户端被拒、信任了其他 CA 的客户端拒绝服务端证书、不带客户端证书无法完成握手、edge 证书不能调用 `Admit`、edge 不能注册其他 id 也不能读快照、watcher 不能在 edge 上创建 sandbox、连 edge 时对方身份不符会被拒、TLS 模式下 service token 无效、吊销跨 apiserver 约 1 秒生效（实测 0.98 秒）、过期 token 即使在缓存里也失效、审计记录的字段正确（认证失败也会记录）。
  - SDK 通过 TLS 访问并管理 token。
  - **多进程 TLS 冒烟测试**：`pki init` 签发证书 → 四类组件各自独立启动 → `opendsecctl -ca` 访问正常，审计落盘正常。
- 已知局限：
  - 证书不能自动轮换，也没有 CRL / OCSP，组件证书到期前需要重新签发并重启。
  - `ca.key` 由运维自行保管（`pki init` 会提示离线保存）。
  - IAM 仍是单实例。
  - 审计日志只写本地文件，没有接入集中式日志系统。

## 15. 管控加固 H3：IAM 高可用 + 按 edge 增量对账

### 15.1 IAM 多副本（内置 Raft）**[决定]**
- 使用 hashicorp/raft，推荐 3 或 5 个副本；日志和元数据存在 BoltDB 里，快照存文件。不依赖外部存储。
- **复制状态机**：主体、项目、策略、配额、token、**配额 lease**、安全版本号，全部通过 Raft 日志复制，切主或重启后不丢。原来 lease 只放在内存里、重启后要靠对账重建的问题因此消失；对账仍然保留，作为兜底。
- **确定性**：随机数（token secret、token id）和时间戳由提议者在发起变更时生成并写进命令；状态机执行时只读取命令里的值，所以各副本执行结果完全一致。
  - 鉴权检查（actor 是否有权限）也在状态机里做，保证判断依据的是已提交的状态。
- **读请求**：在 leader 上直接读本地状态，不额外确认自己仍是 leader（省掉每次读的一轮网络确认），换来的代价是切主瞬间可能读到短暂过期的数据。**[决定]**
- **follower 转发**：任意副本都可以接受请求，follower 把请求原样转发给当前 leader。选主期间返回 `unavailable`，由客户端重试。
- **客户端**：apiserver、watcher、edge 配置全部副本的地址，按 round-robin 发送；遇到 `UNAVAILABLE` 透明重试（最多 3 次，带退避）。
  - 重试是安全的：`Admit`（同一个 lease）、`Release`、对账都是幂等的；管理类操作被重放时会得到 `exists` 之类的错误，不会重复执行。
- **启动**：
  - 节点上还没有 Raft 状态时，用配置里的完整成员列表初始化集群（每个节点使用相同的成员配置，可以安全地同时初始化）。
  - 当选 leader 后，提交一次幂等的 bootstrap 命令，创建 root 项目和 admin。多副本模式**必须配置 `admin_token`**，否则不同副本会各自生成不同的 token。
- **mTLS**：Raft 复制流量走 TLS，只接受 `iam/*` 身份。证书按副本签发：`iam-<id>`。
- 兼容性：只配置一个 IAM 地址时保持原来的单机模式（JSON 文件）不变。

配置：
```json
"iam": {"replicas": [
  {"id": "0", "addr": "10.0.0.1:7001", "raft_addr": "10.0.0.1:7011", "data_dir": "/var/lib/opendsec/iam"},
  {"id": "1", "addr": "10.0.0.2:7001", "raft_addr": "10.0.0.2:7011", "data_dir": "/var/lib/opendsec/iam"},
  {"id": "2", "addr": "10.0.0.3:7001", "raft_addr": "10.0.0.3:7011", "data_dir": "/var/lib/opendsec/iam"}],
 "admin_token": "dsk.admin.<secret>"}
```

### 15.2 按 edge 增量对账（替代全集群一次性对账）
- 原有问题：
  - 只要有一个「健康」的 edge 读不到，整轮对账就跳过，规模大了以后几乎永远在跳过。
  - 一次请求带上全集群的 lease（38 万个约 30 MB）。
- 新做法：IAM 为每个 lease 记录它属于哪个 edge，并维护按 edge 的索引。
  - `ReconcileEdge(edge, live_leases, min_age)`：
    - 把上报的 lease 记到该 edge 名下；IAM 没有记录的，补记占用（adopt）。
    - 记在该 edge 名下、但这次没有上报、且年龄超过 `min_age` 的 lease，予以释放。
  - `SweepUnbound(max_age)`：还没被任何 edge 认领、且年龄超过 `max_age` 的 lease 予以释放（默认 10 分钟，大于创建超时的 5 分钟）。这类 lease 来自失败的创建，而它们的释放消息丢了。
  - leader 先计算出差异，只把差异写进 Raft 日志，所以常态下每次对账的日志很小。
- watcher 每一轮：
  - 对每个可达的 edge 各自调用 `ReconcileEdge`，互不影响；某个 edge 读不到，只是这一轮跳过它。
  - edge 持续不健康超过 `lost_edge_grace`（默认 120 秒）时，按「无存活 sandbox」调用一次，释放它名下的配额 **[决定]**。原来的做法是标记不健康后立即释放；有了 H1 的状态恢复，edge 很可能会带着 sandbox 回来，所以留出宽限期。
  - 最后调用一次 `SweepUnbound`。
- edge 带着 sandbox 回来时，下一次 `ReconcileEdge` 会重新补记它的配额。

### 15.3 测试
- IAM 单元测试：状态机确定性（同一组命令在两个实例上执行，结果一致）；快照与恢复；增量对账的各个分支（补记、释放、宽限期、未认领 lease 清理、同一 lease 被两个 edge 上报的冲突）。
- Raft 集成测试（进程内 3 副本，真实 TCP 和 TLS）：
  - 写入后各副本状态一致；follower 收到的请求被转发。
  - 杀掉 leader 后选出新 leader，Admit 和管理操作继续可用，已有的配额占用、token 和吊销都还在。
  - 恢复的副本追上进度。
- e2e：在 3 副本 IAM 上运行整个集群，创建过程中杀掉 IAM leader，创建请求最多重试一次即可成功，最终配额完全一致。
- 压测：Raft 模式下的创建吞吐（每次 Admit 都要经过一次 Raft 提交）。

### 15.4 实现状态
- 已完成：
  - IAM 改为命令式状态机（`internal/iam/commands.go`），单机模式与 Raft 模式共用同一套状态机代码。
  - Raft 副本（`raft.go`）：BoltDB 存储、快照、mTLS 复制通道（只接受 `iam/*` 身份）。
  - follower 转发请求到 leader；客户端连接多个副本，按 round-robin 发送，遇到 `UNAVAILABLE` 透明重试。
  - leader 上任后执行幂等的 bootstrap。
  - `opendsec-iam -replica <id>`；`pki init` 按副本签发证书 `iam-<id>`。
  - 按 edge 增量对账（`ReconcileEdge`、`SweepUnbound`），watcher 对丢失的 edge 留出 `lost_edge_grace` 宽限期。
- **实现中修订**：
  1. **lease 在准入时就绑定 edge**。原设计只在对账时才记录 lease 属于哪个 edge，这样 edge 若在首次对账（30 秒）前崩溃，它的 lease 没有归属，要等 10 分钟后的未认领清理才会释放（e2e 测试暴露了这个问题）。现在 apiserver 改为**先选点、再调用 `Admit`（带上 edge）**；换节点重试时以同一个 lease 再次 `Admit`，只是把归属改到新 edge。正常路径上仍然只有一次 Raft 写入。没有任何 edge 放得下时，会补做一次只读的 `Admit`，以保证认证、鉴权错误仍然优先返回。
  2. **BoltDB 文件锁**：`raft.Shutdown()` 不会关闭日志存储，同一进程内重启副本时会无限期等锁。现在关闭时一并关闭存储，打开数据库时设 5 秒超时。
- 测试：
  - 增量对账的各个分支；状态机确定性（同一组命令在两个实例上执行，结果一致）；快照与恢复。
  - 3 副本 Raft 集成测试（明文与 TLS 各一遍）：切主约 1 秒后用量、token、配额限制都还在；重启的副本能追上进度；edge 证书无法加入复制。
  - **e2e：在 3 副本 IAM + mTLS 集群上，8 个并发 worker 持续创建，期间杀掉 IAM leader**。三次运行均在 0.9–1.3 秒内完成切主，创建 1366–1572 个，**失败 0 次**；配额用量和存活 sandbox 数精确一致；切主后吊销仍然有效；重启的副本追上进度；所有 lease 都有 edge 归属。
  - 多进程冒烟测试：3 个 `opendsec-iam` 进程，对 leader 执行 `kill -9`，另一个副本接任，创建继续进行，配额统计一致。
- 压测（1 vCPU，3 个副本与全部组件共用这一个核和同一块盘）：单机 IAM 约 1960 次/秒，3 副本 Raft 约 1110 次/秒；p50 延迟从 130 ms 升到 232 ms，失败 0 次。
- 已知局限：
  - 读请求在 leader 本地处理，没有做 lease read，切主瞬间可能读到短暂过期的数据。
  - 不支持在线增删副本，需要停机修改配置。
  - Raft 日志的快照阈值是固定值，尚未按规模调优。

## 16. 部署加固 D1：watcher 多实例 + 部署清单

### 16.1 watcher 多实例
- **读路径，所有实例都工作**：
  - 每个实例都独立探测全部 edge、生成快照。
  - apiserver 配置全部 watcher 地址，按 round-robin 拉取，失败自动切到其他实例。
  - edge 向每个 watcher 都注册。
  - placement 只按 `taken_at` 判断快照的新旧：不同实例的 `version` 计数器互不可比。
- **写路径（对账），只由 leader 执行**：
  - 对账会根据「edge 失联」释放配额。某个实例如果只是自己和 edge 之间的网络断了，会误判 edge 已死；实例越多，出现这种误判的机会越多，所以只让一个实例做对账。
  - 选主用 IAM 提供的**租约锁**：`AcquireLock(name, holder, ttl)`，状态放在 IAM 的 Raft 状态机里。锁空闲、已过期、或者调用方本来就是持有者时，才授予或续期，并返回当前持有者及其到期时间。
  - watcher 每 `ttl/3` 续期一次（默认 ttl 为 10 秒）。只有在「本地记录的获锁时刻 + ttl − 2 秒」之前，才认为自己仍是 leader：用自己的单调时钟计时，不受各机器之间时钟偏差的影响。
  - 正常退出时主动 `ReleaseLock`，让其他实例立即接任，不必等租约过期。
  - leader 失效后，最迟约一个 ttl 内由其他实例接任；这期间只是暂停对账，不影响创建和其他操作。
- 配置：`"watcher": {"replicas": [{"id": "0", "addr": "..."}, ...]}`；单个 `addr` 的写法继续兼容。证书按实例签发：`watcher-<id>`。

### 16.2 动态 edge（Kubernetes / 大规模节点）
- `edge_template`：作为 edge 的默认配置，凡是没有列在 `edges` 里的 edge 都套用它。
  - `opendsec-edge -id <id> -advertise <host:port>` 用这份模板启动；watcher 通过 edge 的注册发现它。
  - edge id 必须符合 `[a-z0-9-]{1,32}`，可以取节点名，必要时做一下转换。
- 每个 edge 的证书在**节点上线时签发**：`opendsecctl pki issue -ca <dir> -role edge -id <id> -hosts <ip> -out <dir>`，放到节点本地的 `/etc/opendsec/pki`。每台机器的证书带着自己的 edge 身份，watcher「只能注册自己」和 apiserver「校验 edge 身份」这两条检查才有意义。**[决定]**

### 16.3 部署清单（`deploy/`）
- `Dockerfile`：一个镜像包含全部二进制，基于 debian-slim，自带 `e2fsprogs`，因为 edge 要用 `mkfs.ext4`。
- `systemd/`：
  - `opendsec-iam@.service`（实例名即副本 id）、`opendsec-watcher@.service`、`opendsec-apiserver@.service`：以普通用户运行，使用 `StateDirectory`，并开启常用的进程防护选项。
  - `opendsec-edge.service`：以 root 运行；`KillMode=process`。sandbox 位于 `/sys/fs/cgroup/opendsec/...`，不在这个服务自己的 cgroup 里，因此重启或升级 edge 不会连带杀掉 sandbox，与 `keep_sandboxes_on_exit` 的语义一致。
- `k8s/`：
  - IAM：StatefulSet，3 副本，每个副本一个 PVC，配一个 headless Service；副本 id 取 Pod 序号。
  - watcher：Deployment，2 副本。
  - apiserver：Deployment，加 Service。
  - edge：DaemonSet，privileged、hostNetwork，挂载宿主机的 `/sys/fs/cgroup`、`/dev`、state 目录和证书目录。
  - 公共部分：配置用 ConfigMap，集群级组件的证书用 Secret。
- 验证：systemd unit 用 `systemd-analyze verify` 检查；Kubernetes 清单做 YAML 解析和结构检查（这台机器没有 Kubernetes 集群，只能做静态检查）。

### 16.4 测试
- IAM 锁：获取、续期、过期后被其他实例接管、被其他实例持有时拒绝、主动释放；状态写进快照。
- e2e：2 个 watcher。同一时刻只有一个执行对账；杀掉 leader 后另一个在 ttl 内接任；任何一个 watcher 挂掉，apiserver 都还能拿到快照；edge 向两个 watcher 都注册了。
- 动态 edge：一个不在 `edges` 列表里的 edge 用模板启动，被 watcher 发现，sandbox 能调度到它上面。

### 16.5 实现状态
- 已完成：
  - IAM 租约锁（`AcquireLock` / `ReleaseLock`，在 Raft 状态机里，写进快照）。
  - watcher 多实例：配置 `watcher.replicas`；对账由持锁的实例执行；按 `taken_at` 判断快照新旧；edge 向所有 watcher 注册；`opendsec-watcher -replica`。
  - 动态 edge：`edge_template`，以及 `opendsec-edge -id/-addr/-advertise`。
  - `opendsecctl pki issue`；证书中跳过 `0.0.0.0` 这类无意义的地址。
  - `deploy/`：Dockerfile、systemd unit、Kubernetes 清单和部署文档。
- 测试：
  - 锁的单元测试（获取、续期、过期接管、非持有者无法释放、快照恢复）。
  - e2e（TLS）：始终恰好一个对账 leader，2 秒内的密集采样中从未出现两个；动态 edge 被两个 watcher 发现，sandbox 能调度上去；leader watcher 正常退出后，另一个约 250 ms 接任（它主动释放了锁；崩溃时则要等租约 ttl 过期）；一个 watcher 挂掉后，apiserver 仍能拿到新快照。
- 部署清单的验证：systemd unit 通过 `systemd-analyze verify`；Kubernetes 清单做了 YAML 解析和结构检查。**均未在真实环境中运行。** edge DaemonSet 的 `hostPID`、`mountPropagation: Bidirectional` 和宿主机 cgroup 挂载，是 edge 重启后重新接管 sandbox 的前提，需要在目标集群上验证。
- 已知局限：
  - Kubernetes 下，所有集群级组件共用一个 `opendsec-pki` Secret，任何一个组件的 Pod 都能读到其他组件的私钥。生产环境建议用 cert-manager，按组件分别签发证书。
  - 组件还没有标准的 gRPC 健康检查接口，探针暂时只做 TCP 端口检测。

## 17. P3（镜像部分）：镜像感知调度、共享镜像库、pack_diff

### 17.1 镜像感知调度（兜底修复）
- 问题：镜像是每个 edge 的静态配置，placement 并不知道哪些 edge 有哪个镜像。请求被调度到没有该镜像的 edge 时，edge 返回 `invalid`，而 apiserver 只在 `no_capacity` / `unavailable` 时换节点，所以**不会重试**，直接失败。
- 修复：
  - 后端可以选择实现 `Images()` 接口，返回本机可用的镜像列表（返回 nil 表示不限制）。edge 在状态中按后端上报这个列表。
  - placement 过滤掉没有所需镜像的 edge。
  - **所有** edge 都没有这个镜像时，返回 `not_found`（「镜像在任何节点上都不可用」），而不是含糊的 `no_capacity`。
  - edge 收到自己没有的镜像（例如快照过期时）返回 `no_capacity`，apiserver 换节点重试。
- 启用共享镜像库以后，所有 edge 都能读到所有镜像，`Images()` 返回 nil，也就不再按镜像过滤。

### 17.2 共享镜像库 **[论文 §4.1、§4.4]**
- 配置：集群级 `"image_store": {"root": "/mnt/opendsec-images"}`。这是一个所有 edge 和 apiserver 都挂载的共享文件系统（论文用 3FS；这里可以用 CephFS、JuiceFS、NFS 等）。
- 存储布局：
  ```
  <root>/layers/<layer-id>/rootfs/...   层内容，发布后不再修改；文件按 overlay 格式存放（删除标记为 0:0 字符设备，opaque 目录带 xattr）
  <root>/layers/<layer-id>/meta.json    {id, size, source, created_at, created_by}
  <root>/images/<project>/<repo>/<tag>.json   镜像清单
  ```
  - 层 id：从 OCI 导入的层用 `sha256-<压缩包摘要>`，内容相同的层只存一份（去重）；`pack_diff` 产生的层用 `diff-<随机串>`。
  - 写入方式：先写到 `<id>.tmp-*`，完成后 rename 到正式位置，所以中途失败不会留下半个层。
- **镜像名格式**：`<项目路径>/<repo>:<tag>`，例如 `root/rl/python:3.12`。镜像归属于这个项目，按项目鉴权。
  - 没有项目前缀的名字（例如 `python:3.12`）仍然表示 edge 本地的静态镜像，兼容 P2 的配置。
- **镜像清单**：`{name, layers（从底到顶）, env, workdir, user, parent, created_at, created_by, source}`。
- **edge 如何使用**：
  - 读取镜像清单（清单不可变，edge 在内存里缓存），按层 id 拼出 overlay 的只读层路径（最上层排在最前），直接指向共享存储上的目录。
  - 这就是**按需加载**：sandbox 读到哪个文件才从共享存储取哪个文件。论文统计实际只会读到镜像的 4%–13%。
  - 镜像清单里的 env / workdir / user 作为 sandbox 的默认值。
- **组合式镜像** **[论文：base / workspace / toolkit 分层]**：`ComposeImage(name, parts=[底层镜像, ..., 顶层镜像])` 把各部分的层列表按顺序拼起来，不复制任何数据。
  - 好处：升级一个 toolkit 时，所有用到它的组合镜像只需重新登记一份清单，不用重建 N 个镜像。

### 17.3 权限
| 操作 | 需要的权限 |
|---|---|
| 登记 / 组合 / 删除镜像，`pack_diff` 的目标镜像 | 对目标镜像所属项目有 `layer.publish` |
| 用某个镜像创建 sandbox；作为 `ComposeImage` 的组成部分 | 对该镜像所属项目有 `layer.use` |
| `pack_diff` 的源 sandbox | 对 sandbox 所属项目有 `sandbox.operate` |

- 这样就能实现论文里**构建环境的账号与跑任务的账号分离**：跑任务的账号只有 `layer.use`，不能发布镜像，也就没法把东西写进别人会用到的镜像里。

### 17.4 `pack_diff` **[论文 §5]**
- `PackDiff(sandbox_id, image, scrub)`：
  1. edge 冻结 sandbox，保证可写层内容一致。
  2. 把可写层（宿主机上的 `disk/upper`）复制到共享存储，成为一个新层；保留删除标记和 xattr。
  3. 解冻 sandbox。
  4. apiserver 登记新镜像：层列表 = 源镜像的层 + 新的 diff 层，`parent` 指向源镜像。
- 默认清理以下内容，避免构建残留进入镜像：`tmp/*`、`var/tmp/*`、`root/.cache`、`*/.bash_history`、`.opendsec`（运行时挂载点）。
- 只有源镜像来自共享镜像库时才能执行：静态镜像的层不在共享存储上，没法拼进新镜像。

### 17.5 OCI 导入：`opendsecctl image import`
- 在构建机上运行：需要 root，并且挂载了共享存储。步骤：
  1. 从镜像仓库拉取镜像清单。如果是多平台清单，选 linux/amd64。
  2. 逐层下载并解压，把 OCI 的删除标记转换成 overlay 的格式：`.wh.<name>` 转成 0:0 字符设备，`.wh..wh..opq` 转成 opaque xattr。
  3. 读取镜像配置里的 Env / WorkingDir / User。
  4. 调用 `RegisterImage` 登记，按 `layer.publish` 鉴权。
- 支持 Docker Hub 匿名拉取，以及带 bearer token 认证的镜像仓库。
- **解压安全**：拒绝绝对路径和 `..`；写入前逐级检查父目录，**任何一级是符号链接就拒绝**，防止恶意层先建一个指向宿主机的链接、再往里写文件；硬链接只能指向层内的文件。
- 已经存在的层直接跳过，实现去重。

### 17.6 API
- 对外：`RegisterImage`、`ComposeImage`、`GetImage`、`ListImages(project)`、`DeleteImage`、`PackDiff`。
- edge 内部：`PackDiff`（写出层）。
- 删除镜像只删清单；不再被任何清单引用的层，由后续的垃圾回收清理（本阶段不实现）。

### 17.7 测试
- 镜像感知调度：只有部分节点有镜像时，请求只落到这些节点；没有任何节点有镜像时返回 `not_found`；快照过期导致落错节点时，换节点后成功。
- 镜像库：清单的读写、组合、拼出 overlay 层路径、按名字解析项目。
- OCI：用测试内建的假镜像仓库（不访问外网）验证导入，包括删除标记与 opaque 目录的转换、Env / WorkingDir、去重，以及**路径穿越和符号链接攻击被拒绝**。
- 容器 e2e：从共享库镜像启动 sandbox，镜像的 env / workdir 生效；底层的删除在上层可见；`pack_diff` 的结果作为新镜像启动后，包含之前写入的文件、不含被清理的内容，之前删除的文件仍然不存在；权限检查（只有 `layer.use` 的账号不能 `pack_diff`）。
- 冒烟：从 Docker Hub 导入一个小镜像（alpine）并在 sandbox 里运行。

### 17.8 实现状态
- 已完成：
  - 镜像感知调度：edge 按后端上报可用镜像，placement 据此过滤；所有 edge 都没有该镜像时返回 `not_found`；落到没有镜像的 edge 时返回 `no_capacity`，可以换节点重试。
  - `internal/images`：镜像库的层和清单读写、组合、拼出 overlay 层路径、OCI 导入（Docker Hub 匿名 token、多平台清单、层摘要校验、删除标记转换、安全解包）。
  - edge 从共享存储叠加镜像层，镜像清单里的 env / workdir / user 作为默认值；edge 的 `PackDiff`。
  - 对外镜像 API 加 `PackDiff`，按 `layer.publish` / `layer.use` 鉴权。
  - `opendsecctl image import/compose/list/get/delete/pack`；`cluster up -image-store`；SDK 的 `pack_diff`、`list_images`、`get_image`、`compose_image`、`delete_image`。
  - 部署清单加上了共享镜像库：Kubernetes 用 RWX PVC，systemd 给 apiserver 加了 `ReadWritePaths`。
- 测试：
  - 单元测试：镜像名解析、层与清单的读写和去重、清理规则；用测试内建的假镜像仓库验证 OCI 导入（多平台清单选择、token 认证、删除标记与 opaque 目录、硬链接与符号链接、再次导入不重复下载）；4 种恶意层（`..` 路径穿越、借符号链接写出去、嵌套的符号链接、硬链接指向层外）全部被拒绝，且没有写到层目录之外。
  - 镜像感知调度：单元测试加 e2e，镜像只存在于部分节点时请求只落到这些节点。
  - 容器 e2e：组合镜像、镜像默认值生效、删除标记在真实 overlay 上生效；`pack_diff` 得到的新镜像带有构建产物，构建残留被清理，源 sandbox 里的删除得以保留，源 sandbox 继续运行；只有 `layer.use` 的账号不能发布镜像；没有 `layer.use` 的账号不能用镜像创建 sandbox；未知镜像返回 `not_found`。
  - **真实镜像冒烟测试**：从 Docker Hub 导入 `alpine:3.20`（3.6 MB 用时 2.2 秒；再次导入直接复用已有层）→ 在 sandbox 里运行 alpine 的 `/bin/sh` 和 `apk` → `pack_diff` → 新 sandbox 中带有新写的文件，被删除的文件仍然不存在；SDK 的镜像接口全部验证通过。
- **实现中修订**：只有配置了 `image_store` 时，带 `/` 的镜像名才按镜像库镜像处理。最初的实现不论是否配置都这样处理，导致论文示例里 `registry.example/...` 这种名字在没有镜像库的集群上报 `unavailable`，是 SDK 测试发现的回归。
- 未做 / 已知局限：
  - 没有层的垃圾回收：删除镜像只删清单，层留在存储里。（已完成：`opendsecctl image gc`，§24）
  - 层格式是目录，没有用 EROFS 打包。
  - 没有做按需加载与全量拉取的对比实验（论文中 8192 个容器突发创建，两者分别为 35 分钟和 60 分钟以上）。
  - 不支持 zstd 压缩的层，也不支持需要用户名密码的私有镜像仓库。（之后都已支持，见 §35。）
  - 多个 apiserver 用 `overwrite` 写同一个镜像名时，最后一次写入生效。

## 18. 管控加固 H4：准入补强（TTL、磁盘、限流）

目标：堵住上线后会慢慢把集群拖垮的三个口子——忘了设 TTL 的 sandbox 永不回收、稀疏盘把节点磁盘写满、单个客户端的请求洪峰直接压到 IAM 和 placement。

### 18.1 TTL 默认值与上限（apiserver）
- 配置 `admission.default_ttl_running_stop_s`（默认 3600）、`default_ttl_max_s`（默认 86400）、`max_ttl_max_s`（默认 7 天）。0 表示用内置默认值，-1 表示不设。
- 请求里 TTL 为 0 时填入默认值；`ttl_max_s` 超过上限返回 `invalid`（与 token 的 `max_token_ttl_s` 一致：拒绝，不悄悄截断）。默认生命周期大于上限时按上限；没有默认生命周期但有上限时，用上限。
- 生效的 TTL 写进 sandbox 的 spec，`GetSandbox` 能看到。
- 空闲 TTL 只在 RUNNING 时计时（暂停不计），因此暂停的 sandbox 最终由 `ttl_max` 回收。

### 18.2 磁盘准入（edge + placement）
- 每个 sandbox 按可写盘大小记账：请求的 `disk_mb`，或后端的 `default_disk_mb`（linux 运行时默认 10240）。edge 把实际大小写回 spec。
- 容量：`capacity.disk_mb × disk_overcommit`（默认 1）。linux 运行时下 `disk_mb` 为 0 时取 `state_dir` 所在文件系统的大小。sim 后端不设则不限。
- 实际空闲空间：可写盘是稀疏文件，记账看不到 sandbox 实际写了多少，所以另外检查 `state_dir` 所在文件系统的空闲空间，低于 `disk_reserve_mb`（0 = 自动，文件系统的 5%，至少 1 GB；-1 关闭）时拒绝创建，并在状态里上报 `under_pressure`、`pressure: "disk"`、`disk_available_mb`。
- placement：`Capacity` 新增 `disk_mb` 和每个后端的 `default_disk_mb`，按与 edge 相同的规则过滤和计算负载（负载取 cpu / 内存 / gpu / 磁盘 / 槽位中的最大值）；预占（overlay）也计磁盘。
- 所有 edge 都放不下时，错误信息会说明有几个 edge 处于内存或磁盘压力下。
- **取舍**：`disk_overcommit` 默认 1，保证所有 sandbox 同时写满也不会撑爆节点；调大可以提高密度，但 sandbox 真写满时会在自己的盘里遇到 ENOSPC。

### 18.3 限流（apiserver）
- 新错误原因 `rate_limited`（gRPC `RESOURCE_EXHAUSTED`），表示请调用方退避重试。
- **请求速率**：每个 principal 每秒 `request_rate` 次（默认 10000，突发 2 倍），包括 exec / 文件 / http 调用。一个 RL 任务用一个账号驱动成千上万个 sandbox，默认值只拦失控的客户端。
- **创建速率**：每个 principal 每秒 `create_rate` 个 sandbox（默认 2000，突发 32768，即一整批）。单个创建超速直接返回 `rate_limited`；批量创建则在服务端排队按速率放行，不会让一批里的一部分失败。
- **认证失败**：每个客户端地址每秒 `auth_fail_rate` 次（默认 5，突发 2 倍）。超过后，来自这个地址、且不在认证缓存里的 token 被拒绝，不再去问 IAM；已经认证过（在缓存里）的 token 不受影响。
- **并发创建上限**：每个 apiserver 同时进行的创建最多 `max_inflight_creates` 个（默认 2048），超出的排队等待，限制一个 apiserver 打到 IAM 和 edge 上的并发。
- 限流在拦截器里做，排在审计之后，被拒的调用也会进审计日志。
- 限额按 apiserver 实例计算：N 个实例时，一个 principal 最多能拿到 N 倍。

### 18.4 测试
- 单元测试：令牌桶（突发、按速率回填、按 key 隔离、等待会按速率放行、取消的等待把令牌退回）；TTL 默认值、显式值、上限、默认值大于上限、-1 关闭；edge 磁盘记账（默认盘大小写回 spec、超出容量拒绝并说明是磁盘、停止后释放、空闲空间不足时拒绝并上报压力）；placement 按磁盘过滤、overlay 计磁盘、压力原因写进错误。
- e2e（真实 gRPC）：默认 TTL 出现在 sandbox 的 spec 里、超过上限被拒；连续单个创建超过突发后被限流；30 个的批量创建全部成功且耗时符合速率；另一个 principal 不受影响；错误 token 超过突发后被限流，而已认证的 principal 照常可用。
- 回归时发现：容器 e2e 的 `state_dir` 在一个 476 MB、只剩 279 MB 的 tmpfs 上，新的空闲空间检查（默认保留 1 GB）让所有节点都处于磁盘压力，创建全部失败——检查是对的，测试改为显式设置小容量和小保留值。同时发现原来的报错只有 "no edge can host"，看不出原因，于是在错误里加上了压力说明；随后 SDK 测试遇到同样的 tmpfs 问题，新的报错直接给出了「2 个 edge 处于磁盘压力」。

### 18.5 实现状态
- 已完成：18.1–18.4 全部内容；`opendsecctl cluster up -runtime linux` 的开发集群用 1 GB 默认盘、4 倍超配，空闲空间保留值可用 `-disk-reserve-mb` 调整（默认 512 MB）；部署示例配置加上了 `admission` 段和 edge 的磁盘参数；SDK 加了 `RATE_LIMITED`。
- **实现中修订**：认证失败限流最初在查认证缓存之前检查，导致一个客户端猜 token 会连累同一地址上已认证的用户，e2e 测试发现后改为缓存命中的 token 跳过这项检查。
- 未做 / 已知局限：
  - 限额不跨 apiserver 共享（见 18.3）。
  - 认证失败按客户端地址计数：如果 apiserver 前面的负载均衡做了 SNAT，所有客户端看起来来自同一地址，需要保留源地址，或把 `auth_fail_rate` 设为 -1。
  - IAM 配额不包含磁盘，磁盘只在节点层面限制。
  - 不限制单个 sandbox 的磁盘 IO 带宽（cgroup io.max）。（已完成：后端配置 `disk_io`，§24）

## 19. 设计 V1：Firecracker 主力后端 + 快照 / fork（参考 E2B）

> 状态：**F0–F4 已完成**（实现记录见 19.9–19.13；F2 已经包含带内存的 fork；F3 的 userfaultfd 按需拉页没有做，原因见 19.12；F4 的 DAMON 放在 guest 内核里，宿主机内核不用改，见 19.13）。开发机没有 KVM；F1 起在一台带 KVM 的裸金属测试机上开发和验证（2 × EPYC 9Y24 共 384 线程、1.5 TB 内存、2 × 3.5T NVMe RAID0、Ubuntu 24.04 / 内核 6.8）。
> 参考：E2B 开源后端 e2b-dev/infra 的 `spec/openapi.yml`（`POST /sandboxes/{id}/fork`、`/snapshots`、`/pause`）、`docs/ARCHITECTURE.md`，以及 E2B 的 fork / snapshot 文档。

### 19.1 目标与取舍
- **[决定，偏离论文]** microVM（Firecracker）作为通用任务的主力后端：隔离强于容器（不共享宿主内核），并且能做内存快照，从而支持「快照即启动」和带内存状态的 fork。论文以容器为主力，microVM 只用于需要更强隔离的场景。
- 容器后端保留，用于：GPU 任务（Firecracker 不支持 GPU / PCI 直通）、对启动和内存开销最敏感的大批量任务、没有 KVM 的节点。完整 VM（QEMU）仍用于 Windows、Android、图形界面类任务。
- 新增三个能力，接口语义尽量对齐 E2B，便于以后做 E2B 兼容层：
  1. **快照**（snapshot）：把运行中的 sandbox（含内存）存成一个可反复使用的镜像。
  2. **fork**：一次调用，把运行中的 sandbox 复制成 N 个运行中的副本。
  3. **暂停 / 恢复**：microVM 暂停时保存内存快照并结束 Firecracker 进程，恢复时从快照恢复（论文 §11 与 E2B 都这样做）。
- 管控面不变的部分：IAM、配额、placement、watcher、edge 状态机。新能力是在这些之上加接口，不改已有语义。

### 19.2 对外接口

**proto（`OpenDsec` 服务新增）**
```proto
// 从运行中的 sandbox 复制出 count 个运行中的副本。源 sandbox 短暂暂停后
// 继续运行，ID 和 TTL 不变。快照只拍一次。每个副本单独成功或失败。
rpc ForkSandbox(ForkSandboxRequest) returns (stream CreateSandboxResult);
// 把运行中的 sandbox 存成镜像库中的一个快照镜像（含或不含内存）。
rpc CreateSnapshot(CreateSnapshotRequest) returns (ImageInfo);

message ForkSandboxRequest {
  string sandbox_id = 1;
  int32 count = 2;                  // [1, max_fork]，默认上限 256
  int64 ttl_running_stop_s = 3;     // 副本的 TTL；0 = 集群默认值（与创建一致）
  int64 ttl_max_s = 4;
  map<string, string> labels = 5;   // 追加到副本上；副本继承源 sandbox 的 spec
  string task_id = 6;               // 默认继承源 sandbox 的 task_id
}
message CreateSnapshotRequest {
  string sandbox_id = 1;
  string image = 2;                 // "<project>/<repo>:<tag>"
  bool memory = 3;                  // false = 只要文件系统（等价于 pack_diff）；microvm 必须为 true（运行中的 guest 只拷磁盘会丢掉未落盘的页缓存）
  bool overwrite = 4;
}
```
- **快照就是镜像**：快照存进现有的共享镜像库（§17），清单里多一个 `vm_snapshot` 字段，权限沿用 `layer.publish` / `layer.use`。`run_sandbox(image="root/rl/env:snap1", backend="microvm")` 遇到带内存快照的镜像就**恢复**，否则冷启动。这样不需要单独的「快照 ID」概念，也自然支持「构建账号 / 运行账号分离」。
- **fork 不产生持久快照**：拍下的快照只给这一次调用的副本用，副本都启动后由 edge 回收（与 E2B 一致）。需要反复使用时用 `CreateSnapshot`。
- **配额**：每个副本都是一次正常的创建，各自走 IAM Admit，计入配额和创建速率限制（§18）。
- **错误**：源 sandbox 不存在 → `not_found`；源 sandbox 的后端不支持 fork → `invalid`；源既不在运行也不在暂停 → `invalid`（暂停的源保持暂停）；单个副本失败（没有容量、超配额）在流里逐个报告，和批量创建一样。
- 两个接口在**所有后端**上都有定义，各后端按能力实现（见 19.6 的 F0）：容器后端的 fork / 快照只包含文件系统，返回结果里明确标出 `memory: false`；`CreateSnapshot(memory=true)` 在容器上返回 `invalid`。

**SDK**
```python
forks = await sb.fork(count=8, ttl_max=600)        # list[Sandbox | DSecError]
img   = await sb.create_snapshot("root/rl/env:step3", memory=True)
sb2   = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/env:step3"))
```
以后的 E2B 兼容层（§19.8）把 `sandbox.fork(count, timeout)`、`create_snapshot()`、`Sandbox.create(snapshot_id)` 映射到这些接口。

### 19.3 edge 的 microVM 后端

**每个 sandbox 的组成**
| 部分 | 设计 |
|---|---|
| 进程 | 每个 sandbox 一个 Firecracker 进程，由 **jailer** 启动：独立 chroot、独立 uid、放进 `/sys/fs/cgroup/opendsec/<edge>/<lease>`、放进该 sandbox 的网络命名空间 |
| 规格 | vCPU = `ceil(cpu_cores)`，并用 cgroup `cpu.max` 限制到实际申请的核数；内存 = `memory_mb`；开启 `track_dirty_pages`（增量快照需要） |
| 内核 | 统一的 guest 内核 `vmlinux`（virtio-blk / net / vsock、overlayfs、erofs、ext4），按版本放在 `agent_dir` 旁边 |
| 根文件系统 | 见下面「磁盘」 |
| guest 内的 agent | 沿用 `opendsec-aether --init` 作 PID 1，监听 **vsock**（容器里监听 unix socket）；chronus 不变。edge 通过 Firecracker 的 vsock unix socket（`CONNECT <port>`）连 aether，运行时 API（exec / 文件 / http / 会话）**完全复用**现有实现 |
| 网络 | 每个 sandbox 一个网络命名空间，里面一个 tap。**所有 sandbox 用相同的 tap 名和 guest IP**（Firecracker 官方推荐的克隆网络方案），靠命名空间隔离、在命名空间出口做 NAT。这样快照里的网卡配置对所有副本都有效，fork 时不用改 guest 网络 |

**磁盘**（参考 E2B 的「只读模板 + 每个 sandbox 写时复制」，但用内核 dm-snapshot 代替 E2B 的用户态 NBD）
> F1 实现时改了方案，见 19.10：只读镜像盘 + guest 内 overlay + 每个 sandbox 一块独立的可写 ext4 盘，不用 dm-snapshot。
- 镜像的层（§17）展平成一个只读块设备镜像，按镜像缓存在节点本地，同一镜像的所有 sandbox 共享。论文用 EROFS，第一版用 ext4 只读镜像，EROFS 作为后续优化。
- 每个 sandbox 的可写部分用 **dm-snapshot**：底层是只读镜像，写入落到该 sandbox 自己的稀疏 COW 文件里。guest 看到的是一块普通的可写盘，不需要 guest 内的 overlay。
- 快照 / fork 时，把源 sandbox 的 COW 冻结成新的只读层，源和每个副本各接一个新的 COW。这一步不复制数据，成本与副本数无关。
- 层链过深（例如超过 8 层）时，后台把链合并成一个新的只读镜像。
- 磁盘记账沿用 §18.2：每个 sandbox 按申请的盘大小计入节点磁盘容量。

**内存与恢复**
- 快照 = Firecracker `PUT /snapshot/create` 得到的 `snapfile`（VM 状态）+ `memfile`（内存）+ 当时的磁盘层链。
- **恢复用 File 后端**：Firecracker 以 `MAP_PRIVATE` 映射 memfile，页面在被访问时才读入（按需加载），并且**同一份快照的所有副本共享宿主机页缓存中的同一份只读页**，直到某个副本写入该页（写时复制）。这对 fork 出很多副本的场景能省很多内存。E2B 用 userfaultfd 处理器是为了从对象存储拉页、预取热点页，可以放到 F3。
- 暂停：VM 暂停 → 拍快照 → 结束 Firecracker 进程，释放全部内存；恢复：在原节点从快照恢复（优先原节点，因为快照在本地）。第一版拍全量快照，F3 改为基于脏页跟踪的增量快照，再与基础 memfile 合并。

**副本的「去重身份」**（Firecracker 官方明确警告：同一快照恢复多次，所有副本会有相同的随机数状态和标识）
- 每次从快照恢复后，edge 先通过 aether 调用一个新的内部 RPC `PostRestore`，做完以下事情之后才把副本标为 RUNNING：
  - 重设系统时间；
  - 往内核熵池注入新的随机数；如果 Firecracker 版本支持 VMGenID 设备也一并启用，较新的 guest 内核收到通知会自己重新播种；
  - 设置新的 sandbox id、hostname 和 machine-id；
  - 更换 aether 与 edge 之间的会话密钥。
- 副本里的对外网络连接都会断开（新的网络命名空间里没有旧连接的 NAT 状态），这一点和 E2B 一样写进接口文档。源 sandbox 上正在进行的 exec 输出流、文件读写等调用也会中断，由 SDK 重连或重试。

### 19.4 fork 的完整流程
```
SDK sb.fork(count=8)
 → apiserver ForkSandbox：鉴权（源 sandbox 的 sandbox.operate + 源项目的 sandbox.create）、限流
 → 源 edge ForkPrepare(sandbox_id)                         (内部 RPC)
     1. 暂停 VM（PATCH /vm Paused），拍内存快照，冻结磁盘 COW → 新只读层
     2. 恢复源 VM，接上新的 COW；源 sandbox 的 ID、TTL 不变
     3. 返回快照引用 {edge, snapshot_id, 大小}；快照先放在源节点本地，后台同步到共享存储
 → apiserver 对每个副本：Pick（优先源 edge，其次已缓存快照的 edge）→ IAM Admit
     → 目标 edge CreateSandbox(spec = 源 spec + from_snapshot 引用)
        · 同节点：直接恢复，共享页缓存
        · 跨节点：从共享存储（或源 edge）拉取快照后恢复
        → PostRestore → RUNNING
 → 流式返回每个副本的结果
 → 所有副本都启动后，源 edge 回收这份快照（已被副本引用的磁盘层由引用计数保留）
```
- **调度**：placement 的 `Request` 加一个「偏好节点」，fork 优先放在源 edge 上（不需要传快照，内存共享效果最好），源节点放不下才分散到其他节点。edge 在状态里上报本地缓存了哪些快照，placement 只把它当作加分项，不作为过滤条件。
- **一致性**：源 VM 暂停期间拍内存和磁盘，guest 的页缓存在内存快照里，所以内存和磁盘是同一时刻的。
- **失败处理**：拍快照失败则整个请求失败，源 sandbox 恢复运行；单个副本失败只影响它自己。

### 19.5 内部接口与组件改动
| 组件 | 改动 |
|---|---|
| proto | `OpenDsec` 加 `ForkSandbox`、`CreateSnapshot`；`Edge` 加 `ForkPrepare`、`ReleaseSnapshot`、`CreateSnapshot`；`EdgeCreateRequest` 加 `from_snapshot`；`EdgeState` 上报本地快照缓存；aether 加 `PostRestore` |
| backend 接口 | 新增可选接口 `Snapshotter`（`Snapshot(sb, memory) → ref`、`Restore(ref, sb)`），能力通过状态上报 |
| placement | `Request.PreferEdge`、快照缓存加分 |
| apiserver | fork 流程（复用批量创建的并发和逐个报告机制） |
| 镜像库 | 清单加 `vm_snapshot`：`{kernel, snapfile, memfile, disk_layers, mem_mb, vcpus}`；快照文件放在 `<root>/snapshots/<id>/` |
| aether | 支持 vsock 监听；`PostRestore` |
| SDK | `Sandbox.fork`、`Sandbox.create_snapshot`；`DSecRunArgs` 补 `disk_mb` |

### 19.6 分阶段计划
| 阶段 | 内容 | 需要 KVM |
|---|---|---|
| **F0 接口与管控** | 19.2 的 proto 和 SDK；apiserver 的 fork 流程、调度偏好、配额；sim 后端模拟 fork（测调度和配额）；**容器后端实现只含文件系统的 fork 和快照**（冻结 → 导出可写层 → 用它创建副本）。这样接口和管控面先完整可测 | 否 |
| **F1 microVM 冷启动** | Firecracker + jailer、guest 内核、镜像展平成块设备、dm-snapshot 可写盘、vsock 上的 aether、每个 sandbox 的网络命名空间、cgroup | 是 |
| **F2 内存快照** | 「预热」镜像（冷启动后拍快照存进镜像库，之后创建即恢复）；暂停 = 快照 + 结束进程，恢复 = 从快照恢复；`PostRestore` 去重身份；`CreateSnapshot(memory=true)` | 是 |
| **F3 fork 与性能** | 带内存的 fork；增量快照（脏页跟踪 + 合并）；userfaultfd 从共享存储按需拉页和预取；层链合并；跨节点分发 | 是 |
| **F4 论文的内存优化** | virtio-pmem + DAX 共享页缓存、DAMON + balloon 回收冷内存 | 是 |

### 19.7 验证指标（F2 / F3）
- 从内存快照创建一个 sandbox 的延迟（目标：同节点 < 200 ms，不含排队），并与冷启动对比。
- fork 64 个副本的总耗时和源 sandbox 的暂停时长。
- 同节点 64 个副本的宿主机内存占用，与 64 个独立 sandbox 对比（验证页缓存共享）。
- 副本之间随机数、machine-id、hostname 互不相同；副本对外网络可用；源 sandbox 在 fork 后继续正常执行。

### 19.8 不在本设计范围
- 与 E2B 线协议兼容（REST + envd），只考虑以后在 SDK 层做兼容层。
- GPU 直通、完整 VM（QEMU）的快照。
- 跨节点的热迁移。

### 19.9 F0 实现记录（2026-10-15）
- **proto**：`OpenDsec.ForkSandbox`、`OpenDsec.CreateSnapshot`；`SandboxSpec.snapshot`（副本从哪份快照启动，只由 fork 设置，调用方在创建时设置返回 `invalid`）；`ImageInfo.snapshot / memory`。
- **edge 内部接口简化**：设计里的 `ForkPrepare` / `CreateSnapshot` / `ReleaseSnapshot` 合并成一个 `Edge.Snapshot(sandbox_id, snapshot_id, memory)`，快照 id 由 apiserver 分配。
  - `ReleaseSnapshot` 暂不实现：容器副本的 overlay 直接引用快照的层，快照要和副本活得一样久。快照和层一起等以后的镜像库 GC 回收；microVM 的临时内存快照到 F2 / F3 再加回收。
- **快照记录**：`<store>/snapshots/<id>/snapshot.json` = `{base, layers, env, workdir, user, memory, size, image, source}`。
  - `layers` 是源 sandbox 创建时实际解析出的层（edge 写在 sandbox 目录的 `image.json` 里），再加上新导出的可写层。
  - `base` 用于从 edge 本地镜像（开发用的 `host`）启动的 sandbox：这类 sandbox 可以 fork，但不能 `CreateSnapshot` 成镜像库里的镜像。
- **容器后端**：
  - 冻结 cgroup → 用 `cp -a` 把可写层复制成新的层（不清理 `/tmp` 等），成本和可写层大小成正比。O(1) 的冻结 COW 要等 microVM 的 dm-snapshot 方案。
  - 副本用 overlay 叠在快照的层上。
  - 层链上限 48 层，因为 overlayfs 的所有 lowerdir 要写进一页挂载参数。F3 起快照层超过 8 层就合并（19.12），fork 链不会再加深到这个上限。
- **apiserver 的 fork 流程**：
  1. 鉴权：源 sandbox 的 `sandbox.operate`；源镜像是镜像库镜像时检查 `layer.use`（不要求镜像仍然存在）；用不带 lease 的 Admit 预检源项目的 `sandbox.create`，没有权限时在暂停源之前就失败。
  2. 拍快照。
  3. 复用批量创建的并发、按速率排队和逐个返回结果的机制创建副本。每个副本单独走 Admit，计入配额。
- **placement**：`Request.PreferEdge` 指定的节点只要放得下（健康、未排空、无压力、资源够）就选它，不参与负载比较；放不下时按 power-of-k 正常放置。F3 起节点上报快照缓存，调度优先选缓存了快照的节点（19.12）。
- **SDK / 命令行**：
  - SDK：`Sandbox.fork(count, ttl_running_stop, ttl_max, labels, task_id)`、`Sandbox.create_snapshot(image, memory, overwrite)`；`DSecRunArgs.disk_mb`；TTL 注释改正为「0 = 集群默认值」。
  - 命令行：`opendsecctl sandbox fork`、`opendsecctl image snapshot`。
- **测试**：
  - 单元测试：placement 的偏好节点（放得下时优先、满了外溢、被排除或不健康时跳过）；镜像库快照记录（缺层拒绝、id 校验、lowerdir）。
  - e2e `TestForkControlPlane`（sim）：
    - 63 个副本放在源节点、其余外溢到其他节点；
    - 副本继承 spec，追加 labels，TTL 正确；
    - 配额按副本逐个生效；
    - 缺 `sandbox.create` 或跨项目时返回 forbidden；
    - count 越界、源已停止时返回 invalid；
    - 调用方伪造 `spec.snapshot` 被拒绝。
  - e2e `TestForkContainer`（真实容器）：
    - 副本看到 fork 时刻的文件（含 `/tmp` 和删除操作），之后与源、与其他副本互相独立；
    - 副本可以再 fork；
    - 副本的 pack_diff 叠在快照的层上；
    - `CreateSnapshot` 生成的镜像能启动新 sandbox；
    - 容器做内存快照返回 invalid；
    - 本地镜像可以 fork，但不能发布。
  - pytest `test_fork`。

### 19.10 F1 实现记录（2026-10-15，在裸金属测试机上验证）
- **后端**：`runtime: "firecracker"`，代码在 `internal/edge/backend/microvm`。cgroup、进程身份、状态文件这些辅助代码从容器后端抽到了 `internal/edge/backend/linuxrt`，两个后端共用。
- **进程**：
  - edge 用 `CLONE_NEWNET | NEWIPC | NEWUTS` 和 `CgroupFD`（直接放进 `opendsec/<edge>-microvm/<lease>`）启动 jailer；jailer 负责 chroot、新的 mount namespace、切换到独立 uid，然后 exec Firecracker。jailer 自己不设置 cgroup。
  - 每个 VM 的 uid 从 `uid_base` 开始的 65536 个里按 lease 分配，记在 `state.json` 里。
  - Firecracker 用 `--config-file` 启动，同时开着 API socket，用于暂停 / 恢复和以后的快照。
- **磁盘**（和 19.3 的设计不同）：

  | 盘 | 内容 |
  |---|---|
  | vda（根设备，只读） | agent 盘：aether、chronus，以及指向 aether 的 `opendsec-vminit` |
  | vdb（只读） | 镜像各层展平成的 ext4，按层列表缓存在节点上，同一镜像的 VM 共用 |
  | vdc（读写） | sandbox 自己的稀疏 ext4，大小 = `disk_mb`；host 上用 `mkfs.ext4 -d` 写入 `upper/`、`work/`、`opendsec-vm.json` |

  - **为什么放弃 dm-snapshot**：dm-snapshot 卷的大小只能等于底层镜像的大小，无法按 `disk_mb` 给配额，COW 写满后整个卷还会失效。现在 guest 内用 overlay，磁盘配额和写满时的行为（ENOSPC）都和容器一致。
  - F3：`state_dir` 在 XFS 上时，复制可写盘和内存文件用 reflink，接近 O(1)（19.12）。
  - edge 本地的 `host` 镜像（host 的 `/`）不能用于 microvm，返回 invalid，避免把整个宿主机展平。
- **guest 启动**：
  - 内核参数 `init=/opendsec-vminit`。没有用 `init=... -- args` 传参，因为 Firecracker 会把 `root=` 等参数追加在命令行末尾，会落到 `--` 后面。
  - vminit 的步骤：
    1. 挂载镜像盘和可写盘；可写盘带 `noinit_itable`，避免后台清零 inode 表把稀疏文件撑大；
    2. 组好 overlay；
    3. 把 agent 盘以只读方式 bind 到 `/.opendsec/bin`；
    4. 挂载 proc、sys、cgroup2、devtmpfs、devpts、shm；
    5. pivot_root，拉起 lo；
    6. exec `aether --init --vsock-port 1024`。
- **vsock**：
  - aether 自己实现了 AF_VSOCK 监听，因为 Go 的 net 包不支持 vsock。
  - edge 通过 Firecracker 的 vsock unix socket 做 `CONNECT 1024` 握手。
  - 握手成功才创建 gRPC 连接，并把 gRPC 重连退避改成 20ms 起。否则启动中的 guest 第一次连接失败后，要多等 1 秒。
- **启动耗时**：
  - 官方 CI 内核默认会探测 i8042 键盘控制器，耗时约 0.5 s。加上 `i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd` 之后，从启动 jailer 到 aether 应答约 **95 ms**，host 上的准备工作（硬链接、mkfs 可写盘、cgroup）约 13 ms。
  - 8 个 VM 并发启动共 134 ms。
  - 通过 apiserver 端到端创建约 120 ms。
  - `python:3.12-slim` 第一次使用需要先展平镜像，约 400 ms。
- **暂停 / 恢复**：F1 用 `PATCH /vm {Paused|Resumed}`，只暂停 vCPU，不释放内存。F2 改成快照 + 结束进程。
- **重启接管**：edge 重启后，按 `state.json` 里记录的 pid 和 starttime 确认进程还是原来那个、仍在 cgroup 里，再通过 API 查询 VM 状态；如果 VM 是暂停的，先短暂恢复，验证 aether 通道后再暂停回去。
- **尚未实现，留到后续阶段**：网络（和网络策略一起做）、快照 / fork / pack_diff（F2 / F3）、镜像盘缓存清理、guest 内 OOM 时保护 aether。（之后都已完成：网络见 §20，快照和 fork 见 19.11 / 19.12，镜像盘缓存清理见 §24，OOM 保护见 §21。）
- **其他修复**：edge 创建失败时保留后端错误的原因（invalid / not_found / no_capacity / unavailable）。之前一律报 internal，调用方看不出原因，apiserver 也不会因为节点没容量而改去其他节点重试。
- **测试**（需要 KVM，没有时自动跳过）：
  - 后端测试：
    - 启动与隔离：guest 内核、vCPU 数、hostname、只有 lo、agent 只读、写入不影响镜像、cgroup 限额、Firecracker 以独立 uid 运行在 chroot 里；
    - 磁盘配额；
    - 暂停 / 恢复；
    - 杀掉进程能检测到；Stop 之后不留残余；
    - 重启接管（暂停的保持暂停，没接管的被清理）；
    - 8 个 VM 并发启动且只展平一次镜像；
    - 拒绝 host 镜像。
  - e2e `TestMicroVMEndToEnd`：
    - 镜像库镜像、文件读写、后台命令；
    - 暂停后透明恢复；
    - edge 重启后会话状态和后台命令都还在；
    - 容器和 microvm 在同一个 edge 上共存；
    - microvm 的 fork 暂时返回 invalid；内存不足最小值时返回 invalid；
    - 按 task 停止后配额归还，jail 被清理。

### 19.11 F2 实现记录（2026-10-15，在裸金属测试机上验证）
- **暂停 = 快照 + 结束进程**：
  - 暂停：`PATCH /vm Paused` → `PUT /snapshot/create`（Full）写到 jail 里的 `pause.vmstate` / `pause.mem` → 结束 Firecracker 进程 → 对内存文件做 `fdatasync` + `FADV_DONTNEED`，让它的页缓存也释放掉。
  - 恢复：在同一个 jail 里重新启动 jailer（先清掉上一个进程留下的 `firecracker`、`dev`、`run`、`v.sock`），`PUT /snapshot/load`（File 后端，`resume_vm`）→ 重新连接 aether → `PostRestore`。
  - 恢复后删除快照文件的名字。内存仍然以私有映射的方式被引用，磁盘空间在下一次暂停或 VM 结束时释放。
  - 暂停期间 sandbox 没有进程：Probe 改为检查快照文件是否存在；`state.json` 里标为 `suspended`；edge 重启后直接按「暂停」接管。
  - 和容器的冻结不同，暂停时正在进行的调用会失败，guest 里的进程停在快照那一刻。
- **快照 = 镜像库里的一个目录**：`<store>/snapshots/<id>/`，内容为
  - `vmstate`、`mem`；
  - `disk.ext4`：可写盘在 VM 暂停期间做的稀疏复制，和内存是同一时刻的状态；
  - `image.ext4`、`agents.ext4`：guest 当时挂着的只读盘，必须是同一份文件才能恢复，所以随快照一起保存（硬链接）。
  - 记录里新增 `vm: {mem_mb, vcpus, disk_mb}`。
- **从快照创建**：
  - 两种来源：fork 副本（`spec.snapshot`），以及 `CreateSnapshot(memory=true)` 生成的镜像（清单里的 `snapshot` 字段）。
  - 做法：只读盘硬链接进新的 jail，可写盘复制一份（以后在 XFS 上用 reflink），内存文件硬链接后以 File 后端加载。
  - 同一节点上的所有副本共享同一份页缓存，直到某个副本写入（写时复制）。
  - 新 sandbox 的 `memory_mb` 必须等于快照的值，否则返回 invalid 并给出应填的值。
  - 容器不能用 microvm 的快照镜像，返回 invalid。
- **配置盘**：guest 配置（hostname、aether 参数）移到第 4 块盘 vdd，guest 启动时读完就卸载。可写盘因此只放数据，复制给副本时不会带上源 sandbox 的配置；恢复时也可以换一块新的配置盘。
- **`PostRestore`**（aether 新增的 RPC）：
  - `settimeofday` 设为宿主机时间（恢复后 guest 的时钟停在拍快照那一刻）；
  - `RNDADDENTROPY` 注入 64 字节随机数并计入熵值，再 `RNDRESEEDCRNG`；
  - 副本另外设置新的 hostname 和 machine-id（若 `/etc/machine-id` 存在）。
  - 暂停后的恢复只做时钟和随机数。
  - 设计里的「更换会话密钥」：目前 edge 到 aether 的 vsock 通道没有密钥，所以不需要。
- **拍快照会断开 vsock 连接**：Firecracker 拍快照时会重置 guest 的 vsock 连接。
  - 每个 VM 到 aether 的连接改成独立的 `link` 对象：拍快照前先把当前 link 标为「预期内关闭」，拍完重新连接，避免心跳流断开被当成 sandbox 丢失。
  - 拍快照期间进行中的调用会失败。
- **fork**：
  - apiserver 调 `Edge.Snapshot` 时带 `prefer_memory`：后端支持内存快照就拍内存快照（microvm），否则只拍文件系统（container）。
  - 内存快照只在启动副本时用到，副本全部创建完成后由 apiserver 删除；文件系统快照保留，因为副本叠在它的层上。
- **microvm 不支持只含文件系统的快照**：对运行中的 guest 只复制磁盘，会丢掉还在页缓存里没写盘的数据，所以 `memory=false` 返回 invalid。
- **实测**（BM，256–512 MB 的 VM）：

  | 操作 | 耗时 |
  |---|---|
  | 暂停（写 256 MB 全量快照） | 约 210 ms，cgroup 内存 148 MB → 5 MB |
  | 恢复 | 约 50 ms |
  | 运行中的 VM 拍快照 | 暂停 110 ms |
  | 从快照恢复副本 | 每个约 58 ms，4 个并发共 60 ms |
  | fork 3 个 512 MB 的副本（经 apiserver） | 398 ms |
  | 从快照镜像创建 | 54 ms，冷启动约 110 ms |

  - **内存共享**：8 个副本，每个都读一遍 128 MB 数据，宿主机一共多用 135 MB；不共享的话约 1.4 GB。
- **留到 F3**（结果见 19.12）：
  - 增量快照：暂停时只写脏页；F2 每次暂停都写全量，即整个 guest 内存的大小；
  - userfaultfd 按需拉页，以及跨节点从共享存储拉取快照；
  - 用 XFS reflink 复制可写盘；
  - 暂停的 sandbox 在 edge 的容量记账里仍然算内存，还没有利用这部分空间做超配（F3 也没有做，见 19.12）。
- **测试**：
  - 后端测试：
    - 暂停到快照：进程结束、内存释放、Runtime 返回 unavailable、Probe 仍为存活；恢复后内存数据、shell 状态、后台进程都还在，时钟正确；可以连续暂停 / 恢复多次。
    - 从同一份快照恢复多个副本：起始状态和源一致，之后互不影响；hostname、machine-id、随机数各不相同；源继续运行；内存大小不匹配时拒绝；可以对暂停中的副本再拍快照；拒绝只含文件系统的快照。
    - `OPENDSEC_BENCH=1` 时运行内存共享基准。
  - e2e：
    - microvm fork 三个副本：都在源节点上、内存状态一致、hostname 各不相同，fork 用的快照随后被删除；
    - `CreateSnapshot(memory=true)` 生成的镜像可以创建新 sandbox；内存大小不对或用容器后端时拒绝；
    - 暂停中的 VM 在 edge 重启后被正确接管，之后访问时自动恢复。


### 19.12 F3 实现记录（2026-10-15）
- **增量快照（脏页跟踪）**：
  - 所有 VM 都开启 Firecracker 的 `track_dirty_pages`：冷启动写在 `machine-config` 里，从快照恢复时在 `/snapshot/load` 里再设一次，因为快照不保存这个设置。
  - 每个 sandbox 记录一个「基础内存文件」`base`：它的内容等于上一次拍快照或恢复那一刻的 guest 内存，记在 `state.json` 里。
    - 冷启动的 VM 没有 base，第一次暂停写全量；
    - 暂停后恢复的 VM，base 就是它的 `pause.mem`，归它自己独有；
    - 从快照恢复的副本，base 是快照的内存文件，和其他副本共享。
  - 有 base 时，暂停改成拍 `Diff` 快照（只写脏页，稀疏文件），再用 `SEEK_DATA` / `SEEK_HOLE` 和 `copy_file_range` 把脏页合并进 base，得到新的 `pause.mem`：
    - base 独有时原地合并；
    - base 是共享的（快照或副本）时，先复制一份再合并，绝不写共享文件。
  - 合并在 VM 进程结束之前、VM 还暂停着的时候做。VM 以 `MAP_PRIVATE` 映射 base，被合并的正好是它写过的页，这些页在它的映射里已经是私有副本，所以合并不影响它。合并失败时 VM 直接恢复运行，base 作废，下次暂停写全量。
  - 运行中的 VM 拍快照（fork、`CreateSnapshot`）也用同样的办法：VM 只在写脏页和复制可写盘时暂停，恢复运行后再「复制 base + 合并脏页」得到完整内存文件。快照的内存文件随后成为源 sandbox 的新 base（共享）。
  - Firecracker 的全量快照也会清空脏页记录，所以只要拍过任何快照，旧 base 就作废，换成这次快照的内存。
  - 暂停中的 VM 被拍快照时，它的 `pause.mem` 被快照硬链接共享，于是标记为「非独有」，下次暂停会先复制再合并。测试检查了快照的内存文件在之后的暂停中保持不变。
- **XFS reflink**：
  - 复制可写盘和内存文件一直用 `cp --reflink=auto`，`state_dir` 在 XFS（`reflink=1`）上时自动共享数据块。
  - 测试机没有重新格式化 `/data`，而是在上面建了一个 200 GB 的 XFS 环回盘（`/data/xfs`），测试用 `OPENDSEC_TEST_STATE` 指过去。环回盘写全量快照比 ext4 慢一些，真实 XFS 分区应该更好。
- **跨节点**：
  - 镜像库和节点的 `state_dir` 在同一个文件系统上时，恢复直接硬链接快照文件，和 F2 一样。
  - 不在同一个文件系统上时（镜像库在共享存储上，或快照来自其他节点），节点第一次用某份快照时把它整份拉到节点本地的快照缓存（`cache/snapshots/<id>`），并发的请求共用一次拉取。之后同一节点上的副本都链接这份缓存，共享它的页缓存。
  - 快照从镜像库删除后，后台每分钟清理一次对应的缓存；已经运行的副本持有硬链接，不受影响。
  - `EdgeState.snapshots` 上报节点缓存了哪些快照。placement 的 `Request.Snapshot` 由 apiserver 填写（副本的快照，或快照镜像对应的快照）：在放得下的节点里，有缓存的节点优先进入 power-of-k，都没有缓存时正常调度。`PreferEdge`（fork 的源节点）仍然优先于缓存。
- **userfaultfd 没有做**：
  - 设计里 UFFD 用来从对象存储按需拉页和预取。现在快照都在文件系统上：同一文件系统用 File 后端按需缺页，并共享页缓存；跨文件系统先整份拉到节点缓存。
  - UFFD 的处理进程如果放在 edge 里，edge 重启（`keep_sandboxes_on_exit`）时 VM 会卡在缺页上，需要单独的常驻进程。
  - 收益只在快照放到对象存储、或者 VM 内存远大于拉取带宽时才明显，等有这个需求时再做。
- **容器的层链合并**：
  - 每次快照仍然先导出可写层（冻结时间不变），解冻之后，如果栈顶连续的快照层超过 8 层（层元数据的来源以 `snapshot ` 开头），就把它们合并成一层；镜像自己的层不动，继续共享。
  - 合并（`Store.MergeLayers`）按 overlay 的语义从下往上叠：先删掉新一层里 whiteout、opaque 目录、类型变化（文件 ↔ 目录）所覆盖的路径，再 `cp -a` 复制。结果仍是 overlay 格式，whiteout 和 opaque 标记保留，用来遮住下面的镜像层。
  - 测试：同一组层合并前后，叠在同一个基础层上的 overlay 视图完全一致；e2e 里连续 fork 12 代（每代都覆盖、删除、新建文件），最后的镜像不超过 9 层，内容正确。
- **实测**（BM；ext4 是 `/data` 的 RAID0，XFS 是环回盘）：

  | 操作 | ext4 | XFS |
  |---|---|---|
  | 512 MB VM 第一次暂停（全量） | 278 ms | 337 ms |
  | 之后的暂停（写 8 MB 后，合并 18 MB 脏页） | 85 ms | 78 ms |
  | 副本 / 拍过快照的 VM 暂停（需要先复制 base） | 210–300 ms | 70–95 ms |
  | 运行中的 512 MB VM 拍快照：源暂停时长 / 总耗时 | 13 ms / 225 ms | 17 ms / 40 ms |
  | F2 的全量方式（对比） | 311 ms / 312 ms | — |

  - **fork 64 个副本**（19.7 的指标，512 MB 的 VM，内含 128 MB 数据）：源暂停 7–10 ms；64 个副本并发恢复共 207 ms（单个 p50 约 177 ms，最慢 208 ms）。每个副本读一遍 128 MB 数据后，宿主机一共多用 1.0–1.3 GB；不共享的话约 11.4 GB。
  - **经 apiserver**：fork 3 个 512 MB 副本 184 ms（F2 是 398 ms）；源节点排空时 fork 2 个副本到另一节点（跨文件系统，含拉取快照）140 ms。
  - **跨文件系统恢复**：另一节点上第一个副本先拉取 256 MB VM 的快照，108 ms；之后的副本约 27 ms。
- **没有做的**（之后都在 §24 完成）：
  - 暂停中的 microVM 在 edge 容量记账里仍按申请的内存计算。如果拿这部分内存去超配，恢复时可能没有内存，需要定一个策略：拒绝恢复、把快照迁到别的节点恢复，或者给暂停中的 sandbox 单独一个超配比例。最终选的是单独一个比例 `paused_mem_charge`。
  - 镜像盘缓存（`cache/img-*.ext4`）仍然不会自动清理。
- **测试**：
  - 后端测试：
    - `TestDiffPause`：全量、增量、副本共享 base、拍快照后共享 base、暂停中被拍快照这几种情况下，暂停 / 恢复后内存内容（`/dev/shm` 的校验和）不变，快照的内存文件不被改动；增量暂停只合并了脏页。
    - `TestSnapshotOtherFS`（需要 `OPENDSEC_TEST_XSTATE` 指向另一个文件系统）：只拉取一次，缓存上报，快照删除后缓存被清理，副本照常暂停 / 恢复。
    - `TestFork64`（需要 `OPENDSEC_BENCH=1`）。
  - placement：缓存了快照的节点优先，满了以后正常调度，没有缓存时负载均衡不变。
  - e2e：
    - `OPENDSEC_TEST_XSTATE` 设置后，第二个 edge 的 `state_dir` 放在另一个文件系统上；
    - 源节点排空时，fork 的副本和快照镜像创建的 sandbox 都落到另一节点，内存状态正确；
    - 另一节点上报了快照缓存，再从同一快照镜像创建的 sandbox 都放到它上面；
    - 容器 fork 链合并见上。


### 19.13 F4 实现记录（2026-10-15）
- **[偏离设计] DAMON 放在 guest 内核里，宿主机内核不改**：
  - Ubuntu 24.04 的内核没有编译 DAMON，7.0 的 HWE 内核也没有。在宿主机上用 DAMON 就得自己编宿主机内核，整个机群都要换内核、重启。
  - guest 内核本来就是我们提供的，所以改为在 guest 里运行 DAMON_RECLAIM：它找出冷内存并换出到压缩的 zram，空出来的页由 balloon 的 free page reporting 交还宿主机。效果相同（宿主机内存跟着工作集走），机群用原厂内核即可。
- **guest 内核**（`deploy/guest-kernel/`）：
  - `build.sh` 用 kernel.org 的 6.1.167 源码和 Firecracker v1.17 的 CI guest 配置（已经包含 virtio-pmem、FS_DAX、DAMON_RECLAIM、balloon、free page reporting），再叠加 `opendsec.config`：zram、IKCONFIG，以及 `CRYPTO_MANAGER_DISABLE_TESTS`。
  - 加密算法的启动自检占了 82 ms（用 `initcall_debug` 查出来的 `crypto_algapi_init`），关掉后启动时间和 F1 用的 6.1.155 CI 内核持平：8 个 VM 并发启动 131–172 ms，CI 内核 137–147 ms。
  - 脚本在 olddefconfig 之后检查片段里的每个选项都生效了，依赖缺失时直接失败。
  - 384 线程上编译约 20 秒。
- **配置项**（`config.Backend`，默认都关闭，需要 opendsec 内核）：`image_pmem`、`free_page_reporting`、`cold_age_s`、`zram_pct`（默认 100）。
- **virtio-pmem + DAX 的镜像盘**：
  - 镜像盘从第 2 块 virtio-blk 改成只读的 pmem 设备（Firecracker 以 `MAP_SHARED` 映射文件），guest 以 `-o dax` 挂载。读镜像里的文件直接走宿主机页缓存，同一镜像的所有 VM 共享，guest 里不再各缓存一份。
  - 后面的盘号相应前移（可写盘 vdb、配置盘 vdc）。guest 的 init 看到 `/dev/pmem0` 就按这个布局挂载，否则按原来的布局。
  - 镜像盘改用 4 KB 块（DAX 要求块大小等于页大小），大小按 2 MB 对齐（pmem 按 2 MB 映射）。镜像盘缓存的键里加了格式版本，旧格式的缓存不会再用到，仍然需要手动清理。
  - Firecracker 的快照不包含 pmem 的内容，只记录路径。恢复时打开同一个路径（jail 里的 `/image.ext4`），副本链接的是同一个文件，所以也共享。
  - 安全：用同一镜像的 sandbox 共享同一批物理页，和容器共享宿主机页缓存的情况一样；Firecracker 文档提醒这可能成为侧信道，所以默认关闭。
- **free page reporting**：
  - vm.json 里加 balloon 设备：`amount_mib` 0、`deflate_on_oom`、`free_page_reporting`。guest 释放的页由 Firecracker `madvise(MADV_DONTNEED)` 交还宿主机。
  - 内核默认只上报 2 MB 以上的连续空闲块，DAMON 换出后空出来的页很零散，guest init 把 `page_reporting_order` 改为 6（256 KB）。
  - 和快照的关系：交还的页对 guest 来说是空闲页，内容无所谓。从文件恢复的 VM（`MAP_PRIVATE`）交还后再读到的是文件里的旧内容，也不影响；增量快照不会把这些页当成脏页，合并结果依然正确。
- **DAMON_RECLAIM + zram**（`cold_age_s` > 0）：
  - guest init 创建大小为 `zram_pct` × VM 内存的 zram0，写入 swap 签名后 `swapon`，再通过 sysfs 设置 DAMON_RECLAIM：`min_age` = `cold_age_s`，水位设为始终启用（默认水位只在 guest 空闲内存不足时才回收，但冷内存不论 guest 缺不缺内存都占着宿主机）。
  - zram 盘大小限制的是压缩前的数据量：测试里最初按 50% 设置，结果换出 252 MB 就满了，默认值因此改为 100%。
  - 数据完全不可压缩时，换出到 zram 省不了内存，只多花 CPU。
- **暂停时只写用过的内存**（顺带改进 F3）：
  - Firecracker 文档说明，冷启动 VM 的增量快照本身就是完整的：启动时内存全为零，写过的页都在脏页记录里。
  - 所以冷启动的 VM 记一个「全零 base」（`zero`）：第一次暂停、第一次 fork 快照都只写脏页，得到稀疏的内存文件，不再写全量。
  - 实测：512 MB 的 VM 里放了 200 MB 数据，第一次暂停写 280 MB，用时 186 ms（全量 278 ms）；256 MB VM 的 fork 快照从 111 ms 降到 43 ms，文件 119 MB。
  - 限制：被换出到 zram 或交还给宿主机的页仍然在脏页记录里，暂停时会被写成零页，所以回收过的 VM 暂停时内存文件仍接近满（实测 488 MB / 512 MB）。占的是磁盘，不占内存。
- **实测**（BM）：

  | 场景 | 不开 | 开 |
  |---|---|---|
  | 6 个 VM 读同一个 64 MB 的镜像文件 | 515–529 MB | 112–140 MB |
  | guest 写 300 MB 后删除，VM 的 cgroup 内存 | 329 MB 不变 | 降到 120 MB |
  | 300 MB 闲置文本数据（`cold_age_s` = 2） | 333 MB 不变 | 11–20 s 后降一半，最后 127–152 MB；压缩后 zram 只占 7 MB |
  | **16 个闲置的 512 MB VM**（每个读 64 MB 镜像文件、留 100 MB 数据、释放 50 MB） | 4568 MB（每个 285 MB） | 1426 MB（每个 89 MB），**31%** |

  - DAMON_RECLAIM 用默认配额（每秒最多 10 ms、128 MB），300 MB 冷数据要十几秒才回收一半；生产环境的 `cold_age_s` 本来就是分钟级，够用。
  - 开了所有优化后，经 apiserver fork 3 个 512 MB 副本 111 ms。
- **没有做的**（之后都在 §24 完成）：
  - balloon 只用了 free page reporting，没有主动充气（`amount_mib`）。节点内存紧张时由 edge 给 VM 充气回收，留到以后，需要先定策略。
  - 暂停中 VM 的容量记账（19.12）。打开优化后可以调高 `mem_overcommit`，节点 MemAvailable 低于 `mem_reserve_mb` 时 edge 照常拒绝新建。
  - 回收过的 VM 暂停时的内存文件可以打洞（扫描零页），以后再做。
- **测试**（需要 opendsec 内核，默认路径 `/data/opendsec-vm/vmlinux-6.1.167-opendsec`，也可以用 `OPENDSEC_FC_OPENDSEC_KERNEL` 指定；找不到就跳过）：
  - `TestPmemImage`：开和不开各起 6 个 VM 读同一个镜像文件，对比宿主机内存；pmem 下暂停 / 恢复、快照副本都能读镜像，写入可写层正常。
  - `TestFreePageReporting`：开和不开对比释放后的 cgroup 内存。
  - `TestColdReclaim`：zram swap 和 DAMON 已启用；闲置数据被回收，校验和不变；回收后暂停 / 恢复、从快照恢复副本，数据都正确。
  - `TestMemoryDensity`（需要 `OPENDSEC_BENCH=1`）：上表最后一行。
  - e2e：有 opendsec 内核时，microVM 的 e2e 打开全部优化跑完整流程（API、暂停、edge 重启接管、fork、快照镜像、跨节点），并检查 guest 里 pmem、DAMON、zram 都已启用。
  - 跨节点 e2e 原来不稳定：源 sandbox 随机放置，落在 state 位于另一文件系统的节点上时，另一节点和镜像库在同一文件系统，不需要拉取。现在固定在和镜像库同一文件系统的节点上建源。

### 19.14 内存脏页跟踪：业界做法与取舍（2026-10-16）
- **问题**：增量快照（19.12）依赖 Firecracker 的 `track_dirty_pages`，也就是 KVM 的脏页日志。它的运行时开销没有量化过；业界有用 userfaultfd（UFFD）写保护代替它的做法。
- **几种机制**：

  | 机制 | 运行时开销 | 增量的准确度 | 前提 |
  |---|---|---|---|
  | KVM 脏页日志（`track_dirty_pages`） | 每次清零后，每页第一次写在 KVM 里缺页一次，不回到用户态；内存槽开着日志时 KVM 不用大页映射 guest 内存 | 精确，只有写过的页 | 官方 Firecracker |
  | `mincore`（Firecracker 关掉跟踪时拍 Diff 用它） | 无 | 偏大：读过的页也算；页缓存里的页不分是谁读进来的；被换出到宿主机 swap 的页漏掉 | 官方 Firecracker；宿主机不能开 swap |
  | UFFD 缺页模式（AgentENV 的 `uffd-core`） | 按需加载本来就要缺页，顺手记录 | 偏大：访问过就算脏；页填进去以后不再缺页，集合只增不减 | 常驻的处理进程 |
  | UFFD 异步写保护（`UFFD_FEATURE_WP_ASYNC`，内核 6.7+） | 和 KVM 同一量级：每页第一次写缺页一次，内核就地处理 | 精确 | 改 Firecracker |
  | UFFD 同步写保护 | 每次缺页回到用户态，最贵 | 精确；处理进程可以在写之前复制旧页，把复制移出暂停窗口 | 改 Firecracker |

  凡是精确的写跟踪，本质都是"每页第一次写缺页一次"，UFFD 写保护并不比 KVM 便宜。它的价值在于和 UFFD 按需加载、远端存储放在同一个处理进程里，并且能把复制脏页移出暂停窗口。
- **各家的做法**（2026-10 读源码和文档）：
  - 官方 Firecracker：恢复用 File（`MAP_PRIVATE`）或 UFFD；Diff 快照开跟踪时用 KVM 日志，不开时用 `mincore`。官方 UFFD 不支持写保护。
  - AgentENV：生产路径是 OverlayBD 拼成只读 ublk 设备，以 File 后端交给 Firecracker；默认用 KVM 日志（`AGENTENV_MEMORY_SNAPSHOT_TRACK_DIRTY_PAGES=false` 改用 `mincore`）；暂停时只存 VM 状态，再按 fork 的 `/vm/dirty-memory-ranges` 用 `process_vm_readv` 读出脏页，写成新的 OverlayBD 层。`storage/uffd-core` 不在 workspace 里，只作参考。
  - E2B：全部走 UFFD，guest 内存是 memfd；`track_dirty_pages` 一律关闭（`fc/client.go`）；脏页由私有 fork `e2b-dev/e2b-firecracker` 的 UFFD 写保护提供（`GET /memory/dirty`："pages written to since write-protection was enabled"），默认异步写保护，同步写保护（`use_sync_wp`）在 feature flag 后面，用来做"先恢复运行、后台复制"的就地快照；冷启动的 VM 用 `mincore`（`GET /memory`）。
  - CodeSandbox：从 `MAP_PRIVATE` 改为共享内存加 UFFD（据其员工所说，原因是 NVMe 成了瓶颈），配合 balloon 记录归还的页。
  - forkd：memfd 用 `MAP_SHARED`，`UFFDIO_WRITEPROTECT` 写保护后异步复制脏页，报告 1 GiB VM 暂停从约 150 ms 降到约 3 ms（内核 6.14）；为此向 Firecracker 提了 #5912，仍在等待评审。
  - QEMU / KVM 热迁移用 KVM 日志（bitmap，或 5.11 起的 dirty ring，Intel 上有 PML）；CRIU 从 soft-dirty 转向 `PAGEMAP_SCAN` 加 UFFD 异步写保护。
- **为什么不全面对齐 E2B**：
  - E2B 的模板在对象存储里，恢复几乎都跨节点，UFFD 是必需的。我们的主要场景是一份快照在同一节点 fork 出几十上百个副本，最看重副本之间共享内存。
  - UFFD 用 `UFFDIO_COPY` 把页复制进每个 VM 自己的内存，副本之间不再共享。64 个副本各读 128 MB：现在宿主机多用 1.0–1.3 GB，不共享约 11.4 GB（19.12）。
  - E2B 的 Firecracker 是私有仓库，补丁（写保护、dirty 接口、memfd、balloon 上报暂停）只能自己在官方版本上实现和维护。
- **决定：分阶段**：
  1. 现在：保持 KVM 日志，在 BM 上量化它的开销和 `mincore` 的增量大小（见下）。microvm 后端增加内部选项 `NoDirtyTracking`，用于对比测量。
  2. 接入多节点和共享存储时：快照存储改为按块切分，用 header 记录每块来自哪一层，增量叠在父快照上（对齐 E2B 和 AgentENV 的分层格式），跨节点只拉缺的块。不需要改 Firecracker。
  3. 需要按需拉页时（跨节点恢复成为常态、节点宕机后暂停的 sandbox 不能丢、VM 内存普遍数 GB）：新增 UFFD 恢复路径，使用异步写保护跟踪脏页，补丁打在官方版本上，产物记进 `deps.lock`（§28.12）。同一节点上的 fork 仍走 File 后端，其他情况走 UFFD。
- **测量方法**（`TestDirtyTracking`，需要 `OPENDSEC_BENCH=1`）：
  - guest 里的负载程序 `testdata/memwork`：首次写入（每页写一次）、重写、随机读写 8 字节（对 TLB 敏感）、分配密集（GC 压力）。
  - 冷启动的 VM 和从快照恢复的 VM 各测一遍，跟踪开、关交替跑多轮取中位数；拍快照会清零脏页日志，之后再测一次重写，量出"清零后第一次写"的代价。
  - 增量大小：同一份快照恢复两个副本，一个读完全部数据，另一个只写 16 MB 后暂停，比较开、关跟踪时合并的字节数。
  - 记录 Firecracker 进程的 `AnonHugePages`：测量机的宿主机 THP 是 `always`，冷启动 VM 的内存可能是大页，开着日志时 KVM 只能用 4K 映射。
- **测量结果**（2026-10-16，bm1：AMD EPYC 9Y24，宿主机内核 6.8，THP `always`，Firecracker v1.17.0；VM 2 vCPU、3 GB，负载 1 GB；跑了 5 轮和 3 轮两次，取各自的中位数；测量时线上压测在跑）：

  | 指标 | 开跟踪 | 关跟踪 | 差别 |
  |---|---|---|---|
  | 冷启动 VM：首次写 1 GB | 1114 ms | 668 ms | 慢 67% |
  | 冷启动 VM：之后重写 1 GB（日志未清零） | 119 ms | 88–89 ms | 慢 33–35% |
  | 冷启动 VM：随机读写（Mops/s） | 79–80 | 87–94 | 低 9–16% |
  | 冷启动 VM：分配密集（Mops/s） | 1.97–2.03 | 2.19–2.21 | 低 7–11% |
  | 冷启动 VM：拍快照（日志清零）后重写 1 GB | 314–317 ms | 89 ms | 每页多约 0.85 µs |
  | 冷启动 VM：宿主机 THP 大页 | 1186–1188 MB | 1186–1190 MB | 相同 |
  | 恢复的副本：随机读写、分配密集、重写 | — | — | 波动大于差别（±20% 以内，方向不一致） |
  | 恢复的副本：兄弟副本读完 1 GB 后，写 16 MB 再暂停，合并量 | 24–26 MB | **3072 MB（整个内存）** | — |
  | 同上，暂停耗时 | 103–111 ms | 1152–1533 ms | — |
  | 冷启动 VM 拍全量快照（3 GB） | 1.06–1.39 s，写 3072 MB | 同 | — |

- **结论**：
  - 开销集中在**冷启动的 VM**：两种配置下宿主机都用大页（THP）承载 guest 内存，但开着脏页日志时 KVM 只用 4K 映射，所以即使没有任何写保护缺页（日志未清零时的重写），也慢 33%；随机访问和分配密集的负载低 7–16%。这是根据"大页量相同、未清零时也慢、4K 映射的恢复副本没有差别"推断的，没有用性能计数器直接验证。
  - **从快照恢复的 VM 没有可测出的开销**：它的内存是 `MAP_PRIVATE` 映射的文件，写入后复制出的页本来就是 4K。
  - **`mincore` 对恢复的副本不可用**：页缓存里的页不分是谁读进来的，刚写完的快照文件整份都在页缓存里，增量变成了整个内存（3072 MB 对 25 MB），暂停从约 0.1 s 变成 1.2–1.5 s。加上宿主机开着 swap（bm1 有 16 GB 的 swap 文件），被换出的页会漏掉，有数据损坏的风险。所以关掉跟踪时不能用 `mincore` 拍 Diff，只能拍全量。
  - 清零后第一次写的代价约每页 0.85 µs，对按页写入的负载是 3.5 倍，但只发生在每次快照之后的第一次写。
- **已实施（2026-10-22）：冷启动的 VM 可以不开跟踪**，配置项 `cold_boot_dirty_tracking`（默认 `true`，即保持原来的行为）。
  - 设为 `false` 时：冷启动的 VM 不开跟踪（运行时状态记 `untracked`），没有 Base，暂停和快照都拍全量；从快照恢复（包括恢复暂停的 VM）时照常开跟踪，此后和原来一样只写脏页。
  - 没开跟踪的 VM 拍完快照后继续运行，这份快照不能作为它下一次增量的 Base：Firecracker 关着跟踪拍 Diff 会退回 `mincore`，上面说过这不安全。
  - 全量快照里包括整份内存的零页。暂停的文件本来就会在后台打洞；快照原来不打洞，现在在 VM 恢复运行之后、移进镜像库之前同步打洞，镜像库里只存数据（8 GB 的 VM 从 8192 MB 降到 464 MB）。
  - 测试 `TestUntrackedBoot`：快照是全量且不成为 Base；第一次暂停是全量，恢复后的暂停是增量；内存内容不变；快照的副本是开跟踪的。
- **第一次暂停的代价**（`TestFirstPauseCost`，2026-10-22，bm1 空闲；VM 2 vCPU，写入 256 MB 数据）：

  | VM 内存 | 跟踪 | 第一次暂停 | 暂停文件（打洞后） | 拍快照 | 镜像库里的内存文件 | 之后的暂停 |
  |---|---|---|---|---|---|---|
  | 1 GB | 开 | 0.24 s | 339 MB | 0.17 s | 349 MB | 0.08 s |
  | 1 GB | 关 | 0.54 s | 339 MB | 0.97 s | 339 MB | 0.08 s |
  | 4 GB | 开 | 0.39 s | 460 MB | 0.26 s | 475 MB | 0.08 s |
  | 4 GB | 关 | 2.6 s | 397 MB | 3.4 s | 396 MB | 0.09 s |
  | 8 GB | 开 | 0.42 s | 527 MB | 0.29 s | 550 MB | 0.09 s |
  | 8 GB | 关 | 5.1 s | 463 MB | 6.7 s | 464 MB | 0.10 s |

  - 关掉跟踪后，第一次暂停和每次快照的耗时随 VM 内存线性增长（约每 GB 0.6 s），其中大部分时间 VM 是冻结的（8 GB 的快照冻结约 4 s，其余是打洞）；之后的暂停没有差别。
  - 所以默认仍开跟踪。只在长时间计算、很少暂停或 fork 的负载上关掉。

#### UFFD 异步写保护的验证（2026-10-22）
在改 Firecracker 之前，先用一个 C 程序（`internal/edge/backend/microvm/testdata/uffdwp`）在 bm1（内核 6.8，THP `always`）上验证两个前提：异步写保护（`UFFD_FEATURE_WP_ASYNC`，用 `PAGEMAP_SCAN` 取写过的页并重新保护）能不能用在恢复 VM 时用的 `MAP_PRIVATE` 文件映射上；以及它能不能保住冷启动 VM 的大页。

- **文件映射（恢复的 VM）**：可以用，而且符合要求。
  - 1 GB 文件私有映射，注册写保护成功（内核 6.7 起，只开异步写保护时允许任意内存类型）。
  - 跟踪精确：用户态写入的页，以及内核代为写入的页（`pread` 进映射，相当于 KVM 或设备写 guest 内存），一页不差；重新保护后的第二轮也精确。
  - 页缓存仍然共享：两个进程同时私有映射同一文件并开写保护，读过的 1007 MB 都是 `Shared_Clean`，只有写过的 11 MB 成为私有副本。
  - 非特权进程可以用：`vm.unprivileged_userfaultfd = 0` 时，以 `UFFD_USER_MODE_ONLY` 创建即可，内核代写的页照样被跟踪（异步写保护在内核里就地处理，不经过用户态处理进程）。不带这个标志会 `EPERM`。
- **匿名大页（冷启动的 VM）**：**保不住大页**。
  - 写保护之后大页还在（`AnonHugePages` 2048 MB），但第一次写就把大页拆成 4K，之后一直是 4K（`AnonHugePages` 0）。
  - 结果和 KVM 脏页跟踪差不多：2 GB 首次写每页多约 0.36 µs；随机读写从 98 降到 84 Mops/s（低 14%，KVM 跟踪实测低 9–16%）。
  - 粒度是 4K：写一个字节只报一页。
- **结论**：UFFD 异步写保护不能解决冷启动 VM 的性能问题，**不为这个目的修改 Firecracker**。冷启动 VM 要拿回大页，只能不跟踪（上面的 `cold_boot_dirty_tracking`）。UFFD 写保护的价值仍在 19.14 第 3 阶段：和 UFFD 按需拉页（跨节点恢复）放在同一处理进程里，以及用同步写保护把复制脏页移出暂停窗口。到那时，上面验证过的几点（私有文件映射可用、非特权可用、精确到 4K）可以直接用上。

### 19.15 从快照创建的耗时拆分（2026-10-16）
- **埋点**：从快照创建时，microvm 后端按步骤计时（`stopwatch`），写进 debug 日志（`microvm restore steps`）和指标 `opendsec_edge_create_phase_seconds{phase="restore_<步骤>"}`。步骤：
  - `prepare`：分配 uid、建目录和 cgroup；
  - `network`：网络命名空间和网卡（测量时没有网络）；
  - `config`：生成配置盘（mkfs）；
  - `files`：链接快照文件、复制可写盘；
  - `jailer`：启动 jailer 进程（`fork`/`exec` 返回）；
  - `api`：直到 Firecracker 的 API 应答（jailer 建 jail、启动 Firecracker）；
  - `load`：`PUT /snapshot/load`；
  - `vsock`：直到 aether 在 vsock 上接受连接；
  - `grpc`：建 gRPC 连接并收到第一个心跳；
  - `post_restore`：设置时钟、熵、主机名和 machine id；
  - `attach`：开始监视、保存状态。
- **测量**（`TestRestorePhases`，需要 `OPENDSEC_BENCH=1`；bm1，512 MB / 1 vCPU 的 VM 内含 128 MB 数据，同一快照连续创建 20 次，没有网络）：

  | 步骤 | 页缓存命中 p50 / p90 | 每次创建前丢弃快照的页缓存 p50 / p90 |
  |---|---|---|
  | **创建合计** | **41–44 / 53–55 ms** | **56–62 / 72–75 ms** |
  | prepare | 1.8 / 2.2 | 1.8 / 16（偶发） |
  | config | 2.8 / 3.3 | 3.0 / 3.3 |
  | files | 1.4 / 1.7 | 1.4 / 1.7 |
  | jailer | 2.6 / 11.5 | 2.6 / 3.0 |
  | api | 9.1 / 11.3 | 9.0 / 11.2 |
  | **load** | **16–20 / 26–31** | **14–19 / 27–28** |
  | vsock | 1.1 / 1.1 | 12.7 / 14.2 |
  | grpc | 2.6 / 2.9 | 7.8 / 8.3 |
  | post_restore | 1.6 / 1.9 | 2.0 / 2.5 |
  | attach | 0.7 / 0.8 | 0.7 / 0.8 |
  | 创建后第一条命令 | 2.7 / 2.9 | 6.7 / 7.8 |

  关掉脏页跟踪对各步骤没有可测出的影响（`OPENDSEC_BENCH_NOTRACK=1`）。测量时线上压测在跑（bm2 发起，两台 BM 的 edge 都在创建），下面 `load` 和 `jailer` 的抖动和这些并发创建有关（见 favordynmods）。
- **`load` 的大头是内核创建 VM**：
  - strace 显示，Firecracker 的 `KVM_CREATE_VM` 少数时候 0.4–0.6 ms，多数时候 6–24 ms。
  - bpftrace 进一步定位到 `kvm_arch_post_init_vm` → `kvm_vm_create_worker_thread`：KVM 为每个 VM 创建 NX 大页恢复线程（`kvm-nx-lpage-recovery`），并用 `cgroup_attach_task_all` 把它挂到创建者的 cgroup 里，耗时 4–32 ms，多数是 8–16 ms。这要拿 `cgroup_threadgroup_rwsem` 的写锁，需要等 RCU，所以时快时慢。
  - 测量期间线上压测的冷启动也是同样的分布，冷启动同样承担这一段。
  - bm1 上 `kvm.nx_huge_pages=N`（关闭，但不是 `never`），CPU 的 `itlb_multihit` 是 "Not affected"。缓解措施本来就没开，线程却照样创建；设成 `never` 就不会再创建它。
- **`api` 里的 jailer**：jailer 的 `pivot_root` 稳定在约 5.4 ms（strace 下）。内核的 `pivot_root` 会遍历宿主机上所有线程，修正它们的根目录引用。bm1 当时约 2 万个线程，所以这段耗时会随节点上的 sandbox 数增长。这是根据内核实现推断的，没有单独验证。
- **丢弃页缓存后**创建合计多约 15 ms，主要在 `vsock` 和 `grpc`；创建之后的第一条命令另外慢约 4 ms。原因是恢复后 guest 里的 aether、内核要访问的页需要从磁盘读入。预取恢复后会用到的页可以消除这部分。
  - 22:30 前后在 bm1 上的复测中，丢弃页缓存时 `vsock` 是 27–29 ms（上表是 12.7 ms），开关 favordynmods 都一样，原因没有查。
- **favordynmods 实测**（2026-10-16 晚，bm1，线上压测在跑）：
  - cgroup v2 的挂载选项 `favordynmods`（内核 6.0 起）让 `cgroup_threadgroup_rwsem` 的写端不再等 RCU，代价是读端（fork、线程创建、exit）走慢一些的路径。它可以在线开关，不需要排空节点。
  - 从快照创建（`TestRestorePhases`，关 2 轮、开 3 轮，p50 / p90，ms）：

    | 步骤 | 关 | 开 |
    |---|---|---|
    | 创建合计，页缓存命中 | 40–44 / 53–54 | **28–30 / 33–34** |
    | 创建合计，丢弃页缓存 | 76–79 / 86–90 | 64–68 / 66–75 |
    | `load`，页缓存命中 | 14–17 / 22–30 | **2.0–2.1 / 2.3–2.7** |
    | `load`，丢弃页缓存 | 16–17 / 21–27 | 5.0–5.7 / 5.3–7.7 |
    | `jailer` 的 p90 | 9–20 | **3–5** |
    | 其他步骤 | 不变 | 不变 |

    - 证实 `load` 慢在上面那把锁：关掉写端等 RCU 之后，`load` 只剩约 2 ms。
    - 上表 `jailer` 的长尾（p90 11.5 ms）也是同一把锁：jailer 的 `clone` 要拿读锁，正好碰上别的 VM 创建在等写锁时就被堵住。
  - 64 个副本同时从一份快照恢复（`TestFork64`，关、开交替各 2 轮）：

    | | 64 个合计 | 单个 p50 |
    |---|---|---|
    | 关 | 434 / 417 ms | 339 / 300 ms |
    | 开 | 382 / 361 ms | 285 / 247 ms |

    并发恢复快 12–15%。
  - 代价（自写的基准程序，每项 5 秒，关、开交替各 2 轮，单位：次/秒）：

    | 测试 | 并发 | 关 | 开 |
    |---|---|---|---|
    | fork+exec+exit | 1 / 32 / 256 | 2597、2573 / 26041、25915 / 20715、21085 | 2605、2674 / 25948、25949 / 20269、20735 |
    | 线程创建+退出 | 1 | 32012、32489 | 31421、30233（低 2–7%） |
    | | 32 | 42159、41063 | 40967、40475（低 1–3%） |
    | | 256 | 21423、19139 | 15314、20660（两轮方向相反，没有结论） |

    - 进程的创建和退出（容器里最常见的路径）测不出差别。
    - 线程创建慢几个百分点。测试是每秒 3–4 万次的极端负载，实际负载远达不到。
    - 并发 256 的线程创建结果不确定，要更多轮才能定论。
  - 测试期间线上压测（每 10 秒约 100 次 microVM、50 次容器创建）一直没有失败。
  - **在线开关的坑**：util-linux 2.39 的 `mount -o remount,...` 会把现有选项合并回去，去掉 `favordynmods` 时命令成功但选项还在；`--options-mode=replace` 则报 "already mounted"。要直接调 `mount(2)`：`MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME`，data 写完整的选项（`nsdelegate,memory_recursiveprot[,favordynmods]`），漏掉 `nsdelegate` 会关掉它。改完要查 `/proc/mounts` 确认。
- **优化方向**（未实施，按收益排序）：
  1. **cgroup v2 `favordynmods`**：实测见上，`load` 从 14–17 ms 降到约 2 ms，`jailer` 的长尾消失，并发恢复快 12–15%，代价只有线程创建慢几个百分点。可以在线开启，冷启动同样受益。要持久化，需要在节点启动时（`deploy/node/install.sh` 或 edge 启动时）按上面的方式设置并检查。
  2. **`kvm.nx_huge_pages=never`**（AMD 不受 iTLB multihit 影响）：根本不创建那个线程。效果应和 favordynmods 相近（`load` 约 2 ms），但没有实测，也不能消除 `jailer` 的长尾。要在没有 VM 运行时设置（内核拒绝在有 VM 时改成 `never`），或者写进 modprobe 配置后重启或重新加载 kvm 模块。
     - 较新的内核据说把这个线程改成了 vhost_task，并改为按需创建，不再走 `cgroup_attach_task_all`，升级到 HWE 内核可能也能消除这段开销。这条凭记忆，待核实。
  3. **预先启动 jailer 和 Firecracker**：每个节点保留几个已经进了 jail、API 就绪的 Firecracker 进程，创建时直接加载快照。`jailer`、`api` 两步（约 12 ms）移出关键路径，也避开随线程数增长的 `pivot_root`。难点在于 jail、uid、cgroup、网络命名空间要在分配给 sandbox 之前确定。
  4. **配置盘**：从快照恢复时，guest 已经读过配置，身份信息由 `post_restore` 下发；可以复用一份预先做好的配置盘，省去 mkfs（约 2.5 ms）。
  5. **预取**：记录恢复后最先访问的内存页（参考 REAP、E2B），创建时预先读进页缓存，节省快照不在页缓存时多出的约 15 ms。
  6. **预建池**：从模板快照提前恢复好一批 VM，创建时直接分配（类似 fncall 的预建池），创建延迟可以降到毫秒级。


## 20. P3：网络策略（2026-10-15）
> 论文用 eBPF 执行网络策略，这里用 nftables + edge 内置的 DNS 代理实现同样的语义：默认拒绝，按规则放行，规则可以在运行中修改。代码在 `internal/edge/netpol`。

### 20.1 接口
- `SandboxSpec.network_rules`（论文示例里的字段，原先被忽略）：键是规则集名（集群配置 `network.rule_sets`）、域名（同时覆盖它的子域名）、IPv4 地址或网段，或 `"*"`（所有公网地址），后面可以加 `:端口[/协议]`（§29.2）；`true` 放行，`false` 撤销集群默认规则 `network.default_rules` 里的一项。未知的规则名在创建时返回 `invalid`。
- `OpenDsec.UpdateNetwork(sandbox_id, rules, replace)`：合并或替换规则，需要 `sandbox.operate`。撤销立即生效，已建立的连接也会被切断（见 20.2）。SDK `Sandbox.update_network`，命令行 `opendsecctl sandbox network <id> pypi !npm`，创建时 `-net`。
- edge 配置 `network: {enabled, subnet, dns_port}`，默认关闭（关闭时和以前一样只有 lo）。同一台机器上的多个 edge 需要不同的网段和端口。

### 20.2 实现
- **每个 sandbox 一个网络命名空间**（`/run/netns/opendsec-<edge>-<lease>`），用 veth 接到宿主机，占 edge 网段里的一个 /30；分配记录在 `<state_dir>/<edge>/net/` 下，edge 重启后照常接管。
  - 容器：init 进程仍然带 `CLONE_NEWNET` 启动，edge 用 `ip netns attach` 给它的命名空间命名，再接上 veth。
  - microVM / 完整 VM：edge 先建命名空间，jailer 用 `--netns` 加入（QEMU 在切换到该命名空间的线程上 fork）。命名空间里是 Firecracker 推荐的克隆网络布局：每个 VM 都是同样的 tap0（固定 MAC）和同样的 guest 地址 172.16.0.2，在命名空间出口做 masquerade，DNS（发往 172.16.0.1）DNAT 到宿主机一侧。所以快照副本不用改 guest 网络，暂停 / 恢复也保留命名空间。
  - guest 网卡由 vminit 用 ioctl 配置。最初用内核参数 `ip=`，内核自动配置要多等约 20 ms。
- **宿主机过滤**：每个 edge 一张 nftables 表 `inet opendsec_<edge>`。
  - 发往 sandbox 的新连接一律丢弃（其他 sandbox、宿主机、外部），回包放行。
  - sandbox 发出的每个包（包括已建立连接的）按「入口 veth + 源地址」查 verdict map，跳到该 sandbox 自己的链，伪造源地址的包查不到而被丢弃。链的顺序是：放行规则里的网段 → 丢弃私网、链路本地、组播、云元数据等地址 → 放行 DNS 代理学到的地址 → 规则含 `"*"` 时放行 → 丢弃。
  - 已建立的连接也逐包检查，所以撤销规则会立即切断连接；学到的地址在有流量时刷新超时，闲置 1 小时后过期，长连接不会因为超时被断开。
  - 宿主机上除 DNS 代理端口外的服务都不可达；DNS 代理端口只对 sandbox 开放，避免成为开放解析器。veth 名字带 edge 的哈希，同一台机器上不同 edge 的规则互不干扰。
- **DNS 代理**（UDP / TCP）：按查询的源地址识别 sandbox。
  - 允许的域名转发给上游（默认取宿主机 `/etc/resolv.conf`），把应答里的 IPv4 地址加进该 sandbox 的放行集合后再返回；超时取 TTL，限制在 5 分钟到 1 小时之间。
  - 不允许的域名返回 NXDOMAIN；AAAA 查询返回空应答（sandbox 只有 IPv4）。
- edge 开启网络时会打开宿主机的 `net.ipv4.ip_forward`。
- **已知限制**：
  - 按 IP 放行：CDN 上和允许域名共用 IP 的其他站点也能访问（要更严格需要 SNI 过滤）；
  - 直接用 IP 地址访问需要有网段规则；
  - 不支持 IPv6。
- chronus 的 `Http` 调用每次新建连接：复用的长连接在快照恢复（新的命名空间）或规则撤销后会失效。

### 20.3 测试
- `netpol` 集成测试（需要 root、nftables 和外网，`OPENDSEC_NET_TESTS=1`）：
  - 允许的域名可解析、可连接；拒绝的域名返回 NXDOMAIN，用 IP 直连也不通；
  - 默认规则里的网段可达，不在规则里的地址不可达；
  - 宿主机的 sshd 和其他 sandbox 不可达；`"*"` 下元数据地址和私网地址仍不可达；
  - 撤销后不能再解析，旧地址也立即不可达；
  - 重建 manager 后保留的 sandbox 照常可用，未保留的被清理；释放后不留命名空间和链。
- e2e `TestNetworkPolicy`：容器、fncall（取用预建 sandbox 时才接上网络）、完整 VM、microVM 四种后端，都在 sandbox 里用 HTTPS 访问 pypi.org 和 example.com，按规则通或不通；运行中修改规则。microVM 还覆盖暂停 / 恢复、fork 出的副本（各自的命名空间）、edge 重启后网络照常可用并且还能改规则。结束后不留命名空间。
- 带网络的创建耗时：容器约 30 ms；microVM 约 170 ms（含第一次使用镜像时的展平）；完整 VM 约 290 ms。

## 21. P3：容器加固与文件访问限制（2026-10-15）
- **起因**：容器 sandbox 里的 root 原先保留全部 capability，`/proc/sys` 可写，写 `/proc/sys/kernel/core_pattern` 就能在宿主机上执行命令（逃逸）；这是 11.7 记下的「没有 seccomp」。容器的 setup 进程在 exec aether 之前做以下几件事，之后的所有进程都继承：
  - **capability**：bounding set 只留 Docker 的默认集合，去掉 `CAP_MKNOD`（没有 device cgroup，设备节点能直接读宿主机磁盘）。capability 是按线程的，setup 进程锁定在执行 exec 的线程上。
  - **seccomp**（BPF，拒绝时返回 EPERM，用 `TSYNC` 作用到所有线程）：
    - 非 x86_64 的入口（i386 / x32）一律拒绝，避免绕过系统调用号；
    - 拒绝 mount 及新的挂载 API、`pivot_root`、`setns`、模块加载、kexec、`bpf`、keyring、`open_by_handle_at`（shocker 逃逸）、`userfaultfd`、`perf_event_open`、I/O 端口、swap、quota、reboot、改时钟；
    - `clone` / `unshare` 只拒绝带 `CLONE_NEWUSER` 的调用（新的 user namespace 会拿回 capability）；`clone3` 返回 ENOSYS，让 libc 退回 `clone`。
  - **/proc**：和 runc 的默认一样，`/proc/sys`、`sysrq-trigger`、`irq`、`bus`、`fs` 只读，`kcore`、`keys`、`kallsyms` 等屏蔽。
- **文件访问限制**：`SandboxSpec.readonly_paths` / `masked_paths`（新字段 13、14，`internal/sandboxfs`）。
  - 路径在 sandbox 的根里解析，只读用重新挂载实现；屏蔽时目录换成空的只读 tmpfs，文件换成 `/dev/null`。
  - 容器里 root 撤销不了这些限制（没有 mount 也没有 `CAP_SYS_ADMIN`）；microVM / 完整 VM 里由 vminit 设置，guest 的 root 可以撤销，所以这类场景要配合非 root 的 `init_user`。
  - edge 在创建时检查路径必须是干净的绝对路径。
- **guest OOM 时保护 aether**（19.10 留下的问题）：aether 和 chronus 的 `oom_score_adj` 设为 -1000。容器在 setup 进程里设置，那时还有 `CAP_SYS_RESOURCE`；VM 在 vminit 里设置；chronus 把它启动的用户命令改回 0。
- **顺带修复 `init_user`**：会话目录的上级目录原先是 0700，非 root 用户的 shell 读不到命令脚本，所有命令都返回 1 且没有输出；microVM 的 `/.opendsec/run` 也是 0700。之前没有测试覆盖。
- **测试**（`TestHardening`、`TestOOMSparesAgents`）：
  - capability 恰好是保留的那一组；
  - mount、umount、写 core_pattern、sysrq、`unshare -U`、`unshare -m`、mknod、setns 都失败；
  - 屏蔽的路径读出来是空的，只读路径不能写；
  - 普通操作（写文件、chown、读 `/proc/sys`、Python 多线程）正常；
  - 在 128 MB 的 sandbox 里申请 512 MB 的进程被杀掉，aether 照常响应。

## 22. P4：RL 协同（2026-10-15）
### 22.1 容器暂停时回收内存
- 后端配置 `pause_reclaim`：冻结后把 sandbox 的匿名内存换出到 swap，恢复时在后台用 `process_madvise(MADV_WILLNEED)` 预取回来，不用等缺页时一页一页地读（论文 §4.3）。
- 实现过程中的发现：
  - `memory.reclaim` 遵循宿主机的 `vm.swappiness`（测试机的云镜像设为 0），这时 cgroup 回收完全不碰匿名页；6.10 之前的内核也不能在 `memory.reclaim` 里单独指定 swappiness。所以先对每个进程用 `process_madvise(MADV_PAGEOUT)` 换出（不受 swappiness 影响，冻结状态下也可以），再只针对 swap cache（`memory.stat` 的 `swapcached`）调用 `memory.reclaim`，并限时 3 秒。在冻结的 cgroup 上请求超过可回收的量，内核会一直重试。
  - 开启 `pause_reclaim` 需要宿主机有 swap，且 `vm.swappiness > 0`；swappiness 为 0 时 edge 启动报错并给出设置方法，不会自己修改宿主机设置。
- 实测（BM）：暂停 85 ms，sandbox 内存从 227 MB 降到 7 MB；恢复后进程持有的 200 MB 数据校验无误。

### 22.2 GPU
- edge 配置 `gpu: {devices, extra, mounts, shared_slots}`（`linuxrt.GPUs`，同一个 edge 上所有容器运行时的后端共用）。
  - 独占的 sandbox（`resources.gpus = n`）拿到 n 整张卡；`gpu_mode = "shared"` 的 sandbox 拿到某张没有被独占的卡上的一个槽位（默认每卡 4 个，由驱动分时或 MPS 共享），优先选用户最少的卡。
  - 设备节点和 `extra` 里的节点（`nvidiactl`、`nvidia-uvm` 等）挂进容器的 `/dev`，`mounts` 里的驱动库只读挂入，并设置 `CUDA_VISIBLE_DEVICES`。
  - 分配记录在运行时状态里，edge 重启后接管。`capacity.gpus` 默认取设备数。
- 测试机没有 GPU，测试用假的设备节点（major/minor 指向 `/dev/null`）验证了分配、共享槽位、容量不足时返回 `no_capacity`、释放后可以再分配，以及容器里能看到的设备、环境变量和挂载。

### 22.3 FnCall 后端（预建池）
- 容器运行时的后端配置 `warm_pool: {image: n}`（`container/pool.go`），例如配置成名为 `fncall` 的后端：后台为每个镜像保持 n 个已经启动、aether 已就绪的 sandbox。
- 普通请求（不带快照、`init_user`、`workdir`、路径限制、GPU，磁盘为默认大小）直接取一个：
  - 当场设置它的 cgroup 限额（cpu、memory、QoS）；
  - 有网络时接上网络，把 resolv.conf 原地写好（这个文件在启动时就已经绑定挂载）；
  - 不满足条件的请求照常冷启动。
- 预建 sandbox 保留自己的状态目录和 cgroup。cgroup v2 不支持 rename；迁移进程又会让 sandbox 里看到的 cgroup 视图（cgroup namespace 的根）不再是它的限额。所以 sandbox 自己的 lease 只是状态目录里的一个符号链接，接管和遗留清理都会跟随这个链接。
- 实测：经 API 创建 fncall sandbox，BM 上 1–2 ms，开发机上 5–25 ms；预建池在后台补充。
- 预建的 sandbox 不计入 edge 的容量记账，需要在节点容量里预留。

### 22.4 CPU QoS 与解耦 rollout 示例
- QoS：BE sandbox 的 cgroup 设置 `cpu.idle`（P2 起就有，这次补了测试）。BM 上 LS 和 BE 两个 sandbox 绑在同一个 CPU 上跑忙循环，3 秒内 LS 跑了 173 万次，BE 只有 5 千次。开发机（Hyper-V 虚拟机、1 个 vCPU、内核 7.0）上 cgroup 的 CPU 权重看不出效果，原因没有查明，测试改为至少 2 个 CPU 才运行。
- `sdk/python/examples/decoupled_rollout.py`：多条轨迹各自在自己的 sandbox 里执行动作。
  - 等待推理时暂停 sandbox，下一条命令到来时透明恢复；
  - 训练端更新权重时用 `pause_task` / `resume_task` 冻结整个 rollout；
  - 结束时 `stop_task`；
  - pytest 里用真实的容器集群跑了一遍。

## 23. P5：QEMU 完整 VM 后端（2026-10-15）
- **运行时**：运行时 `qemu`，后端 `internal/edge/backend/fullvm`。
  - 每个 sandbox 是一个 QEMU 进程：q35 机型、KVM、直接引导 opendsec guest 内核（PVH）。
  - 磁盘沿用 microVM 的四块盘布局，挂在 virtio-blk-pci 上；镜像盘缓存和盘的构建代码从 microvm 包导出复用。
  - aether 走 vhost-vsock（每个 VM 一个全机唯一的 CID）；edge 侧新增 `aether.DialVsock`，Go 的 `net.FileConn` 不支持 AF_VSOCK。
  - QEMU 以每个 VM 独立的 uid 运行，附加 kvm 组（`/dev/kvm`、`/dev/vhost-vsock` 属于 kvm 组），放在该 sandbox 的 cgroup 里，开启 `-sandbox`（seccomp）。
- **和 microVM 的区别**：
  - 有完整的 PCI 总线：edge 配置 `gpu.pci` 列出 PCI 地址，`resources.gpus` 按整卡分配，以 `vfio-pci` 直通。测试机没有可以直通的设备，这部分没有实测。
  - `full_init: true` 时，vminit 先把 aether 服务作为子进程拉起，再 exec 镜像自己的 `/sbin/init`（比如 systemd）作为 PID 1；镜像里没有 init 时退回 aether 作为 PID 1。
  - 暂停是 QMP 的 `stop` / `cont`，只停 vCPU，内存保留；没有内存快照和 fork（§19.8）。
- 实测：启动 225–238 ms（第一次使用镜像时多出展平的时间）；暂停、edge 重启后接管（暂停中的 VM 接管后仍是暂停状态）、停止后清理干净都有测试。
- 实现中的一个问题：vsock 的非阻塞 connect 第一次被唤醒时 `SO_ERROR` 还是 0，导致把未完成的连接当成了成功，表现为每次启动要重试十几秒。改成先等可写、再检查 `SO_ERROR`。

## 24. 运维收尾（2026-10-15）
- **镜像库垃圾回收**：`opendsecctl image gc -store DIR [-grace 24h] [-dry-run]`（`Store.GC`）。
  - 引用来源：镜像清单、快照记录，以及容器 sandbox 运行时登记在 `<store>/inuse/` 下的层（sandbox 可能比它的镜像活得久）；容器结束或 edge 清理遗留时撤销登记。
  - 回收对象：没有被引用、并且超过宽限期的层；没有被镜像引用的旧快照（fork 的快照只在启动副本时用到；VM 副本持有文件的硬链接）；中断的写入。
  - 被重新导入（内容寻址、直接复用）的层会刷新时间戳，重新进入宽限期。
- **节点镜像盘缓存**：microVM 和完整 VM 都把镜像盘硬链接进每个 VM 的目录。链接数为 1（没有 VM 或快照在用）且 24 小时没用过的盘，由后台每分钟检查一次并删除。
- **磁盘 IO 限速**：后端配置 `disk_io: {read_mbps, write_mbps, read_iops, write_iops}`。
  - 容器：在可写盘的 loop 设备上设置 `io.max`。
  - microVM：Firecracker 磁盘的 `rate_limiter`。Firecracker 的令牌桶读写共用，取读、写里较低的那个值；只设 cgroup 的 `io.max` 不起作用，因为 Firecracker 忽略 guest 的 flush（缓存模式是 `Unsafe`），数据只停留在宿主机的页缓存里。
  - 完整 VM：QEMU 的 `throttling.*` 参数。
  - io 控制器只在配置了 `disk_io` 的后端启用：开发机（内核 7.0、loop 设备）上启用 io 控制器后，内存很紧的 sandbox 在大量写页缓存时会被 OOM 杀掉。
  - 实测：24 MB 按 8 MB/s 写入，容器 3.0 s，microVM 1.96 s（令牌桶开始时是满的），完整 VM 2.96 s。
- **暂停中 sandbox 的内存记账**：edge 配置 `paused_mem_charge`（0–1，默认 1，即不变）。
  - 真正释放了内存的暂停（microVM；开启了 `pause_reclaim` 的容器）只按这个比例计入内存容量。
  - 恢复时重新全额计入：节点处于内存压力之下时恢复返回 `no_capacity`；否则即使暂时超出容量预算也照常恢复，新的创建会被拒绝，直到用量降下来。
  - edge 重启后，暂停中的 sandbox 重新按比例计入；在暂停状态下结束的 sandbox 退回的是它实际被计入的量。
- **内存紧张时充气 balloon**：edge 每秒检查一次。
  - 可用内存低于 `mem_reserve_mb` 的 1.5 倍时，挑选运行中、有 balloon 的 sandbox（BE 优先，其次空闲最久的），每轮把 balloon 充到内存的 25%，最多 50%，直到补足缺口；
  - 可用内存回到预留值的 3 倍以上时放气。guest 先交出空闲内存和页缓存，`deflate_on_oom` 保证 guest 在 OOM 前能从 balloon 拿回内存。
  - 实测：512 MB 的 VM 充气 300 MB 后，常驻内存从 320 MB 降到 258 MB，正好在它最多还能用的范围（512 − 300 MB，加上 VMM 自身）内；放气后 guest 正常。
- **暂停内存文件打洞**（19.13 留下的问题）：暂停完成后，后台用 `fallocate --dig-holes` 把全零的块打成空洞（交还宿主机的页在快照里是零页）。下一次暂停原地合并之前，先停掉还在进行的打洞，避免抹掉刚写入的页。实测：回收过冷内存的 VM 暂停文件从 470 MB 降到 278 MB。
- **测试**：
  - 镜像库 GC：被镜像、快照、运行中 sandbox 引用的层保留；无主的层和旧快照被删除；dry-run 不删；撤销登记后再回收；被重新导入的层不会被回收；
  - 三种后端的 IO 限速；
  - 暂停记账、balloon 调度策略（sim 后端）；
  - 真实 microVM 的 balloon 充气；
  - 打洞后的内存文件大小。


## 25. 两节点验证（2026-10-15）
> 环境：两台裸金属，各 384 线程、1.5 TB 内存、2 × 3.5T NVMe RAID0，同一内网（延迟约 0.13 ms）。第一台的 `/data` 是 ext4，第二台是 XFS。镜像库是第二台导出的 NFS 4.2（`nconnect=8`），两台都挂在 `/mnt/opendsec-images`。组件全部走 mTLS：IAM、watcher、apiserver-0 和 edge e1 在第一台，apiserver-1 和 edge e2 在第二台；镜像是从 Docker Hub 导入的 `python:3.12-slim`。

### 25.1 结果
| 项目 | 结果 |
|---|---|
| 调度 | 批量创建平均分到两个节点；容器、microVM、完整 VM 里都能运行镜像中的 python |
| 第一次在某节点使用镜像 | microVM / 完整 VM 要从 NFS 读层并展平，4 个共 5–8 s；之后 8 个 microVM 共 261 ms，8 个完整 VM 共 532 ms |
| 单个创建（经 API，含 opendsecctl 启动和 TLS，带网络） | 容器约 65 ms，fncall 40–60 ms，microVM 约 190 ms，完整 VM 约 300 ms |
| fork（源 512 MB，内存里有 100 MB 数据） | 同节点 8 个 448 ms、32 个 897 ms；源节点排空后到另一节点 8 个 1.6 s、32 个 2.2 s（含经 NFS 发布快照和拉取），副本的内存状态正确。§26.1 之后到另一节点 8 个 581 ms、32 个 460 ms |
| edge 被 SIGKILL | 4 s 后被判为不健康；30 s 宽限期后配额回收（34 s）；期间新建的 sandbox 都落到另一节点；该节点上的 sandbox 一直在运行；edge 重启 5 s 后恢复，10 个 sandbox 全部被接管并可用，配额对账正确 |
| 突发创建容器（0.25 核、256 MB，带网络） | 2048 个 24 s，再加 4096 个 66 s，再加 2048 个 45 s，共 8192 个、全部成功；8192 个在跑时单个创建 134–161 ms |
| 批量停止 | 4096 个 30 s 左右 |
| 突发创建 microVM（512 MB，带网络、pmem、free page reporting） | 1024 个 11 s，再加 2048 个 33 s，再加 2048 个 51 s，共 5120 个、全部成功；宿主机实际共用约 468 GB（申请合计 2.6 TB，约 91 MB / 个） |

### 25.2 多机测试发现并修复的问题
- **快照写共享存储**：快照直接写进 NFS 上的镜像库，同节点的副本也要再整份拉回来。改为 §19.4 原本的设计：
  - 节点和镜像库不在同一个文件系统上时，快照先写本节点的快照缓存，记录里标记 `publishing` 后台发布到镜像库；
  - 本节点的副本立即可用（实测 41 ms）；
  - 其他节点等发布完成后再拉取（138 ms）；
  - 发布中途快照被删除（fork 的快照）就停止；edge 重启后接着发布。
- **NFS 上的 ESTALE**：快照记录被另一节点用 rename 原子替换时，正在读的一方得到 `stale file handle`，导致跨节点 fork 偶发失败。镜像库读 JSON 时遇到 ESTALE 改为重新打开。
- **两个容器运行时后端互相清理**：container 和 fncall 共用状态目录和 cgroup 路径。edge 重启时，一个后端把另一个刚接管回来的 sandbox 当作遗留物杀掉（10 个全部 `aether channel closed`）。现在每个后端有自己的路径（`container` 沿用原路径，以兼容旧部署），加了回归测试。
- **opendsecctl**：
  - 选项解析用的是写死的 bool 选项名单，`-undo`、`-dry-run`、`-replace` 后面的参数被当成了它们的值，改为从 FlagSet 判断；
  - 新增 `OpenDsec.DrainEdge` 和 `opendsecctl edge drain <edge> [-undo]`，需要 root 上的 `project.admin`，有 e2e。
- **规模**（按影响从大到小）：
  - **挂载命名空间复制**：容器的可写盘 loop 挂载和 netns 的绑定挂载都在宿主机上，8000 个容器就是 1.2 万多条挂载。每新建一个 sandbox 的挂载命名空间（`CLONE_NEWNS`）都要复制整张挂载表，耗时 120–140 ms 且线性增长。现在：
    - 容器的 netns 改为通过 init 的 `/proc/<pid>/ns/net` 引用；
    - 可写盘只挂在 sandbox 自己的挂载命名空间里：edge 只配置 loop 设备，由 init 挂载，并绑定到 sandbox 里的 `/.opendsec/disk`，edge 通过 `/proc/<pid>/root/.opendsec/disk` 访问可写层；
    - 旧版本留在宿主机上的盘照常兼容；
    - 宿主机挂载表从 1.2 万多条降到恒定 29 条，8192 个容器时单个创建从约 600 ms 降到约 140 ms，第二批 4096 个从 1 分 59 秒降到 66 秒。
  - **nft / ip 命令行**：每次加元素前 nft 都要先拉取整个规则集（3000 个 sandbox 时每次约 300 ms，而且 DNS 代理每学到一个地址也要加一次），`ip -n` 每次还要复制一份挂载表（约 110 ms）。每个 sandbox 的集合、链、map 元素，以及 netns、veth、tap、地址，改为直接走 netlink（`google/nftables`、`vishvananda/netlink`）；只有启动时下发的基础规则还用 nft。4000 个 sandbox 时，新增或删除一个约 1 ms。
  - **loop 设备争用**：几百个并发创建会拿到同一个空闲 loop 设备号，32 次重试不够（65 个 `no free loop device`），改为进程内串行分配。
  - **tap 偶发 EBUSY**：创建 tap 时，edge 同时 fork 的子进程在 exec 之前会短暂持有 tun fd 的副本，VMM 打开 tap 时可能遇到 EBUSY，约 0.4%。netlink 不能创建 tap，这个 fd 无法避免，所以 microVM（冷启动和快照恢复）与完整 VM 遇到时重启 VMM 重试，最多 3 次。
  - **edge 的 GC**：7000 多个 sandbox 时，edge 的 CPU 约 40% 花在扫描几万个 goroutine 的栈上，384 个 GC worker 还在互相争用。改动：
    - 服务进程默认最多用 32 个 P；
    - aether 心跳从 1 s 改为 15 s（丢失靠流断开判断，不靠心跳）。
    - 这两项降低了 CPU 占用，但创建延迟主要不在这里，起决定作用的是上面的挂载问题。
  - **edge 停止时的清理顺序**：先关闭 netlink 连接再清理，几千个网络要几分钟。改为先清理再关闭。
- **测试**：IAM 的 Raft 测试在整套测试的负载下偶发失败（选举恰好发生在写入时），改为写操作遇到「不是 leader」就换新 leader 重试。

### 25.3 宿主机上的系统服务
- 压测时 CPU 占用最高的是宿主机自带的服务：
  - 云厂商的监控代理（最高 340%）和安全代理；
  - systemd-udevd 及其 worker：每个 veth、loop、tap 都产生 udev 事件；
  - systemd（PID 1）：跟踪挂载变化，已经随挂载表一起解决；
  - udisksd：测试时已停掉，对创建速度影响不大。
- 密集部署 sandbox 的节点建议：停用 udisks2；把 veth（`ds*`）和 tap 从 networkd、NetworkManager 的管理范围里排除；评估云代理的采样频率。
- 吞吐量仍然随规模下降（85 → 46 个 / 秒），剩下的大头在 udev。另外，每个 microVM 有一个命名 netns（暂停时需要它保住网络），jailer 新建挂载命名空间时仍要复制这些挂载；5120 个 VM 时单个创建为 420–880 ms。
- **后续可做**：
  - 在私有挂载命名空间里管理 VM 的 netns（要解决 edge 重启后的接管）；
  - edge 自己处理 udev 事件，或把这类设备排除在 udev 规则之外。
  - 这两项都已在 25.4 完成。

### 25.4 VM 的 netns 与 udev（2026-10-15）
- **VM 的 netns 不再挂到宿主机上**：
  - 每个 VM 配一个占位进程（`sleep infinity`，约 1 MB），由它持有 netns，通过 `/proc/<pid>/ns/net` 引用；
  - 占位进程放在后端单独的 cgroup（`<backend>/netns`）里，暂停时结束 VM 进程不会误杀它，edge 重启后按 pid 和进程启动时间校验后继续使用；
  - 清理遗留时，结束不属于被保留 sandbox 的占位进程；microVM 和完整 VM 都改了。
  - 5120 个 VM 时宿主机挂载表也恒定在 29 条，e2e 里也加了检查。
- **udev 事件**：
  - 统计发现，500 个容器产生了 76.8 万个内核事件。原因是内核默认给 veth 每个 CPU 一对收发队列（这里是 384 + 384），每个队列都是一个带事件的内核对象，peer 端移进命名空间时还要再删除和重建一遍。
  - veth 两端改为 1 个收队列、1 个发队列后，500 个容器只产生 1251 个事件，约少了 600 倍。
  - 停掉 udevd 的对照实验表明，它原本约占突发创建耗时的 28%。`deploy/node/` 下的 udev 规则和 `.link`、`.network` 文件在对照实验里没有可见效果（耗时相同，udevd 加 PID 1 的 CPU 都是 202 s），但能减少 systemd 和 networkd 对这些设备的处理，作为节点准备保留。
- **tap 的 EBUSY 彻底解决**：之前的重试在高负载下（负载平均值 300+）也不够，失败率升到约 1.4%。tap 改为在 VM 的命名空间里由单独的 `ip tuntap add` 进程创建，edge 自己的 fd 表里从此没有 tun fd，之后 fork 的子进程也就无从继承。重试保留，加了退避。
- **edge 创建 microVM 的分阶段耗时**（debug 日志，5120 个 VM 时）：
  - 准备 4 ms，网络 25 ms，配置盘 6 ms，磁盘 8 ms，jailer 3 ms，启动 144 ms，共约 190 ms；
  - 空载时约 120 ms。
- **结果**：

  | 项目 | 25.2 修复后 | 25.4 |
  |---|---|---|
  | 容器突发创建 2048 + 4096 + 2048 | 24 + 66 + 45 s | 16 + 49 + 42 s |
  | microVM 突发创建 1024 + 2048 + 2048 | 11 + 33 + 51 s，0.4–1.4 % 失败 | 4.3 + 12.6 + 18.8 s，全部成功 |
  | 一次批量创建 5120 个 microVM | — | 37 s，约 137 个 / s |
  | 已有 5120 个 VM 时单个创建（经 API） | 420–880 ms | microVM 208–240 ms，容器 106–121 ms |
  | 停止 5120 个 microVM | — | 22 s |

- **仍在下降**：容器吞吐量仍然随规模下降（第三批 2048 个约 49 个 / s），云厂商监控代理在压测时最高占约 15 个核，还没有逐项排查。

## 26. 断线续传、跨节点 fork、暂停 sandbox 换节点、指标（2026-10-16）

### 26.0 SDK 断线续传
- **命令提交幂等**：`ExecRequest.request_id`（字段 8），由客户端生成。chronus 按会话去重：同一个 id 再次提交时返回已有的命令，不会再执行一次。在会话锁上排队的重复提交，拿到锁后也会再查一次。
- **流式续传**：`ExecRequest.stdout_offset` / `stderr_offset`（字段 9、10），ExecStream 从这里开始发送。
- **SDK**：
  - `run_shell`、`run_shell_background`、`stream_shell` 每次调用生成一个 request_id；遇到 `unavailable` 时退避重试，间隔从 0.1 s 翻倍到 2 s；
  - 重试窗口默认 60 s，从最近一次有进展算起，用 `DSecClient(retry_timeout=...)` 设置，0 表示关闭；
  - `stream_shell` 断开后，用同一个 request_id 和已收到的字节数重新打开流，输出不重复、不丢失；
  - 只读调用（`get_output`、`read_file`、`list_dir`、`stat`、`list_sessions`、`refresh`）同样会重试；`write_file`、`remove` 和生命周期操作不自动重试；
  - gRPC 重连退避的上限设为 2 s，默认最长是 2 分钟。
- **测试**：
  - chronus：命令运行中重试、结束后重试、流式重试、带偏移的续传、并发的重复提交，都只执行一次；
  - SDK：`opendsecctl cluster up` 收到 SIGUSR1 时会重启所有 edge（中断 1 s）。命令执行到一半时重启 edge，流式输出完整，并行的前台命令只执行一次；关掉重试后，同一个测试失败。
- **限制**：Go 客户端（`pkg/client`、opendsecctl）没有自动重试。

### 26.1 跨节点 fork：快照留在源节点
- **原因**（两节点实测）：
  - 源节点排空后，fork 8 个副本要 1.47 s。其中目标 edge 光读快照记录就花了 1.06 s。
  - 当时源 edge 正经 NFS 发布 368 MB 的快照，包括内存、可写盘，以及每次都整份复制一遍的只读镜像盘。目标的 NFS open 在这段时间里被挡住约 1 s。nfsd 线程增到 64、关闭委托都没有效果，单独复现时也不出现，根因未查明。
  - 发布本身要 0.4–0.5 s，而 fork 的快照在副本起来后就删除，发布完全是浪费。
- **做法**：
  - fork 的快照改为临时快照（`EdgeSnapshotRequest.ephemeral`）：文件留在源节点的快照缓存里，不发布；镜像库只写一条记录，`holder` 是源 edge。
  - 副本的创建请求带上源 edge（`EdgeCreateRequest.snapshot_peer`），目标 edge 直接从源 edge 拉取文件。这是新增的 edge 之间的调用 `Edge.FetchSnapshot`，mTLS 下只允许 edge 角色调用。
  - 只传数据：用 SEEK_DATA / SEEK_HOLE 跳过空洞，数据区里 64 KB 的全零块也不发，接收端保持稀疏；多个文件并行传。
  - 只读盘（镜像盘、agent 盘）按 ext4 UUID 识别内容：UUID 每次 mkfs 随机生成，而这些盘生成后不再修改。目标节点把它们缓存为 `peer-<id>.ext4`，之后再 fork 同一个 sandbox，或同一镜像盘上的其他 sandbox，就直接复用；随镜像盘缓存一起回收。
  - 同一节点上的多个副本共享一次拉取。拉取不跟随单个请求的取消，限时 5 分钟。
  - `CreateSnapshot` 生成的快照镜像要长期保存，仍然发布到镜像库。
- **结果**（源 VM 512 MB，内存里 100 MB 数据，镜像库在 NFS 上）：

  | 源节点排空后 fork 到另一节点 | 25.1 | 26.1 |
  |---|---|---|
  | 8 个副本（第一次，要拉镜像盘） | 1.47 s | 581 ms |
  | 32 个副本（镜像盘已缓存） | 1.55 s | 460 ms |
  | 目标 edge 读快照记录 | 1.06 s | 3 ms |

  - 第一次拉取（内存、可写盘和两块只读盘）用时 377 ms；同节点 fork 不受影响。

### 26.2 暂停的 sandbox 换节点恢复
- **触发条件**：
  - `ResumeSandbox` / `TouchSandbox` 时，sandbox 所在的 edge 正在排空，或者因为内存压力不能恢复（`no_capacity`）；
  - 运行时调用（exec 等）自动恢复时遇到 `no_capacity`，也会迁移。
  - 只有暂停中的 sandbox 会迁移，并且需要镜像库来记录临时快照。只支持能保留内存的后端：microvm，以及测试用的 sim。
- **过程**：
  1. apiserver 调原 edge 的 `BeginMove`。原 edge 在 sandbox 的操作锁内把暂停快照做成临时快照（只是硬链接暂停文件，再复制可写盘），并冻结这个 sandbox，其他调用都返回 `unavailable`。
  2. 选目标节点：排除原节点，优先缓存了该快照的节点。IAM 把同一个配额 lease 改绑到目标 edge；对已有的 lease 调用 Admit 只改绑定，不重复计费。
  3. 目标 edge 用同一个 id 创建（`move=true`，保留创建时间），从原 edge 拉取快照并恢复，然后调原 edge 的 `EndMove`。原 edge 随即删除这个 sandbox，但不释放 lease；之后 10 分钟内，对这个 id 的调用都会收到"已迁到某 edge"的回复。
  4. 失败时，apiserver 调 `EndMove` 撤销：sandbox 在原节点照旧暂停，lease 绑回原 edge。如果撤销时发现迁移其实已经完成（只是回复丢了），就按完成处理。被放弃的迁移，6 分钟后自动解除冻结。
- **id 不变**，id 里的 edge 是创建时的节点。路由方式：
  - edge 的状态里新增 `moved_in`，列出 id 指向别的 edge 的 sandbox，apiserver 据此路由；
  - 发起迁移的 apiserver 立刻知道新位置；其他 apiserver 去原 edge 会收到"已迁到 X"（`unavailable`，ErrorInfo 里带 `moved_to`），随即转到 X；不认识这个元数据的客户端，按 `unavailable` 重试即可；
  - 所有针对单个 sandbox 的调用都会跟随：生命周期、运行时、fork、快照、pack_diff；
  - `Sandbox.edge_id` 表示当前所在的节点。
- edge 重启后照常接管迁入的 sandbox：记录改为按 lease 校验，不再要求 id 前缀是本节点。
- **实测**（两节点，原节点排空后 resume）：

  | VM | 迁移用时 |
  |---|---|
  | 512 MB，/dev/shm 里 102 MB 数据 | 351 ms |
  | 4 GB，/dev/shm 里 819 MB 数据 | 1.1 s |

  - 迁移后内存数据校验一致，shell 会话的变量和主机名都不变。单机 e2e 中迁移用时 168 ms。
- **限制**：
  - 原节点宕机时无法迁移，因为暂停文件在原节点本地。要扛住节点故障，需要把暂停快照写到共享存储。
  - 任务级恢复（task resume）还不会迁移。
  - 迁移后网络连接会断开，和快照恢复时一样。
  - 迁移后 sandbox 的 `spec.snapshot` 指向迁移用的临时快照，与 fork 副本一致。
  - 每个文件用一个流传输，约 0.8–1 GB/s；更大的 VM 可以改为分段并行。

### 26.3 指标
- 每个服务新增 `-metrics ADDR` 参数，在 `/metrics` 输出 Prometheus 指标。这是一个独立的 HTTP 服务，不带 pprof。`opendsecctl cluster up` 也支持这个参数。
- **所有 gRPC 服务**：`opendsec_rpc_server_handled_total{service,method,reason}` 和 `opendsec_rpc_server_handling_seconds`。统计放在最外层，所以被认证拒绝的调用也会被计入。
- **edge**：
  - 创建：`opendsec_edge_create_seconds{backend,reason}`；
  - 后端的创建分阶段耗时：`opendsec_edge_create_phase_seconds{backend,phase}`，microVM 有 prepare、network、config、booted/restored、disks、vmm_boot；
  - 生命周期操作：`opendsec_edge_op_seconds{backend,op,reason}`，op 为 pause、resume、stop、snapshot；
  - 抓取时读取的状态：`opendsec_edge_sandboxes{backend,state}`、`opendsec_edge_capacity` / `opendsec_edge_allocated{resource}`、`opendsec_edge_mem_available_mb`、`opendsec_edge_disk_available_mb`、`opendsec_edge_draining`、`opendsec_edge_under_pressure{pressure}`、`opendsec_edge_moved_in`、`opendsec_edge_created_total`、`opendsec_edge_rejected_total`；
  - 快照传输：`opendsec_snapshot_transfer_seconds{kind=fetch|pull|publish}`，以及从 peer 收到的数据量 `opendsec_snapshot_transfer_bytes_total`；
  - `opendsec_host_mounts`：进程挂载表的条数（见 §25）。
- **apiserver**：`opendsec_apiserver_create_seconds{backend,reason}`、`opendsec_apiserver_placement_retries_total{reason}`、`opendsec_apiserver_fork_seconds{held}`、`opendsec_apiserver_move_seconds{reason}`。
- **IAM**：`opendsec_iam_leader`、`opendsec_iam_leases`。**watcher**：`opendsec_watcher_edges_healthy`、`opendsec_watcher_edges_unhealthy`、`opendsec_watcher_edges_draining`。
- 另外还有 Go 运行时（GC、goroutine）和进程（CPU、内存、fd）的标准指标。
- **测试**：e2e 检查迁移、RPC、edge 操作、容量、IAM 和 watcher 的指标都会输出。

## 27. 生产化（2026-10-16）

目标：集群可以在生产环境使用。具体指标：
- 任意一台机器宕机，集群仍可用；
- 升级和改配置时服务不中断；
- 状态有备份，可以恢复；
- 有监控和告警；
- 有运维手册。

部署方式为 systemd 裸机，见 `docs/OPERATIONS.md`，拓扑如下：
- 2 台 BM（edge 和全部集群级组件）+ 1 台小云主机（第 3 个 IAM 副本、第 3 个 watcher、监控）；
- 托管 NAS 作为镜像库；
- 私网 CLB 作为 API 入口。

### 27.1 健康检查与优雅下线
- `-metrics` 的 HTTP 服务新增两个路径：
  - `/healthz`：进程存活就返回 200；
  - `/readyz`：所有就绪检查都通过才返回 200，否则返回 503，正文是原因。
- 就绪检查由各组件注册（`metrics.SetReady`）：

  | 组件 | 就绪条件 |
  |---|---|
  | apiserver | 15 秒内收到过 IAM 的应答，并且拿到过 watcher 的快照 |
  | IAM 副本 | 已知当前的 Raft leader |
  | watcher | 最近完成过一轮探测 |
  | edge | 已接管原有 sandbox，并开始服务 |

- 新指标：
  - `opendsec_ready`：`/readyz` 的状态；
  - `opendsec_build_info{version}`：版本号，构建时由 Makefile 通过 `-ldflags` 写入；`opendsecctl version` 也会打印它；
  - `opendsec_tls_cert_expiry_timestamp_seconds{identity}`：本进程加载的证书和 CA 的到期时间。
- **优雅下线**：apiserver 收到 SIGTERM 后，按下面的顺序退出。
  1. `/readyz` 立刻失败。
  2. 继续服务 `-drain-delay`（默认 6 秒），让 CLB 的健康检查（间隔 2 秒 × 失败 2 次）把它摘掉。
  3. 再给进行中的调用最多 `-grace`（默认 30 秒）完成。
  4. 关闭剩余连接。这时 SDK 会重试，流式调用会续传。
- IAM 和 watcher 的客户端本来就会在多个副本之间轮询和重试，所以它们不设等待时间，只让 `/readyz` 失败。

### 27.2 IAM 备份恢复与成员变更
- **备份**：`opendsecctl iam backup -out FILE`。
  - 内容是 gzip 压缩的 JSON，包括 principal、项目、策略、配额、token（只有哈希）和安全版本号，格式标记为 `opendsec-iam-backup/1`。
  - 走流式 RPC：`OpenDsec.BackupIAM` → `IAM.Backup`。follower 收到时转发给 leader。
  - **不包含配额租约和锁** **[决定]**：它们描述的是运行中的 sandbox 和组件，恢复后由对账和选主重建；而且租约数量和 sandbox 数成正比，体积大。
- **恢复**：`opendsecctl iam restore FILE`。
  - 作为一条 Raft 命令 `restore` 执行：替换 principal、项目和 token。
  - 现有租约中，所属项目在备份里仍然存在的予以保留。
  - 安全版本号设为两者中较大的值加 1，使所有 apiserver 立即清空认证缓存。
  - 单机模式下照样写入状态文件。
- **成员变更**：
  - `opendsecctl iam members`：列出成员。
  - `opendsecctl iam member add <id> -raft-addr -iam-addr`：在 leader 上执行 `AddVoter`。
  - `opendsecctl iam member remove <id>`：在 leader 上执行 `RemoveServer`。
  - 新副本用 `opendsec-iam -join` 启动：没有 Raft 状态时不自举，等待被加入。
  - 新副本的 gRPC 地址作为 Raft 命令 `set_member` 写进状态机，所以没有更新配置的老副本也能把请求转发给新 leader。
- 以上操作只有对 root 项目持有 `project.admin` 的用户可以执行。apiserver 先做鉴权，IAM 在执行时再校验一次。
- **测试**：
  - 单元测试：单机模式下备份 → 在新 IAM 上恢复 → 重启后状态仍在；非管理员被拒绝；垃圾数据报 `invalid`。
  - e2e（3 副本，mTLS）：
    - 恢复后，备份之后才创建的项目和 principal 都消失，并且立刻无法认证；存活 sandbox 的配额仍在。
    - 一个 follower 宕机后，把它移除，在新地址上用 `-join` 启动副本 3：它在被加入前既不自举也不找 leader；加入后追上进度。
    - 再杀掉原 leader，新副本和剩下的老副本选出新 leader，创建继续成功。

### 27.3 配置与密钥
- 新增 `iam.admin_token_file`：集群配置里不再写 token 本身。只有 IAM 节点有这个文件；其他组件读不到时直接忽略。
- 每个节点只拿到 `ca.crt` 和本机组件的证书与私钥，CA 私钥只留在运维机。
- apiserver 以 root 运行，但只保留 `CAP_DAC_OVERRIDE` 和 `CAP_FOWNER` 两项 capability：它要删除 edge（root）在共享存储里创建的快照目录。其余 systemd 防护选项不变。
- 生产配置开启 `keep_sandboxes_on_exit` 和 `persist_state`：edge 重启或升级不影响 sandbox。

### 27.4 部署工具（`deploy/prod/opendsecops`）
- 在运维机上，根据 inventory（节点、IP、角色）通过 ssh 操作所有节点：
  - 打包版本：带 sha256 校验；
  - 签发证书，并按节点分发；
  - 首次安装；按依赖顺序启动；
  - 下发配置；
  - 滚动重启、升级和回滚；
  - 检查状态和版本；
  - 备份；
  - 安装监控。
- 节点上的目录布局：
  - `/opt/opendsec/releases/<版本>`，`/opt/opendsec/current` 指向当前版本；
  - `/usr/local/bin` 里的可执行文件是指向 `current` 的符号链接；
  - `agent_dir` 设为 `/opt/opendsec/current/agents`：已经在运行的 sandbox 挂载的是当时的真实目录，所以每个节点保留最近 3 个版本。
- **滚动顺序**：
  1. IAM，先 follower，leader 最后；
  2. watcher；
  3. apiserver；
  4. edge：每台 edge 不但要 `/readyz` 返回 200，还要在集群快照中恢复为 healthy。

  每一步都等上一步就绪才继续，超时就停止。
- **定时备份**：`opendsec-iam-backup.timer` 在每台 IAM 节点上每天备份一次，保留 14 天，并写一个 node_exporter 文本指标，供 `OpenDsecIAMBackupStale` 告警使用。
- **监控**：
  - `deploy/monitoring/alerts.yml` 包括：组件宕机或不就绪、IAM 没有 leader 或剩余副本不足、watcher 或 apiserver 降级、证书即将到期、备份过期、版本不一致、edge 不健康、创建错误率或延迟过高、内存或磁盘压力、容量不足、NAS 未挂载。
  - `opendsecops monitor` 在每个节点上安装 node_exporter，在监控节点上安装 Prometheus 和 Alertmanager，并根据 inventory 生成抓取配置。
  - 各告警的处理步骤写在 `docs/OPERATIONS.md` 里。
### 27.5 创建请求的幂等重试
- 问题：apiserver 重启、切主或连接中断时，SDK 的 `run_sandbox` 直接失败。如果简单地重试，在第一次请求其实已经成功的情况下会多创建一个 sandbox。
- 做法：
  - SDK 为每次创建生成一个随机的 `lease` 作为幂等键。遇到 `UNAVAILABLE` 时，在 `retry_timeout` 和整体 `timeout` 之内重试，重试的请求带上 `retry=true`。
  - apiserver 收到 `retry=true` 的请求时，先在所有健康的 edge 上并行查找 `<edge>.<lease>`。
    - 找到且属于同一个项目：再做一次只读的 Admit，确认调用方有创建权限，然后返回这个 sandbox。
    - 它已经结束：返回 `invalid`。
    - 没找到：照常创建。
  - 只有重试才需要这次查找，正常创建的路径不变。
- 限制：如果第一次请求所在的 apiserver 被强制关闭时，edge 上的创建还没有完成，重试可能会在另一个 edge 上再创建一个。优雅下线会等进行中的请求最多 30 秒完成，所以这种情况只会在强制杀进程时出现。
- 测试：pytest 覆盖了三种情况：用同一个 lease 重试，返回同一个 sandbox；重试一个从未到达的请求，正常创建；sandbox 已经结束后再重试，返回 `invalid`。

### 27.6 CA 轮换
- `ca.crt` 可以同时包含多个 CA。`LoadCA` 用其中第一个 CA 签发证书；所有组件都信任文件里的全部 CA。
- `opendsecops rotate-ca 1|2|3` 分三步轮换：
  1. 节点同时信任新旧两个 CA，组件证书不变；
  2. 用新 CA 重签全部组件证书；
  3. 移除旧 CA。

  每一步都包含一次下发配置和滚动重启。任何时刻，正在运行的两个组件之间都能通过证书校验，所以全程不停服。
- 新增 `opendsecctl pki ca`（只生成 CA），以及 `pki init -ca-days`（CA 有效期默认 10 年）。
- 组件证书的到期时间不会超过签发它的 CA：此前签发的证书有效期 825 天，但 CA 只有 1 年，CA 到期后这些证书就全部失效。

### 27.7 在三台机器上的验证（2026-10-16）
- **环境**：bm1、bm2（裸金属，edge + 集群级组件）和 ctl3（2 核 8G 云主机：iam-2、watcher-2、Prometheus、Alertmanager）。
  - 用 opendsecops 安装，从单机 IAM 迁移：把旧的状态文件包装成备份格式，再执行 `iam restore`。
  - 测试期间镜像库仍是 bm2 导出的 NFS，CLB 也还没有，客户端直接连两个 apiserver。
- **负载**：16 个并发 worker，每个循环执行「创建 → `python3 -c 'print(6*7)'` → 停止」，container 和 microVM 各占一半，使用 Python SDK。
- **结果**：

  | 场景 | 完整循环数 | 失败 |
  |---|---|---|
  | 基线，60 秒 | 2355 | 0 |
  | 滚动升级全部 10 个组件（第一版） | 6543 | 1960 |
  | 滚动升级，修复之后 | 5461 | 0 |
  | 故障注入（下文），260 秒 | 10140 | 0 |
  | CA 轮换三步，每步 75 秒 | 2227 / 2197 / 2231 | 0 |

  - 一次滚动升级大约 40 秒。
  - 循环耗时 p50 为 0.30 秒，p99 为 2.2 秒；container 的 p99 较高。
- **故障注入**：所有请求只经过 bm1 的 apiserver，依次执行：
  1. `kill -9` IAM leader；
  2. `kill -9` 客户端正在使用的 apiserver；
  3. `kill -9` edge e1；
  4. 停掉 ctl3 上的 IAM 和 watcher，40 秒；
  5. 停掉 bm2 上的全部服务，40 秒。

  结果：没有一次失败。最长的一次操作用了 49.5 秒：它的 sandbox 在 bm2 上，SDK 一直重试，等到 bm2 恢复后成功。
- **验证中发现并修复的问题**：
  1. 生产配置模板里写了 `zone: az1`，而 placement 只认 `onprem` 和 `cloud`，所以所有 edge 都被跳过。现在启动时会校验 zone 的取值。
  2. 第一台 edge 重启时连续拒绝创建，它的惩罚期不断被续上；第二台 edge 紧接着重启，两台同时被排除，所有创建都返回 `no_capacity`。现在惩罚改为软性的：只有在还有其他候选 edge 时才跳过被惩罚的 edge，否则仍然尝试它。
  3. SDK 的生命周期操作（stop、pause、resume 等）在 edge 重启期间不重试。现在遇到 `UNAVAILABLE` 时和运行时调用一样重试。
  4. edge 崩溃恢复时，接管失败的 sandbox（包括创建中被中断的，以及进程已经不在的）的记录被直接删除，客户端重试 stop 得到 `not_found`。现在这些 sandbox 按 FAILED 或 STOPPED 保留到保留期结束。重试的创建如果发现第一次尝试的结果是 FAILED，会用新的 lease 重新创建。
  5. 组件证书的有效期（825 天）超过了 CA（1 年）。现在签发时不会超过 CA 的到期时间；集群 CA 已经不停服轮换为 10 年有效期。
  6. opendsecops 自身的 bug：
     - `pipefail` 下，`curl | grep -q` 会被误判为失败；
     - 在 `while read` 循环里调用 ssh，会吃掉循环的输入；
     - `trap RETURN` 在函数返回后残留；
     - 新机器的 apt 软件包索引是空的；
     - Ubuntu 版 node_exporter 默认不统计 `/mnt` 下的文件系统；
     - 三台机器的主机名都是 `kernel`，备份文件从此改用 inventory 里的节点名命名。
- **尚未在真实环境验证**：托管 NAS、CLB（包括 `/readyz` 健康检查和 6 秒的摘除时间）、告警通知通道。这三项都要等对应的云资源开通之后才能测试。

### 27.8 上线准备（2026-10-16）
- **入口**：在 CLB 开通之前，由 SDK 直接连接多个 apiserver。
  - `OPENDSEC_ADDR` 写成 `ip:port,ip:port` 的形式时，SDK 使用 gRPC 的 `ipv4:` 目标和 `round_robin` 负载均衡：请求分散到所有在线的 apiserver，连接失败的会被自动跳过。
  - 证书按 `api.opendsec.internal` 校验。只有 apiserver 的证书带这个名字（`opendsecops certs` 签发），所以其他组件的证书冒充不了 apiserver。
  - 证书里还加入了两台 BM 的公网 IP，VPC 外的调用方也可以直连（需要在安全组里放行 7100）。
  - 验证（单个客户端，16 个并发）：期间优雅停止一个 apiserver 30 秒，4464 次循环 0 失败；分别 kill -9 两个 apiserver，2267 次循环 0 失败。
- **网络**：按要求默认可访问公网：`network.default_rules = {"*": true}`。实测 pypi、百度、github 和 `pip install` 都正常；云元数据地址（100.96.0.96、169.254.169.254）、VPC 内网地址和宿主机都不可达。container 和 microVM 都验证过。
- **租户**：项目 `root/prod`，配额 8000 个 sandbox。调用方 `prod-caller` 在 `root/prod` 上有创建和操作权限，在 `root` 上有 `layer.use`（可以使用镜像 `root/py:3.12`），token 有效期 90 天。在 `root` 下创建会被拒绝。
- **SDK 分发**：`opendsec` wheel（当前 0.10.0）。在全新的 venv 中安装后跑通了 `quickstart.py`：创建 microVM、执行 Python、写文件、`pip install` 访问公网、停止。调用方文档是 `docs/USER_GUIDE.md`。
  - 0.9.1：0.9.0 的桩代码由 grpcio-tools 1.84 生成，要求 grpcio>=1.84，而 VPC 内的 pip 源最高只有 1.81.1，装好后一导入就报错；依赖声明（grpcio>=1.60、protobuf>=5）也没有反映这个要求。改为用 grpcio-tools 1.73 生成（`gen.sh` 有说明），依赖写成 `grpcio>=1.73.1`、`protobuf>=6.31,<8`，并分别在「最低版本」和「镜像源最新版本」两套依赖上验证。
  - 接入包里另带 `test_features.py`（逐项功能测试）和 `load_test.py`（压测），调用方可以直接运行。
- **清理**：最早那次带负载升级（修复前）留下了 12 个 sandbox，原因是当时 stop 不会重试。它们的空闲计时在每次 edge 接管时重新开始，所以一直没有被回收，已手动停止。停止后配额用量与存活的 sandbox 数一致，没有泄漏网络命名空间、挂载或 VM 进程。
- **已知风险，等待云资源开通**：
  - 镜像库仍然是 bm2 导出的 NFS：bm2 宕机时，依赖镜像库的操作会失败，包括在没有缓存的节点上新建、pack 和 snapshot。
  - 告警还没有通知渠道。
  - CA 私钥只有 bm1 上的一份。

### 27.9 改名为 OpenDsec（2026-10-16）
- **范围**：项目整体改名，不保留旧名字。新名字在代码里统一写作 `opendsec`：Go 模块、协议包 `opendsec.v1`、程序 `opendsec-*` 和 `opendsecctl`、运维脚本 `opendsecops`、SDK 包 `opendsec`、环境变量 `OPENDSEC_*`、指标前缀 `opendsec_`、告警名 `OpenDsec*`、目录 `/opt/opendsec`、`/etc/opendsec`、`/var/lib/opendsec`、`/data/opendsec-state`、sandbox 内的 `/.opendsec`、cgroup `/opendsec`、nftables 表 `opendsec_*`、证书域名 `api.opendsec.internal`，客户机内核为 `6.1.167-opendsec`。
- **没有改的**：代码里的类型名（`DSecClient`、`DSecRunArgs`、`DSecError`、Go 的 `DSecServer` 等）、proto 服务名 `DSec`（完整路径为 `/opendsec.v1.DSec/<方法>`），以及 token 前缀 `dsk.`。论文标题里的 DSec 是论文中系统的名字，保持不变。
- **不兼容**：协议包名变了，0.9.x 的 SDK 连不上新集群，调用方必须换用 0.10.0 的接入包；新集群的 CA 也是新的。
- **兼容处理**：IAM 恢复同时接受新格式 `opendsec-iam-backup/1` 和改名前的 `dsec-iam-backup/1`，旧版本的备份可以直接恢复（测试 `TestRestoreLegacyFormat`）。
- **线上切换**（一次停机，约 1.5 分钟不可用）：
  1. 准备阶段不停机：新建运维目录（默认 `/root/opendsec-ops`），集群配置按同样规则改名；生成新 CA 和证书；打包新版本；把新内核分发到 edge 节点；镜像库挂到新挂载点 `/mnt/opendsec-images`。
  2. 用旧版本备份 IAM。
  3. 把旧 edge 的 `keep_sandboxes_on_exit` 改为 false，重启后再停止：edge 自己停掉全部 sandbox（包括 fncall 预热池），清理网络规则，并删除镜像库里的 in-use 标记。
  4. 停止并禁用所有旧服务，确认没有残留：进程、nftables 表、网卡、cgroup、挂载、in-use 标记。
  5. `opendsecops install all` 和 `start all`：全新的 IAM 集群完成引导，然后导入第 2 步的备份。项目、账号、权限和 token 原样保留，`prod-caller` 的 token 继续有效。
  6. `opendsecops monitor`。
- **顺带修复**：
  - `opendsecops certs`：新建 CA 时，`pki init` 已经签好了全部证书，apiserver 证书因此缺少 `lb_hosts` 里的名字。现在新建 CA 后会重签 apiserver 证书。
  - `opendsecops` 里的 `… | head -1`：在 `pipefail` 下会因 SIGPIPE 悄悄退出（`backup` 命令因此失败）。改用 `awk 'NR==1'`。
  - 镜像库的 NFS 挂载原来是手动挂的，没有写进 fstab，节点重启后不会恢复。新挂载点已写入 fstab（`_netdev`；bm2 是 NFS 服务端，额外加了 `x-systemd.requires=nfs-server.service`）。
  - 节点需要加载 `overlay` 和 `dm_snapshot` 两个内核模块，原来靠手动配置。现在由 `deploy/node/install.sh` 写入 `/etc/modules-load.d/opendsec.conf`。
- **验证**：
  - 单元测试和 e2e 全部通过，包括需要开关才运行的网络测试和跨文件系统快照测试；SDK 的 pytest 通过。
  - 切换后以 `prod-caller` 身份，用新接入包在全新的 venv 里运行：quickstart 通过；功能测试 6 项通过、1 项跳过（没有 `layer.publish` 权限）；压测 60 秒、16 并发，2330 次 0 失败。
  - 管理员身份跑完整功能测试 11 项全部通过，覆盖 container、microvm、fncall 和 fullvm。
  - 故障演练：在 180 秒、16 并发的压测中，依次 kill -9 IAM leader、apiserver@0 和 edge e1，6757 次 0 失败，最长 2.54 秒。
  - Prometheus 的 13 个采集目标全部正常，17 条告警规则已加载。
- **改名前的稳定性测试**：从 13:08 跑到 16:30，因为切换而提前结束。共完成 196,687 次循环，0 失败。

## 28. 集群管理 M1：节点代理与分批升级（设计，2026-10-16）

### 28.1 背景与目标
- **背景**：集群要扩到大量物理机。运行时这边已经能支持：
  - 未列在配置里的 edge 套用 `edge_template`，启动后向 watcher 注册（§16.2）；
  - 可以摘除节点（`DrainEdge`），暂停中的 sandbox 可以换节点（§26.2）。

  跟不上的是部署工具 `opendsecops`（§27.4）：
  - 从运维机逐台 SSH，串行执行，一台一台等就绪。一次升级的耗时与机器数成正比，任何一台卡住整个流程就停下；
  - 机器清单是手写的 `inventory`，加机器要改清单、签证书、推配置；
  - SSH 私钥、CA 私钥和管理员 token 都集中在运维机上；
  - 没有发布记录，也没有"这台机器应该是什么版本"的状态，只能现查。
- **M1 目标**：
  1. 每台机器常驻一个节点代理，由它在本机执行安装、切换版本、下发配置和重启。中心不再 SSH 到每台机器。
  2. 新增集群管理服务 fleet，保存期望状态：每台机器的角色、版本和配置，发布过的版本，进行中的升级。
  3. 分批升级：先升试点，再按故障域逐批放大，每批都过健康检查才继续；出问题自动停下，并回退出问题的那一批。
  4. 命令行 `opendsecctl fleet ...`，通过 apiserver 访问，由 IAM 鉴权，所有操作写审计日志。后续的 Web 界面（M3）调用同一套 API。
- **规模假设**：最多约 2000 台 edge 节点，分布在多个机房或可用区，控制面节点 3–7 台。设计不依赖这个上限，但心跳间隔、并发下载数等默认值按这个规模取。
- **M1 不做**（M2）：
  - 证书仍由运维机签发：加机器时用 `opendsecops add-node` 签好节点证书。
  - 管理员 token 仍由 opendsecops 下发。
  - 发布包只校验 sha256，不签名。

### 28.2 组件
```
 opendsecctl fleet / Web(M3)
          │  TLS + bearer token（IAM 鉴权，fleet.view / fleet.operate）
      apiserver ──转发──▶ opendsec-fleet（2–3 副本；只有持锁的 leader 干活）
                               │  期望状态 → IAM Raft（fleet 命名空间）
                               │  leader 锁 → IAM AcquireLock("fleet-controller")
                               │  读集群状态 → watcher 快照；可选 Prometheus
                               ▲  mTLS，身份 node/<name>
         ┌──────────┬──────────┴──────────┐
     nodeagent   nodeagent   …        nodeagent   （每台机器一个，root）
     systemctl / /opt/opendsec / /etc/opendsec
```
- **`opendsec-fleet@<id>`**：新组件，与 watcher 一样多副本运行。
  - 由持有 IAM 锁 `fleet-controller` 的副本担任 leader：接收心跳、运行升级控制器、读写期望状态。
  - 其他副本把请求转发给 leader；节点代理收到 `unavailable` 并附带 `leader` 地址时，直接改连 leader。
- **`opendsec-nodeagent`**：每台机器一个，以 root 运行（`Restart=always`）。只做本机操作，不做决策，所有动作都由 fleet 下发。
- **不放进 apiserver** **[决定]**：
  - apiserver 本身也要被升级，控制器放在里面就是自己升级自己；
  - fleet 不依赖 apiserver：apiserver 全挂时，fleet 仍能把 apiserver 回滚。这时运维人员可以用节点证书 `opendsecctl fleet -direct` 直连 fleet。
- **期望状态放进 IAM 的 Raft** **[决定]**：
  - IAM 本来就有 3 副本、备份恢复和成员变更工具；
  - fleet 的写入量很小：加机器、发布、升级每推进一步写一次。2000 台机器全部升级一遍，大约几千次写入；
  - fleet 副本因此本身不存状态，可以随便替换。
  - 心跳是软状态，**不写 Raft**：只保存在 leader 内存里（2000 台 × 每 10 秒 = 200 次/秒）。切主后，新 leader 在一个心跳周期内重建；重建完成前（2 个周期内听到 90% 以上节点）升级控制器暂停推进。

### 28.3 数据模型（存放在 IAM 的通用键值区）
- **存储方式** **[决定]**：IAM 状态机新增一个通用的键值区，IAM 不理解其中的内容，fleet 的数据模型全部由 fleet 自己定义。这样 IAM 不需要为 fleet 加任何业务逻辑。
  - 每个键带一个版本号（`rev`，即写入时的 Raft 日志序号），写入和删除都可以带"期望版本"，不一致就返回 `conflict`。fleet 靠这个做并发控制。
  - 新增 4 个接口：`KVGet`、`KVList`（按前缀列出）、`KVPut`、`KVDelete`。读请求也转发给 leader，读到的总是最新值；只有 `fleet` 身份能调用。
  - 限制：键最长 256 字节，单个值最大 256 KB，只允许 `fleet/` 前缀。
  - 布局：`fleet/node/<name>`、`fleet/release/<version>`、`fleet/config/<gen>`、`fleet/rollout/<id>`，每台机器的升级步骤单独存成 `fleet/step/<id>/<node>`。这样推进一台机器只改写一个小值，不用每次重写整个升级记录。
- **Node**：
  - `name`：`[a-z0-9-]{1,32}`，同时用作 edge id；
  - `addr`：私网地址；
  - `domain`：故障域，即机房、可用区或机架，用于分批。它与 placement 的 `zone`（onprem/cloud，§27.7）不是一回事；
  - `roles`：与 inventory 相同，`iam=<id> watcher=<id> apiserver=<n> edge monitor`；
  - `labels`：任意键值，用于选择节点；
  - `release`：期望版本；
  - `config_gen`：期望的配置代数；
  - `state`：`active | cordoned | retired`。cordoned 表示保持排空；retired 表示已下线，节点代理收到后停掉全部组件；
  - `pinned`：被回退的节点，后续升级跳过它，直到人工解除。
- **Release**：
  - `version`、`sha256`、`size`、`created_at`、`created_by`、`notes`；
  - 发布包本体不进 Raft，放在 fleet 副本的本地目录（§28.5）。
- **Config**：
  - `gen`：单调递增；
  - `cluster_json`：集群配置。里面不能有密钥（§27.3），fleet 写入前会检查 `service_token` 和 `admin_token` 是否为空；
  - `units`：systemd unit 文件，跟随版本走；
  - `created_by`、`diff_from`。
- **Rollout**：
  - `id`；
  - `target`：`{release?, config_gen?}`；
  - `selector`：角色、domain 和 labels；
  - `strategy`：§28.6；
  - `state`：`pending | running | paused | done | aborted | rolled_back`；
  - `steps`：每个节点一条 `{node, batch, phase, result, started, finished, from_release, from_gen}`；
  - `events`：最近 200 条。
- **备份恢复**：`iam backup` 一并包含键值区，备份格式升为 `opendsec-iam-backup/2`。
  - 恢复 `/2` 时，键值区整体替换为备份里的内容；
  - 恢复 `/1`（包括改名前的 `dsec-iam-backup/1`）时，键值区保持不变：旧备份里本来就没有这部分数据，不能因为恢复一个旧备份把 fleet 的状态清空。
- **成员同步**：集群配置里的 IAM 副本、watcher 副本和 apiserver 列表，由 fleet 按节点的 `roles` 生成，避免与节点表不一致。`edges` 列表留空，edge 全部通过 `edge_template` 加入。

### 28.4 节点代理
- **身份与连接**：
  - 节点证书身份为 `node/<name>`，放在 `/etc/opendsec/pki/node.{crt,key}`；
  - 心跳通过 gRPC 发往配置中的 fleet 地址列表（`round_robin`，跟随 leader 重定向）。
- **心跳**（默认每 10 秒；有变化时立即发）上报：
  - 代理版本、主机名、内核版本、uptime；
  - `/opt/opendsec/current` 指向的版本，以及本地已有的版本；
  - 本机配置代数；
  - 每个组件 unit 的 `ActiveState`，以及本机 `/readyz` 的结果和原因；
  - `/data` 和根盘的剩余空间；镜像库是否已挂载；
  - 正在执行或最近一次的操作结果。
- **心跳应答**带回期望状态：`release`、`config_gen`、`state`，以及最多一个待执行的操作。
- **操作**（带 `op_id`，可以重复下发，节点代理按 `op_id` 去重）：

  | 操作 | 内容 |
  |---|---|
  | `stage` | 下载版本到 `/opt/opendsec/releases/<ver>`，并校验 sha256。不切换，可以提前进行 |
  | `apply` | 依次执行：<br>1. 切换 `current`；<br>2. 写入 `/etc/opendsec/opendsec.json` 和 unit 文件；<br>3. 按顺序重启指定的 unit；<br>4. 等本机 `/readyz` 返回 200（超时默认 120 秒） |
  | `restart` | 只重启指定的 unit |
  | `stop` / `start` | 用于下线、维护 |

  `apply` 的细节：
  - 与 opendsecops 的 `ship`/`switch` 相同：`ln -sfn` 后再 `mv -T`，保留最近 3 个版本；
  - 配置先写成 `.new`，再用 rename 替换；
  - 失败时恢复原来的 `current` 和配置，再重启一次，并上报 `failed` 和原因。
- **安全边界**：
  - 节点代理只接受这几种操作，不执行任意命令；
  - unit 名限定在 `opendsec-*`；
  - 只写 `/opt/opendsec` 和 `/etc/opendsec` 下的固定文件；
  - fleet 被攻破后，最多能把节点切到某个已发布的版本，或者停掉 OpenDsec 的组件。
- **自身升级**：节点代理的二进制在发布包里。`apply` 发现新版本里有新的节点代理时，最后执行 `systemctl restart opendsec-nodeagent`，重启后上报新版本。
  - 节点代理升级失败时，由 systemd 的 `ExecStartPre` 检查发布包是否完整，不完整就回退到上一个版本。
- **离线行为**：连不上 fleet 时不做任何改动，组件照常运行。fleet 全挂不影响现有的 sandbox 服务。

### 28.5 发布包
- `opendsecctl fleet release push BIN_DIR [-notes]`：
  1. 打包为 tar.gz，并生成 SHA256SUMS，与 `opendsecops release` 相同；
  2. 通过 apiserver 上传到 fleet leader，leader 再复制到其他 fleet 副本；
  3. 全部副本落盘后，才在 Raft 里登记 Release。
  - 已登记的版本不可变：同一版本号、内容不同的包（leader 收到的推送和副本之间的复制都一样）返回 `conflict`，而且在替换磁盘上的包之前就拒绝，已存的包保持原样。否则磁盘上的包和登记的 sha256 对不上，节点代理会一直下载失败。
- **下载**：节点代理从任意持有该版本的 fleet 副本流式下载，断点续传。每个副本同时最多服务 64 个下载（可配置），超出时让节点代理稍后重试。
  - 发布包压缩后约 70 MB（二进制去掉符号表后约 55 MB，内核 11 MB，Firecracker 和 jailer 3 MB）。2000 台共约 140 GB，三个副本各有万兆网卡时大约 1–2 分钟可以下完，受网卡和交换机带宽限制。
  - 升级开始时先对全部目标节点下发 `stage`，切换时就不用再等下载。
- **清理**：保留最近 10 个版本，以及任何节点正在使用的版本。

### 28.6 分批升级
- **创建升级**：`opendsecctl fleet rollout create -release V [-config GEN] [-select role=edge,domain=az1] [策略参数]`。同一时间只允许一个升级处于 running 或 paused 状态。
- **顺序**：
  1. 先对全部目标节点并行下发 `stage`。
  2. **控制面逐个升级**：
     - IAM 副本：先升 follower，leader 最后，leader 从 `opendsec_iam_leader` 判断；
     - 然后是 watcher、apiserver、fleet 自己。fleet 升级自己时，先升 follower，最后让出锁再升。
     - 每升一个都等它的 `/readyz` 和集群层面的检查通过，与现有的 `roll` 一致。
     - 控制面只有几台，没有必要分批。
  3. **edge 分批升级**：
     - **试点**：`canary` 台（默认 1 台），升完后观察 `bake` 时间（默认 5 分钟）。
     - **后续批次**：每批 `batch` 台（默认目标数的 5%，至少 1 台，最多 100 台）。同一批里，每个故障域最多 `max_per_domain` 台（默认等于批大小的一半）。
     - 批次按故障域交错排列，同一时刻不会把一个机房的 edge 大量同时重启。
     - 批与批之间等待 `pause`（默认 60 秒）。
- **edge 的单台流程**：
  1. fleet 调 `Edge.Drain(true)`，placement 不再往这台放新的 sandbox。edge 需要接受 `fleet` 身份调用 Drain。
  2. 下发 `apply`。edge 以 `keep_sandboxes_on_exit` 和 `persist_state` 重启，原有的 sandbox 不受影响，由新进程接管（§27.3）。所以升级 edge 二进制**不需要迁走 sandbox**。
  3. 等两项检查都通过：本机 `/readyz` 返回 200，并且这台 edge 在 watcher 快照里是 healthy。
  4. 解除 drain。drain 只保存在 edge 内存里，重启后本来就会清掉；对 `state=cordoned` 的节点，fleet 会重新设回 drain。
- **每批的检查**（全部通过才进入下一批）：
  - 本批每台的操作结果都是 `ok`；
  - 集群整体：IAM 有 leader，所有 apiserver 和 watcher 都已就绪，healthy edge 的比例不低于升级开始时减去本批的数量；
  - 可选：配置 `prometheus_url` 后，在 `bake` 和 `pause` 期间检查若干条 PromQL，默认是创建错误率和 p99 延迟，也可以自己指定。超过阈值就算失败。
- **失败处理** **[决定]**：
  - 失败数超过 `max_failures`（默认 0）时，升级转为 `paused`；
  - 本批失败的节点自动回到 `from_release` 和 `from_gen`，并标记 `pinned`；
  - 已经成功的节点保持新版本；
  - 由人决定下一步：
    - `resume`：继续；
    - `abort`：停在当前位置，不再推进；
    - `rollback`：把所有已经升级的节点按相反顺序分批回到原版本，策略相同。
  - 不默认全量回滚：失败往往只是单台机器的问题，比如磁盘满了，这时全量回滚的代价远大于停下来。
- **人工控制**：`pause`、`resume`、`abort`、`rollback`、`status`（各批进度和失败原因）。
- **只改配置**：`-config GEN` 不带 `-release` 时，同样分批执行：写入新配置，再重启相关组件。
- **控制器切主**：步骤的进度在 Raft 里，新 leader 从未完成的那一步继续：
  - 已下发的 `op_id` 重新下发，节点代理按 `op_id` 去重，不会执行两次；
  - 已经切过版本、但结果没有记录的节点，按心跳上报的实际版本补记。

### 28.7 节点生命周期
- **加机器**：
  1. 在运维机上执行 `opendsecops add-node NAME ADDR DOMAIN ROLES`。它会：
     - 签发节点证书和组件证书；
     - 运行节点初始化脚本 `deploy/node/install.sh`；
     - 安装并启动节点代理。

     M1 仍需要这一次 SSH，M2 改为节点自己申请证书。
  2. 节点代理第一次上报时，fleet 里还没有这台机器，就登记为 `pending`。
  3. 运维人员执行 `opendsecctl fleet node accept NAME`，fleet 下发当前版本和配置，edge 启动后由 watcher 发现。
  - 是否改为不经确认、自动接受，留到 M2 有了证书申请再定。
- **维护**：
  - `node cordon NAME`：排空节点，保持 `cordoned`；
  - `node evacuate NAME`：在排空的基础上，等这台机器上的 sandbox 自然结束或到期，期间定时报告剩余数量；`-deadline` 到期后列出仍在运行的 sandbox，由人决定是否强制停止。
    - 主动把暂停中的 microVM 迁走（§26.2）留到 M2：现在的迁移只在恢复这个 sandbox 时才触发。
  - 维护完成后执行 `node uncordon NAME`。
- **下线**：`node retire NAME`：
  1. 先 evacuate；
  2. 再停止全部组件；
  3. 把节点状态设为 `retired`；
  4. watcher 按 `lost_edge_grace` 释放这台机器的配额。

  retire 本身不做 evacuate：节点代理收到 `retired` 会立刻停掉 edge，所以 fleet 对带 edge 的节点检查它已经 evacuate 过，否则拒绝：
  - 节点必须是 `cordoned`；
  - 直接问 edge（`Edge.Status`，不用 watcher 的快照，快照可能早于刚完成的创建）：edge 必须在排空，并且一个 sandbox 都没有；
  - watcher 不认为这个 edge 健康时数不了 sandbox：机器还在上报心跳就拒绝；已经不上报（机器没了）就允许下线。

  如果节点上有 IAM、watcher 或 apiserver 角色，必须先迁走这些角色（例如 IAM 先 `member remove`），否则 fleet 拒绝下线。

### 28.8 API 与权限
- **新增 proto `fleet.proto`**，包含两个服务：
  - `service Fleet`：fleet 内部使用。
    - 节点代理调用 `Heartbeat` 和 `FetchRelease`（流式）；
    - fleet 副本之间调用 `PutRelease`（流式），复制发布包。
  - `service FleetAdmin`：管理接口，包括 `ListNodes`、`GetNode`、`UpdateNode`（accept/cordon/uncordon/retire/pin/unpin）、`ImportNodes`、`ListReleases`、`PushRelease`（流式）、`PutConfig`、`GetConfig`、`CreateRollout`、`ControlRollout`、`ListRollouts`、`GetRollout`。
  - **同一份 `FleetAdmin` 定义有两个实现**：
    - fleet 上的是真正的实现，只接受 `apiserver` 和 `ops` 两种证书身份；
    - apiserver 在对外端口上注册一个代理：验证 bearer token、检查权限后，把请求连同操作者转发给 fleet。

    这样 proto 里不用再给 `service DSec` 重复写一遍这些方法。现有的审计拦截器作用于整个对外端口，所以这些调用自动进入审计日志。
  - `opendsecctl fleet -direct`：apiserver 全挂时，用运维机上的 `ops` 证书直连 fleet，操作者记为 `ops/<id>`。
- **新权限**（作用于 root 项目；集群管理员在 IAM 下次启动时自动获得）：
  - `fleet.view`：查看；
  - `fleet.operate`：加机器、维护、发布、升级。
  - `project.admin` 同时具有这两项。
  - 这样可以给运维人员单独授权，而不必给 IAM 管理员权限。
- **审计**：所有管理接口都写入现有的审计日志（§14.4），记录操作者、对象和参数；升级的每个事件也写入审计日志。
- **指标**：
  - `opendsec_fleet_nodes{state,domain}`；
  - `opendsec_fleet_node_release{release}`：各版本的节点数；
  - `opendsec_fleet_heartbeat_age_seconds`：最大值和分位数；
  - `opendsec_fleet_rollout_state`、`opendsec_fleet_rollout_progress`；
  - `opendsec_fleet_leader`。
- **新告警**：
  - `OpenDsecFleetNodeSilent`：节点超过 60 秒没有心跳；
  - `OpenDsecFleetNoLeader`；
  - `OpenDsecFleetRolloutPaused`：升级暂停超过 30 分钟；
  - `OpenDsecFleetDrift`：节点实际版本与期望版本不一致超过 10 分钟，且不在升级中。

### 28.9 与 opendsecops 的关系和迁移
- **opendsecops 保留**，用于：
  - 首次搭建集群：IAM 和 fleet 起来之前；
  - `add-node`（M1）；
  - 签发证书、轮换 CA；
  - 应急：fleet 不可用时，原来的 SSH 路径照常可用。

  它的 `upgrade` 和 `roll` 改为在 fleet 可用时提示改用 `opendsecctl fleet rollout`；`-force` 时仍可直接执行。
- **把现有集群迁到 fleet**（不停机）：
  1. 发布含 fleet 和节点代理的新版本：用 opendsecops 做最后一次滚动升级，同时启动 fleet 副本（ctl3 和 bm1）；
  2. `opendsecctl fleet import inventory`：把 inventory 导入成 Node 记录，把当前配置导入成配置代数 1；
  3. `opendsecops install-agent all`：签发节点证书，在每台机器上启动节点代理；
  4. 确认所有节点都在上报心跳，实际版本与期望版本一致；
  5. 之后的升级都改用 fleet。

### 28.10 测试计划
- **单元测试**：
  - 升级的分批算法：试点、批大小、故障域上限、交错排列、`pinned` 节点跳过；
  - 失败时暂停，并回退本批；`rollback` 按相反顺序；
  - 控制器切主后从中间继续：`op_id` 去重，按实际版本补记；
  - Raft 命令与备份：`/2` 格式包含 fleet，`/1` 格式仍可恢复；
  - 节点代理：`apply` 中途失败时恢复原版本和原配置；只接受白名单内的操作；按 `op_id` 去重。
- **e2e**（单机多进程，用 sim 后端模拟 50 个节点，每个节点一个节点代理，`systemctl` 换成假实现）：
  - 正常升级：控制面逐个升，edge 按批升，全部节点达到目标版本；
  - 注入失败：某个节点 `/readyz` 不就绪 → 升级暂停，该节点回退并 pinned；`resume` 后升完其余节点；
  - 升级进行中 kill fleet leader：新 leader 从中间继续，没有节点被执行两次；
  - fleet 全部停止：现有组件和 sandbox 不受影响，fleet 恢复后接着推进。
- **真机**（bm1、bm2、ctl3）：
  - 按 28.9 迁移；
  - 在 16 并发的压测下完成一次全量升级和一次回滚，要求 0 失败；
  - 对比 opendsecops 的耗时。
- **规模**：用 sim 节点代理压测心跳和下载，2000 个节点代理挂在一台机器上：
  - 心跳 p99 延迟；
  - fleet leader 的 CPU 和内存；
  - 2 个副本同时供 2000 台下载的总耗时。

### 28.11 已按默认确定（2026-10-16）
1. 规模按最多约 2000 台、多个机房设计。故障域是 Node 的 `domain` 字段，加机器时由运维填写，取值由运维自己约定（机房、可用区或机架都可以）。
2. 新机器接入时需要人工 `accept`。
3. Prometheus 检查默认关闭，配置了 `prometheus_url` 才启用。
4. fleet 副本与 IAM 一起放在控制面节点上：现在是 bm1、bm2 和 ctl3。

### 28.12 运行时依赖的版本管理（Firecracker、jailer、guest 内核）
- **问题**：
  - 线上的 `firecracker` 和 `jailer` 是 2026-10-15 手动放到 `/usr/local/bin` 的官方 v1.17.0，不在发布包里，也没有任何工具管理；guest 内核也是手动放到 `/data/opendsec-vm` 的。
  - 快照格式与 Firecracker 版本绑定：v1.15.1 是 9.0.0，v1.17.0 是 12.0.0，kvcache-ai fork 的 nestedvirt 分支是 1000.0.0。如果某台机器的 Firecracker 被单独升级或替换：
    - 它上面暂停中的 sandbox 可能无法恢复；
    - fork 和迁移在不同版本的节点之间可能失败。
- **参考**：AgentENV 在 `config/deps_manifest.toml` 里锁定 Firecracker、guest 内核和其他依赖的版本和下载地址，安装时校验 sha256，并把它们打进自己的安装包。我们采用同样的做法。
- **依赖清单 `deploy/deps.lock`**：每行一个依赖，格式为 `名称 版本 来源 sha256 安装路径`。
  - 来源：
    - `url:`：直接下载，比如官方 release 的 tgz，tgz 里取出的文件单独校验；
    - `file:`：本地构建的产物，比如 `deploy/guest-kernel/build.sh` 编出的内核，只校验 sha256。
  - `deploy/fetch-deps.sh OUT_DIR` 按清单下载或复制，逐个校验 sha256，任何一项不一致都直接失败。
- **打进发布包**：
  - `opendsecctl fleet release push` 和 `opendsecops release` 打包时，把这些依赖一并放进去：`firecracker` 和 `jailer` 放在 `bin/`，guest 内核放在 `vm/`；`deps.lock` 本身也放进发布包。
  - edge 配置里的路径指向 `/opt/opendsec/current/bin/firecracker`、`/opt/opendsec/current/vm/vmlinux-…`。
  - 升级 Firecracker 或内核，就是发一个新版本，走 §28.6 的分批升级，可以回滚。
  - 已经运行的 VM 继续用启动时的二进制，节点上保留了最近 3 个版本，不受影响。
- **版本可见、可检查**：
  - edge 启动时运行 `firecracker --version`，通过 `EdgeState.runtime_versions` 上报给 watcher（例如 `firecracker=1.17.0`），并导出指标 `opendsec_edge_runtime_info{component,version}`。
  - microVM 的快照记录（镜像库里的快照元数据和暂停文件）写入创建它的 Firecracker 版本。
  - 从快照创建（fork）或迁移时，placement 只选 Firecracker 版本相同的 edge；没有这样的 edge 时返回 `no_capacity`，并在错误里写明缺的是哪个版本，而不是去尝试恢复。没有记录版本的老快照不受限制。
- **kvcache-ai fork 的取舍**：
  - 现在继续使用官方 v1.17.0。fork 基于 v1.15.1：快照格式更旧，也缺少 1.16、1.17 的修复。其中官方 #6100 修复的问题是：裸暂停再恢复之后，从宿主机发起的 vsock 新连接会卡住。edge 重启接管暂停中的 VM 时正好走这条路径（`microvm/lifecycle.go` 的 adopt）。
  - fork 新增的内存接口（不导出内存的快照、guest 内存地址、脏页范围）是"暂停内存写到共享存储，原节点宕机也能迁移"的基础，留到做这个功能时再引入。届时有两种方式：等 fork 移植到 1.17 以上；或者把这 3 个补丁打到 1.17 上自己编译（`./tools/devtool build --release`），产物记进 `deps.lock`。
  - 预映射内存接口依赖宿主机内核的 `KVM_CAP_PRE_FAULT_MEMORY`，据我们所知要 6.10 以上，我们的宿主机是 6.8，暂时用不上。

### 28.13 M1 实现记录（2026-10-16）
- **代码**：
  - `internal/iam/kv.go`：键值区。条件写入用 `rev`，冲突返回新的错误原因 `conflict`（gRPC `Aborted`）。恢复 `/2` 格式的备份时，键值区的内容整体替换，并分配新的 `rev`，持有旧 `rev` 的写入一律冲突。
  - IAM 的 bootstrap 命令现在携带权限列表：滚动升级时新旧版本的副本混跑，各自按本机代码里的列表应用会导致状态不一致。
  - `proto/opendsec/v1/fleet.proto`，`internal/fleet`（存储、分批、控制器、发布包、管理接口），`internal/nodeagent`，`internal/release`（发布包的打包、校验、解压），`internal/apiserver/fleet.go`（`FleetAdmin` 代理），`cmd/opendsec-fleet`，`cmd/opendsec-nodeagent`，`cmd/opendsecctl/fleet.go`。
  - §28.12：microvm 后端探测 Firecracker 版本；`EdgeState.runtime_versions`；快照记录 `runtime`；placement 的 `Request.Runtime`。
  - `deploy/deps.lock`、`deploy/fetch-deps.sh`；`opendsec-fleet@.service`、`opendsec-nodeagent.service`；`opendsecops` 新增 `install-agent`、`add-node`、fleet 角色、节点和 ops 证书；告警 `OpenDsecFleet*`；`docs/OPERATIONS.md` §6。
  - Go 客户端（`pkg/client`）支持 `host:port,host:port`，与 Python SDK 一样按 `api.opendsec.internal` 校验证书。
  - `make build` 改为 `-ldflags "-s -w"`，二进制从 204 MB 降到 139 MB。
- **与设计的出入**：
  - 节点代理不从 `opendsec.json` 推导自己的服务列表，而是由心跳应答带回（fleet 知道每台机器的角色），这样导入的机器在第一次升级前就能报告各服务是否就绪。
  - 升级中每个服务的就绪超时由单步超时推出：`min(180 秒, 单步超时 / (2 × 服务数))`，给节点代理在单步超时之内恢复原版本留出时间。systemd 报告 `failed` 的服务立即判为失败。
  - 控制器的每一轮和改节点状态的管理操作（cordon 等）由一把锁串行：否则正在进行的一轮可能按旧状态把刚取消排空的 edge 又排空。
  - 回滚使用的策略里，试点和观察期都关掉：退回的是已经运行过的版本。
- **测试**：
  - 单元测试：键值区（条件写入、列出、删除、持久化、`/2` 和 `/1` 备份恢复、3 副本复制和快照）；分批（默认值、故障域上限、单一故障域不设上限、选择器）；发布包（打包、校验、解压，篡改文件和未列出的文件都被拒绝）；节点代理（apply 失败时恢复原版本、配置和单元文件；拒绝非 OpenDsec 的服务、白名单外的文件、sha256 不符的版本和未知操作）；placement 的版本过滤。
  - e2e `TestFleetRollouts`（2 个 fleet 副本、mTLS、10 台模拟机器、8 个 sim edge）。依次验证：
    1. 推送 3 个版本；内容不同的同名版本被拒绝；带密钥的配置被拒绝。
    2. 导入后同步到 v1，edge.env 正确写入。
    3. 升级到 v2：控制面 IAM leader 所在机器最后升；中途停掉 fleet leader，另一个副本接着完成；每台机器的每个服务在 v2 上只重启一次，没有重复执行。
    4. 升级到 v3：n03 失败，被自动退回 v2 并锁定，升级暂停；继续后其余机器升完。
    5. 回滚 v3：所有机器回到 v2。
    6. cordon 和 uncordon 正确地排空和恢复 edge。
    7. 节点代理不能替别的机器上报。

    在 bm1 上开 race 检测连续跑 4 轮，全部通过。
  - bm1 上完整的 `go test ./...` 通过。其中 `TestPmemImage` 有一次失败：它用宿主机的 MemAvailable 衡量内存，线上压测在跑时数值抖动大；随后新旧代码各跑 3 次，全部通过。
  - 在 bm1 上用真实依赖打包：`fetch-deps.sh` 取得的 firecracker 和 jailer 与线上 `/usr/local/bin` 下的逐字节一致，内核与两台 BM 上的一致；发布包 252 MB，压缩后 117 MB（当时尚未去掉符号表）。
- **尚未完成**：线上集群按 §28.9 迁移，以及迁移后真机上的一次全量升级和回滚。

## 29. 补齐论文差距（2026-10-17）
对照论文原文（arXiv:2609.22978）逐项核对后，按对我们负载的价值排序补齐：1 CPU 核心调度 → 5 网络规则按端口和协议 → 4 防作弊和越权 → 3 高可用镜像存储 → 2 microVM 镜像按需加载。主力后端用 microVM、nftables 加 DNS 代理、不用 3FS 等差异保留（理由见对话记录中的取舍表）。

### 29.1 CPU 核心调度（论文 §5.2、§8.5）
- **问题**：CPU 超卖 8 倍且开着 SMT（bm1、bm2 每核 2 线程）。BE 类只做了 SCHED_IDLE（cgroup `cpu.idle`），它只管同一个硬件线程上谁先跑，管不了同一物理核另一个超线程上的邻居抢执行单元和缓存。论文实测 SCHED_IDLE 单独用最多改善 3.4%。
- **做法**：每个 sandbox 一个核心调度 cookie（`prctl(PR_SCHED_CORE_CREATE)`，作用于整个线程组，随 fork、clone、exec 继承）。内核保证 cookie 不同的线程不会同时跑在同一物理核的两个超线程上；这同时挡住了 sandbox 之间经 SMT 的侧信道（L1TF、MDS 一类）。
  - 容器：sandbox 的初始化进程在创建任何子进程之前给自己建 cookie，aether、chronus 和所有命令都继承。
  - microVM、完整 VM：edge 启动 jailer 或 QEMU 后，给它的线程组建 cookie；之后的 vCPU 线程继承，暂停后恢复（新进程）重新建一个。
  - KVM 为每台 VM 建的内核线程（`kvm-nx-lpage-recovery`）也在 VM 的 cgroup 里，它没有 cookie，只意味着不和 sandbox 线程同核，无害。
- **配置**：后端 `core_sched`，不写时内核支持（`CONFIG_SCHED_CORE`）就开；写 `true` 而内核不支持，后端启动失败；`false` 关闭。
- **测试**：`TestCoreSched`（容器、microVM）：一个 sandbox 的所有线程（microVM 含 `fc_vcpu`）共享同一个非 0 cookie，不同 sandbox 不同，恢复后仍有；不开时为 0。
- **实测**（`TestCoreSchedQoS`，`OPENDSEC_BENCH=1`；bm1，384 线程；LS sandbox 32 线程反复跑固定计算并计时，4 个干扰 sandbox 占一定比例的硬件线程，各 15 秒；线上 e1 排空）。计算单元是 4 条独立的 xorshift 链加 1 MB 表随机查找：同一物理核另一个超线程忙时耗时 +84%。第一版只用一条依赖链，对 SMT 不敏感，四种情况都没有差别，结果作废。

  | 干扰负载 | 情况 | LS 平均 | 比单独跑 | LS p99 | 干扰吞吐（单元/秒） |
  |---|---|---|---|---|---|
  | — | LS 单独跑 | 682 µs | — | 957 µs | — |
  | 50% | 不保护 | 805 µs | +18.0% | 1349 µs | 257,000 |
  | 50% | SCHED_IDLE | 772 µs | +13.2% | 1311 µs | 250,083 |
  | 50% | SCHED_IDLE + 核心调度 | 696 µs | **+2.1%** | 878 µs | 273,210 |
  | 100% | 不保护 | 1236 µs | +81.0% | 4163 µs | 374,614 |
  | 100% | SCHED_IDLE | 1235 µs | +80.8% | 2153 µs | 376,734 |
  | 100% | SCHED_IDLE + 核心调度 | 751 µs | **+10.0%** | 872 µs | 465,891 |

  - 与论文同向（论文 50% 负载：不保护 +45.2%，SCHED_IDLE 至多改善 3.4%，加核心调度 +17.3%），核心调度的效果更好。
  - 预期的代价（被强制空闲的超线程）没有测出来，干扰负载的吞吐反而更高，原因没有查清。只测了容器；microVM 的 vCPU 线程同样带 cookie，但没有单独测延迟。

### 29.2 网络规则按端口和协议放行（论文 §6.5）
- **语法**：规则（键，或规则集里的一项）写成 `目标[:端口[/协议]]`。目标同 §20.1；端口是 `443` 或范围 `8000-8080`；协议 `tcp` 或 `udp`，不写时两者都放行。只支持 IPv4，所以第一个 `:` 就是目标的结尾。例：`pypi.org:443`、`10.0.0.0/8:5432/tcp`、`1.1.1.1:53/udp`、`*:443/tcp`。不带端口的规则行为不变（任意端口和协议，含 ICMP）。
- **实现**：同一个 sandbox 里端口和协议相同的规则归为一类，每类有自己的网段集合（`n<slot>p<k>`）和学到地址的集合（`a<slot>p<k>`）。sandbox 的链按顺序：不限端口的网段 → 各类的网段加协议和端口 → 丢弃私网 → 不限端口的学到地址 → 各类的学到地址加协议和端口 → 各类的 `"*"` 加协议和端口 → 不限端口的 `"*"` → 丢弃。
  - DNS 代理学到地址时，按域名分别放进覆盖它的那几类集合（`learnSets`）。
  - 规则变化后不再用的类，集合在同一次更新之后删除；sandbox 释放时一并删除。
- **测试**：`TestCompilePorts`（解析、分类、非法写法）；`TestPolicyPorts`（root、真实网络）：`example.com:443/tcp` 能连 443、连不上 80；`*:443/tcp` 能连任意公网地址的 443，连不上 80 和元数据地址；运行中改成 80 立即生效；改回不限端口后多余的集合删除；释放后不留集合。原有的 `TestPolicy` 同时通过。

### 29.3 防作弊和越权（论文 §6.4–6.5）
论文记录的事件逐条对照（AppArmor 那套在 microVM 里拦不住 guest 里的 root，所以换成「agent 用普通用户、评测用 root」的会话隔离，容器和 microVM 都适用）：

| 论文的事件 | 补齐前 | 现在 |
|---|---|---|
| 无限输出（`yes`）写满存储 | **容器的命令输出写在宿主机状态盘上，没有上限**，一个 sandbox 能写满整台机器；microVM 写在 guest 的 tmpfs 里 | 每条命令每路最多记录 64 MB，之后读出丢弃（`ExecResult.dropped_bytes`），命令不阻塞；每个会话最多保留 512 MB，超出删最早结束的命令的记录 |
| 伪造请求发给 chronus 的 socket | root 的命令能连其他会话的 socket | socket 0600；agent 会话用普通用户时连不上 |
| 读 chronus 的日志找答案 | root 能读其他会话的记录 | 记录目录 0700 属会话用户，输出文件只有 chronus（root）能写；普通用户看不到别的会话 |
| 覆盖 `/bin/bash` | root 能改 | 普通用户改不了系统文件 |
| XFS ioctl 破坏元数据 | sandbox 的可写盘是它自己的 ext4（microVM 是 guest 自己的文件系统），只坏它自己 | 同左 |
| 读 `/proc/kpagecgroup` 让内核崩溃 | 容器没有 `CAP_SYS_ADMIN` 读不了；microVM 崩的是 guest 内核 | 同左 |
| 扫端口、找镜像源 | 默认拒绝私网，按域名放行 | 加上按端口和协议放行（29.2） |
| 经 vsock 连 aether（microVM） | guest 内核没开 vsock loopback，guest 里的进程连不上 | 同左 |

- **输出上限**：命令的 stdout、stderr 不再由 shell 直接重定向到记录文件，而是写进命名管道，由 chronus 读出来记录（`record.go`）。命令结束后最多等 100 ms 让记录写完；它起的后台进程还开着输出时不等，之后写的照样记录，`GetOutput` 能取到。chronus 参数 `--max-output-mb`、`--session-output-mb` 可调。
  - 一台机器上很多 sandbox、很多会话合起来仍可能占不少空间；把容器的记录放进 sandbox 自己的可写盘（受 `disk_mb` 限制）更彻底，留作后续。
- **会话的用户**：`ExecRequest.user`（SDK `run_shell(..., user=)`，命令行 `exec -user`）在会话第一次启动时生效，可以是用户名或 `uid[:gid]`（镜像里不需要有这个用户，家目录是 `/tmp/home-<uid>`）。会话启动后用户固定，指定另一个用户返回 `invalid`，agent 不能借评测会话提权。文件读写类接口是调用方用的，仍由 chronus 以 root 执行。
- **调用方的责任**：评测要瞒着 agent 的东西要用严格的权限写（例如 `umask 077`）。平台不把 root 会话的 umask 改成 077：那样 root 用 pip 装的包，普通用户就 import 不了。测试时 microVM 的精简根文件系统里 `/root` 是 0755，用默认 umask 写的答案普通用户能读，就是这个原因。
- **测试**：chronus 单元测试 `TestOutputLimit`（64 KB 上限下写 1 MB 和无限的 `yes`）、`TestSessionRecords`、`TestOutputAfterCommand`（后台进程的输出：`Exec` 不等它，之后能取到）；容器和 microVM 的 `TestSessionUsers`：uid 1000 的会话读不到 root 会话的答案和记录，连不上 socket，改不了 `/usr/bin/bash`、`/bin/sh`，会话不能换用户。Python SDK 测试、e2e 都通过。

### 29.4 microVM 镜像盘：在镜像库里只做一次（论文 §5.3）
- **问题**：microVM 第一次在某台机器上用到某个镜像时，要把各层叠成 overlay、`mkfs.ext4 -d` 展平成镜像盘（§19.10）。每台机器、每个新镜像都做一遍，镜像越大越慢；论文 §4 指出 RL 任务的镜像种类多、每个镜像用得少，这个代价会被反复支付。
- **测量**（bm1，完整的 `python:3.12`：1.2 GB、7 层、3.3 万个文件，层放在 NFS 上，冷读）：

  | 做法 | 耗时 | 大小 |
  |---|---|---|
  | 现在：每台机器展平成 ext4 | 23.1 s | 1.31 GB |
  | 在镜像库里做一次 EROFS（不压缩） | 19.3 s | 1.05 GB |
  | 同上，lz4hc 压缩 | 33.7 s | 572 MB |
  | 从 NFS 顺序复制做好的 EROFS 到本地 | 0.97 s | — |

  按块按需读（OverlayBD、ublk，或者把共享存储上的文件直接给 VM）还能省下这 1 秒和本地的盘，但要改 microVM 的启动、快照和 fork 对镜像盘的处理；镜像到几十 GB、或者本地盘吃紧时再做。不压缩，是为了保留 virtio-pmem 的 DAX（压缩的 EROFS 不支持 DAX）。
- **做法**（后端配置 `erofs_images`，默认关闭）：
  - 镜像库 `vmdisks/<key>.erofs`：key 由层列表（自下而上）和格式版本算出，旁边的 `<key>.json` 记层列表（给 GC 用）。第一个用到的 edge 在独占锁文件 `<key>.lock` 下构建（各层叠成只读 overlay，`mkfs.erofs -b4096`，补齐到 2 MB 的整数倍），其他 edge 等它；锁超过 30 分钟视为构建者已死，接管。
  - edge 的本地缓存 `img-<key>.erofs`：从镜像库顺序复制一份，之后和 ext4 一样硬链接进 jail，快照、fork、pmem 不变。不在镜像库里的本地镜像就地做 EROFS。
  - guest 的 vminit 按超级块魔数识别 EROFS，否则按 ext4 挂（pmem 时用 `dax=always`）。快照去重按文件系统 UUID（`diskID`，ext4 和 EROFS 都支持）。
  - `opendsecctl image gc`：层被删的镜像盘一并删除。
  - 前提：guest 内核开启 EROFS（`deploy/guest-kernel/opendsec.config` 已加，新内核 `vmlinux-6.1.167-opendsec.2`），节点装有 `mkfs.erofs`（erofs-utils）。
- **端到端实测**（`TestErofsFirstUse`，`OPENDSEC_BENCH=1`；bm1，同一个镜像，NFS 冷读，512 MB VM）：

  | 情况 | 这台机器第一个 VM | 之后的 VM |
  |---|---|---|
  | ext4，每台机器展平 | 19.9 s | 0.11 s |
  | EROFS，全集群第一个 edge（构建） | 21.4 s | 0.11 s |
  | EROFS，其他 edge（复制） | **1.04 s** | 0.11 s |

- **测试**：`TestVMDisk`（并发只构建一次、失败不留残余、死锁接管、lowerdir 映射回层）、`TestVMDiskGC`；`TestErofsImages`（KVM）：第一个 edge 构建、第二个 edge 复制不重建、两层的叠加顺序、暂停后恢复、快照副本、pmem。新内核从 ext4 镜像启动的原有测试也都通过。
- 顺带：测量时测试状态目录设成了 `/data/zz-imgbench/state`，jail 里 `v.sock` 的路径超过 unix socket 的 108 字节上限，VM 连不上，看起来像起不来；`OPENDSEC_TEST_STATE` 要用短路径。

### 29.5 镜像库放在 NFS / 托管 NAS 上：不透明目录
- **问题**：overlay 用 xattr `trusted.overlay.opaque` 标记「不透明目录」（一层里删掉又重建的目录，要完全遮住下层同名目录），而 **NFS 不传 `trusted.*` xattr**。镜像库在 NFS 上（现在是 bm2 导出的 NFS 4.2，计划中的托管 NAS 也一样）时：
  - 导入：写这个 xattr 直接报错（`Operation not supported`），带不透明目录的镜像导入失败；
  - **`pack_diff` 和容器快照**：`cp -a` 复制不了 xattr 时**不报错**，标记悄悄丢失。用户在容器里删掉再重建的目录，打出来的镜像会把下层的旧内容带回来。线上正是这样：`TestPackDiffOpaque` 在 NFS 镜像库上不展开时，`/usr/share/doc` 里露出了 933 个条目（应只有 1 个）。
  - 线上现有镜像的层里没有不透明目录，没有已经出错的镜像。
- **做法**：不透明目录一律「展开」：这个目录（以及它里面的每个子目录）在下面各层叠加后能看到的每个名字，只要本层自己没有，就建一个 0:0 删除标记（字符设备，NFS 能存），并去掉 xattr（`opaque.go`）。
  - 导入：含不透明目录的层按它下面的层展开，层 id 改为 `opq-<hash(摘要, 下面的层)>`（同一个摘要叠在不同的层上，展开结果不同）；不含的层仍按摘要 `sha256-…` 共享。再次导入时两种 id 都先查，已有就不下载。
  - `pack_diff` 和容器快照：`PublishLayerDir` 复制后，按源目录（本地盘，xattr 还在）找出不透明目录，对 sandbox 的下层展开。
  - 合并层仍认旧的 xattr 标记（本地盘上的旧层）。
- **`opendsecctl image store-check -store DIR`**：不连集群，在 DIR 下的临时目录里逐项试镜像库需要的能力，必需项有一项失败就返回错误：读写和 fsync、root 建的文件属 root（没有 root squash）、chown、独占创建（EROFS 盘的构建锁）、文件和目录的原子 rename、硬链接、符号链接、0:0 字符设备、以这里的层为 lowerdir 挂 overlay 并正确处理删除标记；`trusted.*`、`user.*` xattr 只作提示。bm2 的 NFS 全部必需项通过（`trusted.*` 不支持）。
- **测试**：`TestPullConvertsWhiteoutsAndDedups`（导入的不透明目录展开为删除标记、`opq-` id、overlay 挂载后的视图、再次导入不下载）、`TestPublishExpandsOpaque`（嵌套目录）、`TestCheckStore`；`TestPackDiffOpaque`（容器，`OPENDSEC_TEST_STORE` 指向 NFS 时在真 NFS 上；去掉展开后它在 NFS 上失败）。

## 30. 开源准备：clone 下来就能部署（2026-10-17）

- **许可证和仓库**：
  - 采用 Apache-2.0，增加 `LICENSE`、`NOTICE`（写明与 DeepSeek 无关，发布包内附带的第三方组件）、`SECURITY.md`、`CONTRIBUTING.md`；
  - README 改为英文，中文版在 `README.zh-CN.md`；
  - Go module 改为 `github.com/kernflux/opendsec`，OWNER 是占位符，定下仓库地址后替换（docs/RELEASING.md）；
  - Python 包补上许可证信息和 README，`opendsec.egg-info` 不再进仓库。
- **去掉本环境的内容**：示例 inventory 和集群配置改成通用的示例集群（3 台管控节点，各故障域若干计算节点，私网 10.0.x.x）。OPERATIONS 和 USER_GUIDE 不再写具体机器和地址；原版留在运维目录的 `docs/` 下。SPEC 开头说明测量记录里 bm1、bm2、ctl3 指哪些机器。对外仓库从一个干净的初始提交开始，不带开发历史。
- **单机部署 `deploy/quickstart.sh`**：
  - 先检查机器（root、systemd、cgroup v2、内核版本、端口），然后构建、打包，并用 opendsecops 安装到本机；inventory 里 ssh 地址写 `local` 的节点不经 ssh。
  - 安装完成后，导入 `python:3.12`，建项目 `root/demo` 和它的调用方，再各跑一个容器 sandbox 和一个 microVM sandbox 做检查。
  - `--uninstall` 全部移除。
- **guest 内核**：`deps.lock` 改为 GitHub release 上的 `vmlinux-6.1.167-opendsec.2`（带 EROFS），发布包里的路径不变，现有配置不用改。`fetch-deps.sh` 增加两个变量：
  - `OPENDSEC_KERNEL=<文件>`：用自己编的内核。内核构建不能逐字节复现，发布包里的 deps.lock 记录这个文件的实际 sha256。
  - `OPENDSEC_DEPS_SKIP`：只跑容器的节点不带内核。
- **在全新 Ubuntu 24.04 上实测**（bm1 上的嵌套虚拟机，16 核 32G，`/dev/kvm` 可用）：
  - `quickstart.sh --build-kernel` 全程约 7 分钟，其中编内核约 3 分钟、拉镜像约 5 分钟；
  - 容器和 microVM 两种 sandbox 都跑通；
  - SDK 示例（含 pypi 网络规则）通过；
  - 重启后自动恢复；
  - `--no-microvm` 通过；不带内核参数时，脚本给出明确提示后退出。

  实测发现并修掉的问题：
  1. 节点缺 `mkfs.erofs`：`deploy/node/install.sh` 现在自动安装 edge 需要的软件包（erofs-utils、e2fsprogs、nftables、iproute2、util-linux）。
  2. `opendsecctl image import` 受 5 分钟总超时限制，237 MB 的层拉不完：改为 import 默认不设总时限，HTTP 单请求仍有 30 分钟上限；其他命令可以用 `-deadline` 调整。
  3. `edge_template` 的 zone 写错（例如 `local`）时，配置照样通过，结果所有创建都返回 no capacity：现在校验 template 的 zone。
  4. `opendsecctl -h` 的输出里带着 `$OPENDSEC_TOKEN` 的值（作为 -token 的默认值）：现在不显示。
  5. `opendsecctl exec <id> python3 -c ...` 把命令自己的 `-c` 当成 opendsecctl 的参数：现在 id 和命令名之后的参数原样交给命令。
  6. IAM 遇到示例配置里的占位 admin token（`change-me`）时拒绝启动。
- **CI**（`.github/workflows`）：
  - `ci.yml`：gofmt、vet、构建、`go test ./...`（普通用户运行，需要 root 或 KVM 的测试自动跳过）、Python SDK 测试；
  - `release.yml`：打 tag 后构建、打包发布包和 SDK wheel，并发布 GitHub release。
  - 两个工作流都在测试虚拟机里用普通用户按同样步骤跑过（Go 全部通过；Python 6 个通过、5 个跳过），还没有在 GitHub 上运行过。
- **按 README 从头部署多机集群**（bm1 上的 7 台嵌套虚拟机，组网用 QEMU 组播，地址与示例完全一致）：
  - 机器：ctl-1..3（4 核 8G）；node-a1、node-b1、node-c1（8 核 16G，带 KVM）；nas（NFS，加上 HAProxy 作为 10.0.0.10:7100 的负载均衡）。运维机是 ctl-1。
  - 按 README 依次执行：打包、写 inventory 和配置、签证书、安装、挂 NFS、`store-check`、启动、监控、交给 fleet、导入镜像、建调用方。14 个组件全部就绪。
  - SDK 经负载均衡跑通了容器和 microVM 示例，20 个 microVM 的批量创建分到各节点。
  - `add-node` + `fleet node accept` 加入了 node-c1。
  - 做了两次 fleet 升级，每次约 3 分钟，6 台机器全部完成。
  - 停掉一个 apiserver 时，由负载均衡切走，批量创建照常完成。

  发现并修掉的问题：
  1. **负载均衡的空闲超时切断安静的流**：HAProxy 默认 `timeout client 50s`，50 秒内没有数据的连接会被断开（日志标记 `cD`）。
     - 可续传的命令（run_shell）由 SDK 重连后续上；20 个 microVM 的批量创建流不能续传，直接失败。
     - 原因：Python SDK 不发 keepalive，服务端也不发。
     - 修复：所有 gRPC 服务端对空闲连接每 20 秒 ping 一次（`rpcutil.ServerPingInterval`）。用 fleet 升级上线后，没有再出现 `cD`；静默 70 秒的命令无需重连，批量创建 2.4 秒完成。
     - README 和 OPERATIONS 写明负载均衡的空闲超时不低于 30 秒。
  2. **第一个镜像登记后，node-a1 的 edge 约 52 秒读不到它的清单**：
     - 清单在 14:20:13 写入，edge 每秒一次的读取到 14:21:05 才成功。
     - edge 的读取就是 `os.ReadFile`，只缓存成功的结果，所以多半是 NFS 客户端缓存了「不存在」。示例配置里 node-a1 的 fncall 预热池在镜像导入前一直在查这个镜像。
     - 之后三种方式都没有复现：浅路径、深路径、真实挂载参数加 apiserver 写入。
     - 处理：推荐的挂载参数加上 `lookupcache=positive`。nfs(5) 规定这种模式下，「不存在」在使用前总会重新验证。
  3. README 的补充：
     - 新计算节点要先挂共享存储，再 `add-node`；
     - 节点上已有 `/etc/opendsec/pki/ca.crt`，不用另外拷 CA；
     - 节点安装第一次 `apt-get install` 失败时（新机器还没 `apt-get update`），不再打印报错，直接更新后重试。
  - 现有线上集群（bm1、bm2）的 fstab 还没有加 `lookupcache=positive`，要改需要重新挂载。

- **许可证合规**（2026-10-18）：发布包除了 OpenDsec 自己的代码，还有三类第三方软件，它们的许可证现在都放进发布包的 `licenses/`。
  - **Go 依赖**：编进程序的 31 个模块和 Go 标准库，许可证是 Apache-2.0、BSD、MIT 或 MPL-2.0。打包时由 `deploy/third-party-licenses.sh` 把它们原样复制进去，并生成索引。MPL-2.0 的模块（hashicorp/raft 等）没有改动，索引里注明了源码地址。CI 会检查每个依赖都有许可证文件，没有就失败。
  - **Firecracker 和 jailer**：Apache-2.0。它们官方发布包里的 `LICENSE`、`NOTICE`、`THIRD-PARTY` 写进 `deps.lock`，带 sha256 校验。
  - **guest 内核**：GPL-2.0 加 Linux-syscall-note。分发二进制要同时提供完整的对应源码，所以仓库里加了：
    - `deploy/guest-kernel/SOURCE.md`：源码来源（kernel.org 原版 6.1.167，未打补丁，sha256 `2818053c…`）、编译器、重新编译的方法；
    - `.2` 版本实际使用的 `.config`：取自编译目录，那里的 vmlinux 的 sha256 与发布的完全一致；
    - 三份许可证文本。

    `build.sh` 以后会把 `.config` 一起输出。内核 release 的附件改为 vmlinux 加上源码包、配置和构建脚本（docs/RELEASING.md）。
  - **SDK 的 wheel**：带上了 LICENSE，元数据里有 `License-Expression: Apache-2.0`。
  - 只跑容器、跳过内核时（`OPENDSEC_DEPS_SKIP=guest-kernel`），内核的许可证文件也一起跳过。
  - 在 bm1 上完整跑了一次 `opendsecops release`：`licenses/` 下 52 个文件都在 `SHA256SUMS` 里，校验通过。
- **开源前的全量测试**（2026-10-18，dev box，内核 7.0，以 root 运行）：`TestPackDiffOpaque` 和 `TestForkContainer` 失败，报错 `overlapping lowerdir path`。
  - 原因：开发用的 `host` 镜像把 `/` 当作 overlay 的下层；镜像库的层如果和 `/` 在同一个文件系统上，就位于 `/` 之内，形成重叠。新内核拒绝这种组合，6.8 还允许。
  - 正式镜像都来自镜像库，各层之间互不重叠，所以只影响 `host` 镜像。
  - 处理：两个测试改为不依赖这种重叠，`TestForkContainer` 的镜像库放到单独的 tmpfs 上；中文 README 的开发说明注明了这个限制。
  - 结果：单元测试 20 个包、e2e 全部通过。

## 31. 规模压测（2026-10-18）

- **环境**：在 bm1 上起一套独立的测试集群，和线上用一样的部署方式：多进程、mTLS 加 token、apiserver 开审计。
  - 组件：IAM 3 副本 Raft（数据在 NVMe 上），watcher 3 个，apiserver 4 个，模拟 edge 1000 个（分 10 个进程）。
  - 每个模拟 edge 的容量和线上机器一样：384 线程、1.5 TB、4000 个 sandbox。模拟的创建延迟中位数 100 ms，接近真机。
  - 整套集群加上压测客户端，都绑在 NUMA 节点 1 的 192 个线程上，端口和目录与线上隔开，测完已拆除。
  - 压测程序：`opendsecctl bench -target <apiserver 列表>`，每个 sandbox 0.5 核、256 MB。
- **创建吞吐**：
  - **集群级约 2.7 万个/秒**。并发 4096 和 8192 都停在这里，0 失败；p50 0.26 秒（其中 0.1 秒是模拟的创建延迟），p99 0.5 秒。
  - 并发更低时受并发数限制：1024 并发约 8700/s，2048 并发约 1.6 万/s。
  - 运行中的 sandbox 从 0 加到 115 万，吞吐没有下降。
  - 1000 个 edge 上的分布：最大/平均 1.02–1.07。
- **100 万个运行中的 sandbox 时**：
  - IAM：3 个副本的 lease 数一致；leader 内存 1.57 GB；Raft 快照 86–114 MB，`raft.db` 0.4–0.5 GB。
  - 其他组件：apiserver 4 个共 0.8 GB，watcher 3 个共 0.8 GB。
  - 集群快照 200 KB，取一次 7–10 ms。
  - 对账：每 30 秒一轮，每个 edge（约 1000 条 lease）平均 0.84 ms，一轮总共不到 1 秒。
- **IAM 故障切换**（110 万条 lease，压测进行中停掉 leader）：1.2 秒选出新 leader，15 万个创建 0 失败，最长 1.8 秒。旧 leader 重新启动后，9.5 秒追上（加载快照再补日志）。
- **按任务停止**：20 万个 sandbox，`ApplyTaskAction` 约 0.3 秒返回。
- **发现的问题：大批量停止产生 Release 风暴**。一次停掉 115 万个时：
  - **创建被卡住**：新建速率从 3600/s 掉到 0，持续约 45 秒；最长一次创建等了 47.6 秒，最终全部成功。
  - **配额暂时不准**：73 秒后 IAM 里还有约 61 万条 lease 没有释放，约 2 分钟后才由对账全部清掉。
  - **原因**（`internal/edge/service.go` 的 `IAMReleaser`）：
    - 每停一个 sandbox，edge 就单独起一个 goroutine 调 `Release`，每次都是一个 Raft 提交；
    - 调用超时 2 秒，最多重试 3 次。超时的那次提交其实已经进了 Raft 队列，所以每次重试都会多加一个提交，风暴最多被放大 3 倍；
    - 3 次都失败的就成了残留 lease，而失败只记在 debug 日志里。
  - **修复**（同日）：
    - IAM 新增 `ReleaseLeases`：一次释放一批 lease，整批只占一个 Raft 提交；每批最多 10000 条，重复释放是安全的。
    - edge 的 `IAMReleaser` 改为攒批：要释放的 lease 先进队列，满 1000 条或等 50 ms 发一批，同一时间只有一批在途。失败的批次放回队列，退避后重试，并打 warn 日志。遇到没有 `ReleaseLeases` 的旧版 IAM，退回逐条释放，每分钟再试一次批量。
      - 不能一直逐条：fleet 按机器滚动升级，IAM leader 所在的机器排在最后，同机器上的 edge 早于 leader 升级。第一次线上发版（0.11.0-202610181114）时两台 edge 都因此停在逐条释放，于是加了定期重试。
    - 单元测试：`TestReleaseLeases`、`TestIAMReleaserBatches`、`TestIAMReleaserRetries`、`TestIAMReleaserOlderIAM`、`TestIAMReleaserIAMUpgraded`。
  - **修复后用同样的环境重测**：灌到 115 万个，在探测压测（512 并发）进行中一次停掉全部。

    | | 修复前 | 修复后 |
    |---|---|---|
    | 配额全部归还 | 73 秒后还剩 61 万条，靠对账约 2 分钟才清完 | 约 2.3 秒 |
    | 停止期间的新建速率 | 掉到 0，持续约 45 秒 | 一直在 3300–4300/s |
    | 停止期间新建的 p99 / 最长 | — / 47.6 秒 | 0.64 秒 / 1.39 秒，0 失败 |
    | IAM 收到的释放调用 | 约 115 万次，重试最多再放大 3 倍 | 约 2200 次批量调用 |

    结束时 lease 数正好等于还在运行的 8 万个，没有残留。

## 32. 单机真实密度测试（2026-10-19）

- **环境**：
  - 在 bm1 上另起一套测试集群：IAM、watcher、apiserver 各 1 个，真实 edge `d1` 1 个，用线上已部署的 0.11 二进制、guest 内核和 agent。
  - 镜像库复制到本地 ext4，所以镜像读取比线上的 NFS 乐观。
  - edge 和它的 sandbox 都限制在 NUMA 节点 1：192 个线程，capacity 192 核、740 GB。
  - 测试期间 bm1 在 fleet 里 cordon，线上流量全部在 bm2 上。线上调用方压测全程运行，0 失败。
  - 加量脚本每步结束后，抽 5 个 sandbox 执行 `python3 -c "print(6*7)"`，全部通过。
- **容器**（0.1 核、128 MB、带网络）：
  - 加到 5781 个，停在内存容量上（740000 MB ÷ 128 MB），没有其他失败。
  - 创建速度随数量下降：

    | 已有 sandbox | 0 | 1000 | 2000 | 3000 | 4000 | 5000 |
    |---|---|---|---|---|---|---|
    | 每秒创建 | 46 | 26 | 18 | 11 | 9 | 7 |
    | 单个创建 p50 | 1.3 秒 | 2.4 秒 | 3.6 秒 | 5.5 秒 | 7.1 秒 | 8.7 秒 |

  - 内存：主机上每个容器约 15.6 MB，其中约 12.5 MB 计在容器的 cgroup 里。
  - 停止 5500 个容器用了 160–194 秒。
- **microVM**（0.25 核、128 MB、带网络，pmem、free page reporting、EROFS 都开）：
  - 加到 3548 个，停在内存容量上：准入按每个约 209 MB 计算（guest 内存加上 VMM 开销），而实际每个只占约 69 MB。
  - 创建速度：0 个时每秒 113 个，3000 个时每秒 34 个；p50 从 0.5 秒升到 1.8 秒。
  - 停止 3548 个用了 34 秒。
- **发现并修复的问题**：
  - **edge 每个 sandbox 占一个 OS 线程**：
    - 原因：`exec.Cmd.Wait` 阻塞在 `waitid` 系统调用里，edge 对每个容器、netns holder、Firecracker 和 QEMU 进程都在等。
    - 后果：5781 个容器时 edge 有 5817 个线程。Go 运行时超过 10000 个线程会直接结束程序；线上 e1 的容器上限是 8000 个，再加上 fncall、microVM 和 fullvm，可以碰到这个上限。
    - 修复：新增 `linuxrt.WaitCmd`，用 pidfd 在 Go 的 netpoller 里等进程退出（`waitid` 加 `WNOHANG|WNOWAIT`），退出后才调用 `cmd.Wait`。
    - 效果：5000 个容器时 edge 只有 38 个线程。
    - 测试：`TestWaitCmdThreads`（同时等 300 个进程，线程数不随之增长；换回 `cmd.Wait` 时测试失败）、`TestWaitCmdStatus`。
  - **网络策略每次变更都要列出整张 nft 表**：
    - 原因：`dropLimitedSets` 在全局锁里通过 netlink 拉出所有集合，代价是 O(sandbox 数)。
    - 修复：第一次用到时建一个 slot 到端口受限集合数量的索引，之后按索引维护。旧 edge 进程留下的集合在建索引时也能找到。
    - 效果（`TestSlotScale`，5000 个 sandbox）：新建一个从 60 ms 降到 2.8 ms，删除一个从 58 ms 降到 2.0 ms，清理 4900 个从 122 秒降到 6.8 秒。
    - 测试：新增 `TestParseLimitedSet`；`TestPolicyPorts` 覆盖了集合的回收。
- **找到但还没解决：容器创建变慢的主因在内核**：
  - 创建时的 goroutine 采样：57% 的时间在等 sandbox 里的 aether 起来。
  - 内核栈采样：容器 init 卡在 `pivot_root` 和 overlay 挂载的 `do_lock_mount` 上。
  - `pivot_root` 调用 `chroot_fs_refs`，遍历整台主机的全部线程，期间持有全局挂载锁，所以所有容器的创建都排成一队。
  - bpftrace 实测，5000 个容器时：单次 `pivot_root` 8 ms 到 1 秒，多数在 64–256 ms；25 秒内累计 30 秒，基本串行。
  - 线程从哪来：每个容器有两个 aether 进程（PID 1 加服务进程），每个 6–8 个线程，5500 个容器共约 7.4 万个线程。
  - 修复网络集合之后，容器的创建和停止速度没有变化，edge 自己的代码不是瓶颈。microVM 没有这个问题：jailer 也调用 `pivot_root`，但每个 VM 在主机上的线程少得多。
  - 可选的方向（未做）：
    - 把 aether 的 PID 1 和服务进程合并成一个进程，主机线程约减半；
    - 预热池（fncall 后端的 `warm_pool`）让请求不必等 `pivot_root`，但补充预热池的吞吐不变；
    - 不用 `pivot_root`、改用 `MS_MOVE` 加 `chroot`，不可取：容器保留了 `CAP_SYS_CHROOT`，可以逃逸到宿主机的文件系统。
- **其他观察**：
  - 停掉的容器留下大量「dying」cgroup：测试结束时有 4591 个，占着约 18–25 GB percpu 和约 50 GB 不可回收的 slab，主机空载时的内存占用从 34 GB 升到 94 GB。内核会在内存紧张时回收这部分。
  - 停掉 600 个容器后立刻再建 600 个，有 66 个因为 `no_capacity` 被拒，容量释放有延迟，原因未查。
  - 内存准入按申请值计算：容器实际占用约是申请值的 12%，microVM 约 33%。按实际占用，同一台机器可以放得更多（`mem_overcommit`）。

## 33. 故障注入、稳定性测试和 SLO（2026-10-19）

### 33.1 故障注入
- **环境**：线上集群（bm1、bm2、ctl3），版本 0.11.0-202610190417，由 fleet 管理。
- **负载**：bm1 和 bm2 上各跑一个 `soak.py`（6 个并发），以 `prod-caller` 身份经两个 apiserver 访问。每个调用方的负载组成：
  - 3 个 worker 跑短循环：创建 → 执行 → 写 64 KB 再读回 → 停止，container 和 microvm 轮流；
  - 1 个 worker 跑长期 sandbox：保持约 10 分钟，每 5 秒执行一次；
  - 1 个 worker 跑 microvm 的 pause/resume；
  - 1 个 worker 跑 fork：microvm fork 出 2 个副本，检查副本里的文件。
- **做法**：脚本在 bm1 上依次注入下表的故障，每个场景结束后等所有组件的 `/readyz` 恢复，再观察 60 秒。
  - 断网和 NFS 中断用 nftables 实现，ssh 不拦，并由 systemd 定时器保证自动恢复；
  - 进程崩溃用 `systemctl kill --kill-whom=main -s SIGKILL`；
  - 进程卡死用 `SIGSTOP`。
- **结果**：失败按失败操作实际发生的时间归到对应场景。

  | 场景 | 恢复就绪 | 调用方失败 | 说明 |
  |---|---|---|---|
  | 基线 2 分钟 | — | 0 | 1732 个循环 |
  | IAM leader 崩溃 | 2 秒内选出新 leader | 0 | 创建最长 3.2 秒 |
  | apiserver 崩溃 | 2 秒 | 0 | |
  | edge e1 崩溃 | 2 秒 | 1 | fork 的流断开，SDK 不重试 fork（已修复，见下文） |
  | edge e2 卡死 30 秒 | 恢复后立即 | 0 | 落到 e2 的创建等了约 30 秒 |
  | fleet 和 nodeagent 全部崩溃 | 3 秒 | 0 | 不影响数据面 |
  | 镜像库 NFS 中断 60 秒 | 恢复后立即 | 1 | 创建全部卡住，最长 94 秒，恢复后都成功；一个运行中容器里的命令卡了 88 秒，超时后输出为空 |
  | ctl3 断网 60 秒（当时它不是 leader） | 1 秒 | 0 | |
  | bm2 断网 60 秒（e2、iam-1、apiserver-1、NFS 服务端；当时 IAM leader 在 bm2） | 2 秒；leader 转到 bm1 | bm1 上的调用方 3 个，bm2 上的调用方 4 个 | bm1 上调用方的失败都是对 e2 上 sandbox 的操作，调用一直挂到超时（90 秒），新建不受影响，最长 12 秒。bm2 上的调用方处在被隔离的一侧，多出的 1 个是 fork 的副本报 `iam: no leader elected` |
  | IAM 失去多数派 30 秒（SIGSTOP 2 个副本） | 1 秒 | 0 | 创建等了最长 31 秒，SDK 的重试兜住了 |

  - 整个负载跑了 40 分钟，两个调用方共完成 29515 个循环，失败 9 个，成功率 99.970%。
  - 结束时 bm1 的调用方还剩 1 个 sandbox 在运行，由 `stop_task` 清理。最可能的来源是那次流断开的 fork：副本已经建好，但调用方没有拿到它们的 id。按 `request_id` 重试可以避免这种情况。
  - 每个故障结束后，所有组件都在 3 秒内重新就绪。
- **发现的问题和处理**：
  1. **fork 和批量创建在流断开时直接失败**：
     - 原因：SDK 不重试这两个调用，因为重试可能创建出多余的副本。
     - 修复：`ForkSandboxRequest` 和 `CreateSandboxesRequest` 新增 `request_id` 和 `retry`。第 i 个副本的 lease 由 `request_id` 加 3 位 base32 序号构成（`ids.ItemLease`）。
     - 重试时，apiserver 先到各 edge 上按 lease 找出前一次已经建好的 sandbox，原样返回，只创建缺的那些。前一次建的已经失败或已停止的，换一个新 lease 重建。如果全部副本都已存在，fork 的重试不会再给源 sandbox 做快照。
     - SDK 的 `fork()` 和 `run_sandboxes()` 遇到 `UNAVAILABLE` 时带着同一个 `request_id` 重试。
     - 测试：`TestBatchRetry`、`TestItemLease`，以及 SDK 的 `test_batch_retry_same_request_id`。
  2. **对端无声消失时，调用一直挂到超时**：
     - 原因：内部连接的客户端 keepalive 是 30 秒加默认的 20 秒超时，Python SDK 没有客户端 keepalive，断网期间连接上的调用要等到调用超时或 TCP 超时。
     - 修复：内部连接、Go 客户端和 Python SDK 都改为每 10 秒 ping 一次，5 秒没有回应就断开，大约 15 秒内发现对端消失，之后的调用转到其他 apiserver。
     - 对断网 edge 上 sandbox 的操作，在断网期间本来就无法完成，这一项缩短的是失败和恢复的时间。
  3. **镜像库中断会卡住运行中的容器**：
     - 原因：容器的只读层（overlay 的 lowerdir）直接挂在 NFS 上的 `/mnt/opendsec-images/layers/...`。microVM 用本地缓存的 EROFS 镜像，不受影响。
     - OPERATIONS §5 原来写的是「容器使用本地的 overlay，不受影响」，已更正。
     - 修复：容器层在节点本地缓存一份（`layercache.go`，后端配置 `layer_cache`，默认开启），和 microVM 的镜像盘一样。
       - 每一层第一次使用时整层复制到 `<state_dir>/<edge>/layers/<层 id>`，先复制到临时目录，完成后再改名；并发请求共用一次复制。
       - 复制由 Go 实现（`copyTree`），保留内容、属主、权限（含 setuid）、时间、硬链接、符号链接和设备节点，不复制 ACL 和 xattr。不用 `cp -a`，是因为它会把 NFS 上的 NFSv4 ACL 也复制过来，本地 ext4 不接受，在线上镜像库上实测报「preserving permissions: Operation not supported」。
       - 在线上 NFS 镜像库里 python:3.12 的 4 层上验证（`TestCopyTreeReal`，只读镜像库）：每个条目的类型、属主、权限、大小、时间、链接目标、设备号和内容都一致；最大的一层 3271 个条目，1.35 秒。4 层并行复制，一个节点第一次用这个镜像时多花大约 1.4 秒。
       - overlay 的 lowerdir 改用本地副本；`pack_diff` 和快照读下层时也优先用本地副本。
       - 镜像库里的层没有 overlay xattr（不透明目录已展开成删除标记，§29.5），所以普通复制就能保留全部语义。
       - 清理：扫描该 edge 所有容器后端的 sandbox 的 `image.json`，没有 sandbox 用、6 小时没用过的副本删除。所以 container 和 fncall 共用缓存时，一方不会删掉另一方在用的层。
       - 测试：`TestLayerCacheCopy`（属主、权限、setuid、硬链接、符号链接、删除标记，只复制一次，清理规则）、`TestLayerCacheSandbox`（从快照启动的 sandbox 挂载的是本地副本）、`TestCopyTreeReal`（上面的真实数据）。
     - 新建仍要读镜像库（清单、还没缓存的层），镜像库中断期间新建会等待。这一点要靠镜像库本身高可用（托管 NAS）。
  4. **卡死的 edge 拖住创建**：placement 仍然把创建发给卡死的 e2，这些创建要等到 e2 恢复（约 30 秒）才完成。
     - 由第 2 项的 keepalive 一起解决：卡死的进程不回应 HTTP/2 PING，apiserver 约 15 秒后断开到它的连接。进行中的创建得到 `unavailable`，placement 本来就会对此惩罚这个 edge、换下一个 edge 重试。之前卡死超过约 50 秒才会断开。
     - 测试：`TestDialDetectsSilentPeer`，一个转发到一半就把两个方向的包都丢掉的 TCP 代理，进行中的调用 15 秒后以 `unavailable` 结束。
     - 已知的遗留（已在 §36 修复）：卡死的 edge 恢复后，可能把那次已被放弃的创建做完，留下一个孤儿 sandbox。它的 lease 已经绑到别的 edge，watcher 对账时只记为 conflict，不会清理；这个 sandbox 不计配额，到空闲 TTL（默认 1 小时）后被回收。这个问题以前也存在：任何发出后超时、改到别的 edge 重试的创建都可能留下孤儿。要修，需要 watcher 停掉 lease 绑在别处的 sandbox，并先确认暂停 sandbox 迁移时的 lease 绑定规则。

### 33.2 稳定性测试（48 小时）
- **时间**：2026-10-19 15:35 到 10-21 15:35，线上版本 0.11.0-202610190712。
- **负载**：bm1 和 bm2 上各跑一个 `soak.py`，各 6 个并发，组成同 §33.1。bm1 用 0.11 SDK，bm2 用调用方现在手上的 0.10 SDK。
- **采样**：每分钟在三台机器上记录：
  - 内存、percpu、不可回收 slab、dying cgroup、线程总数、挂载、netns、nft 表、D 状态进程、磁盘用量；
  - 每个组件的 RSS、线程、fd、cgroup 内存、goroutine、heap。
- **结果**：

  | | bm1 调用方 | bm2 调用方 |
  |---|---|---|
  | 完整循环 | 1,187,728 | 1,183,384 |
  | 失败 | 3 | 2 |
  | 创建 p50 / p99 / 最大 | 0.15 / 1.81 / 5.23 秒 | 0.15 / 1.82 / 5.27 秒 |
  | 结束时遗留的 sandbox | 0 | 0 |

  - 两边合计 237 万个循环，失败 5 个，成功率 99.9998%。其中：
    - container 和 microvm 的短循环各约 105 万个，0 失败；
    - pause/resume 5.8 万次，0 失败；
    - 长期 sandbox 578 个，每个保持约 15 分钟、每 5 秒执行一次，0 失败；
    - fork 21.9 万次，失败 5 次。
  - 按小时统计，创建 p99 在 1.78–1.88 秒之间，48 小时里没有变慢的趋势。
- **5 个失败**：都是 fork 的副本报 `no_capacity: no edge can host ...`，但两台 edge 都没有因为容量不足拒绝过（`opendsec_edge_rejected_total` 为 0），真实原因是从快照恢复失败（edge 的 microvm 创建：`unavailable` 共 20 次，`not_found` 2 次）。
  - 根因是一个竞态。microVM 拍快照时，先把快照目录改名放进节点缓存，再把快照记录写进镜像库（NFS）。节点快照缓存的清理每分钟运行一次，会删掉「镜像库里查不到」的快照。如果清理恰好落在这两步之间，刚拍好的 fork 快照就被删了。概率约为 22 万次 fork 失败 5 次。
  - 修复：清理时跳过 10 分钟内的快照（`snapGCGrace`，测试 `TestSnapCacheGCGrace`）。
  - 诊断上的问题也一起改了：
    - placement 在 edge 拒绝之后再也挑不出 edge 时，原来返回的是「no edge can host」，盖掉了 edge 给出的真实原因。现在返回最后一个 edge 的错误。
    - apiserver 在 edge 拒绝创建时记一条 Warn 日志（edge 和原因）。
- **资源趋势**（第一个小时对比最后一个小时）：
  - **系统盘每天增长约 1.8 GB**（bm1 和 bm2 都是），这是要修的问题。bm1 的系统盘一共 20 GB，已用到 85%。来源：
    - `/var/log/syslog`：两天 2.8 GB，rsyslog 每周才轮转一次。在 30 万行样本中：
      - networkd-dispatcher 约占 2/3：它对每块网卡的状态变化都调一次 `networkctl`，sandbox 的网卡也算在内；机器上没有它要执行的脚本，它只是在已经删掉的网卡上报错；
      - 其余主要是每个 sandbox 引起的内核消息：loop 盘容量变化、ext4 挂载和卸载、overlay 的 null uuid。
    - 审计日志：按 256 MB 轮转，但没有保留上限，两天 766 MB。
    - journald 有 2 GB 的上限，所以没有越长越大，但上限被这些噪音占满后，只能保留最近约 9 小时的记录。查上面 5 个 fork 失败时，10-19 和 10-20 的 journal 已经没有了。
  - 修复：
    - `deploy/node/install.sh`：
      - networkd-dispatcher 没有配置脚本时关掉；
      - 装一个 rsyslog 过滤规则（`10-opendsec-rsyslog.conf`），这些每个 sandbox 都会产生的内核和 networkd 消息只留在 journal 里。
      - 规则用一个临时的 rsyslogd 实例验证过：丢掉 5 类噪音，保留真实磁盘错误、物理网卡和其他程序的消息。
    - 审计日志加 `audit_keep`（默认 8 个文件，每个 apiserver 最多约 2 GB），超过时删最旧的（`TestAuditKeep`）。
  - **没有泄漏**：
    - goroutine、fd、线程数持平；edge 的线程数在 22–46 之间。
    - edge 的 heap 持平。
    - IAM 的 heap 从 18 MB 到 22 MB。
    - 挂载、netns、nft 表、网卡数回到基线。
  - **看着涨、但不是泄漏**：
    - apiserver 的 heap 从 40 MB 涨到 103 MB，最高 307 MB。这是 sandbox id 到 project 的缓存，上限 100 万条，满了整体清空，所以呈锯齿形。
    - apiserver 和 edge 的 cgroup 内存分别涨到约 1 GB 和 2 GB，是写文件留下的页缓存（审计日志、sandbox 状态文件），heap 没变，可以回收。
    - IAM 的 RSS 从 46 MB 涨到 133 MB，heap 没变，是 Raft 存储 mmap 进来的文件页。
  - **要长期观察**：
    - dying cgroup：bm1 每天多 325 个，bm2 每天多 145 个。
    - 不可回收 slab：bm1 每天多 1.4 GB，bm2 每天多 1.1 GB。相对 1.5 TB 内存，按这个速度一个月约 40 GB，内核在内存紧张时会回收（§32 的观察）。
    - 建议对 `SUnreclaim` 加告警，或者定期重启节点。

### 33.3 SLO
定义在 docs/SLO.md，Prometheus 规则在 `deploy/monitoring/alerts.yml` 的 `opendsec-slo` 组。目标：
- 创建可用性 99.9%；
- 创建延迟 p99：container 5 秒内，microvm 3 秒内；
- 运行时调用可用性 99.95%；
- 调用方端到端成功率 99.9%。

窗口为 30 天。上面故障注入中的行为，就是 SLO 里「单点故障时的行为承诺」的依据。

### 33.4 上线后复测（2026-10-22）
- **上线**：0.11.0-202610220203（含层缓存、fork 快照竞争和日志增长的修复），由 fleet 滚动升级，3 台节点 2 分钟内完成。压测同时在跑，约 1 万个循环，0 失败。之后在 bm1、bm2 上重跑 `deploy/node/install.sh`，并把积压的 syslog 轮转压缩：bm1 的系统盘从 87% 降到 69%。
- **复测**：负载和 §33.1 相同（两边各 8 个并发），依次跑基线、NFS 中断 60 秒、edge e2 卡死 30 秒。

  | 场景 | 循环 | 失败 | 创建最长 | 对比 §33.1 |
  |---|---|---|---|---|
  | 基线 2 分钟 | 2469 | 0 | 2.1 秒 | |
  | NFS 中断 60 秒 | 605 | 0 | 93.6 秒 | 原来 1 个失败：容器里的一条命令卡了 88 秒。现在运行中的容器读本地的层副本，不再卡；新建仍要等镜像库恢复（SLO 中「允许新建失败」） |
  | edge e2 卡死 30 秒 | 1651 | 0 | 15.3 秒 | 原来 1 个失败，创建最长等 30.3 秒。现在 keepalive 约 15 秒发现 e2 没有响应，改到 e1 |

  整个 12 分钟两边共 12,935 个循环，0 失败。容器的 overlay 下层全部在 `<state_dir>/<edge>/layers` 下，没有一个挂在镜像库上。
- **syslog 增速**：负载下 bm1 每 8 分钟约 0.25 MB，以前每天 1 GB 以上。剩下的大头是 overlay 每次挂载打印的 `"xino" feature enabled`，已加进过滤规则。
- **发现：两台节点的 NFS 客户端身份冲突**。
  - 现象：NFS 服务端（bm2）的 syslog 里，`rpc.mountd` 不停地打印 `v4.2 client attached` 和 `client detached`，bm1 和 bm2 两个客户端交替出现。空闲时每小时约 670 次，负载下每分钟约 450 次；4 天累计 127 万行。客户端 ID 不停变化，12 分钟里出现了 2167 个不同的 ID。
  - 原因：三台机器的主机名都是 `kernel`，也都没有设置 NFS 客户端标识（`nfs4_unique_id` 和 `/sys/fs/nfs/net/nfs_client/identifier` 都为空）。这时 NFSv4 客户端向服务端报的身份只有主机名（`Linux NFSv4.2 kernel`），服务端把两台节点当成同一个客户端：一台每次重新登记（EXCHANGE_ID），都会作废另一台的租约、打开的文件和锁，对方要重新恢复状态。
  - 影响：到目前为止没有造成调用方失败（48 小时测试里镜像库相关的操作全部成功），但每次状态被作废都多一轮恢复，镜像库上的读写会偶尔变慢；有文件锁的话锁会丢。容器的层改为本地副本之后，受影响的只剩新建、快照、fork 和镜像导入。
  - 修复：`deploy/node/install.sh` 用 `/etc/machine-id` 设置 `nfs4_unique_id`（写 `/etc/modprobe.d/opendsec-nfs.conf`，并直接写入当前内核）。内核在客户端第一次登记时生成身份并缓存，所以已有的挂载要等重新挂载、且旧挂载没有进程在用之后才换成新身份，最简单的是重启节点。只要两台节点中的一台换了身份，冲突就消失。
  - 同时：overlay 的 `xino` 消息加进了 rsyslog 过滤规则，用临时的 rsyslogd 实例验证过。

## 34. 许可证和扩展点（2026-10-23）

- **许可证**（取代 §30 的 Apache-2.0）：
  - 服务端和工具改为 AGPL-3.0，另外提供商业授权。这样任何人都能自由使用、修改、自建；拿去改了再作为服务提供给别人的，要公开修改，或者购买商业授权。
  - 客户端部分保持 Apache-2.0，调用 OpenDsec 的程序不受 AGPL 约束：Python SDK（`sdk/python/`）、Go 客户端（`pkg/`）、API 定义和生成的代码（`proto/`、`gen/`）。每个目录都有自己的 LICENSE，CI 检查它们一致。
  - 为此，`pkg/client` 不再导入 `internal/pki`：它自带 `APIServerName` 的副本，由 pki 的测试检查两者相同。
  - 发布包的 `licenses/opendsec/` 带上 OpenDsec 自己的 LICENSE 和 NOTICE。
  - 贡献代码要签 CLA（`CLA.md`，由 `.github/workflows/cla.yml` 在 PR 上收集），这样外部贡献也能纳入商业授权。
- **扩展点**（`ext`）：开源版之外的代码（企业版）从这里接入，开源版不链接任何扩展。
  - 扩展在 `init()` 里注册，各组件启动时用集群配置的 `"extensions": {"<名字>": ...}` 一节初始化它。配置里写了本程序没有的扩展时，组件拒绝启动，免得功能悄悄失效。
  - **认证器**：apiserver 先问各个扩展的认证器，没有认领的 token 再交给 IAM。认领的 token 进同一个认证缓存，记下「由扩展认证」；对它做 Admit（创建、fork、迁移时的鉴权和配额预留）时，apiserver 改为把 principal 交给 IAM（`AdmitRequest.principal`），因为 IAM 不认识这个 token。IAM 的内部接口只有 apiserver 能调用，这和 `Authorize` 本来就信任 apiserver 给出的 principal 是同一个信任边界。
  - **审计输出**：每行审计记录写进本地文件之后，交给各个扩展的审计输出。它们不能阻塞。
  - 带扩展的程序：`ext/cmdmain` 放组件的 main 函数，开源版的 `cmd/` 和带扩展的构建都调用它。
  - `make check-open` 在一份去掉扩展代码的副本上构建和 vet，保证开源版不依赖它们（CI 每次都跑）。
  - 2026-10-23 起，扩展点和 main 函数从 `internal/` 移到根目录的 `ext/`、`ext/cmdmain`：Go 不允许别的模块导入 `internal/` 下的包，移出来以后，收费代码可以放进单独的私有仓库，把开源版当依赖引用（商业 spec 第 5.4 节的方案 B）。它们仍然是 AGPL。
- **测试**：`test/e2e/ext_test.go` 用一个假的 SSO 认证器验证：它的 token 能查身份、创建、受配额限制、停止；没有权限的被拒绝；认证器拒绝的 token 返回 unauthenticated；审计输出收到这些调用的记录。

## 35. 私有镜像仓库和 zstd 镜像层（2026-10-23）

企业的镜像大多在私有仓库里（Harbor、GitLab、云厂商的仓库）。之前 `image import` 只会匿名拉取。

- **凭据从哪来**（`opendsecctl image import`）：
  - `-username U -password-stdin`：密码或访问令牌（Harbor 的机器人账号、GitLab 和 GHCR 的令牌）从标准输入读，不出现在命令行和进程列表里；
  - 否则读 docker 的配置文件，即 `docker login` 写下的凭据：`-registry-auth` 指定的文件，或 `$REGISTRY_AUTH_FILE`（podman 用的变量，格式相同）、`$DOCKER_CONFIG/config.json`、`~/.docker/config.json`。
    - 支持 `auth`（base64 的「用户名:密码」）、`username`/`password` 和 `identitytoken` 三种写法；Docker Hub 的各种写法（`https://index.docker.io/v1/`、`docker.io`）都对应到 `registry-1.docker.io`。
    - 凭据由凭据助手（`credsStore`、`credHelpers`）保管时不去运行助手，报错并提示改用 `-username`。导入是在服务器上以 root 运行，那里的 `docker login` 一般直接写进配置文件。
  - 都没有时匿名拉取，和原来一样。
- **认证方式**（`internal/images/oci.go`、`auth.go`）：
  - 令牌服务（Docker Hub、Harbor、GHCR 等）：向质询里的 realm 要令牌，有用户名密码时带 Basic 认证；
  - identity token：按 OAuth2 的 refresh token 方式（POST，`grant_type=refresh_token`）换令牌，和 docker 的做法一样；
  - 仓库直接要求 Basic 认证（`registry:2` 配 htpasswd、Nexus 等）：之后每个请求都带上；
  - 令牌过期（大镜像下载时间长）时，遇到 401 会重新要一次。
- **凭据不外泄**：镜像层常常跳转到 CDN 或对象存储下载，跳转离开仓库的主机和端口时去掉 Authorization。Go 的默认规则只比较主机名，同一主机名的其他端口、以及子域名照样会带上，测试里正好抓到了这一点。
- **报错说清原因**：没有凭据时提示 `docker login` 或 `-username`；凭据被拒时说明是哪个用户（或 identity token），不显示密码。
- **zstd 镜像层**（`application/vnd.oci.image.layer.v1.tar+zstd`）：新构建的镜像越来越多用 zstd 压缩，之前导入时报「unsupported layer media type」。现在用 `klauspost/compress` 的 zstd 解码器解压，这个模块本来就在依赖图里（Prometheus 客户端用它），没有引入新模块。同一个镜像里 gzip 层和 zstd 层可以混用。`TestPullZstdLayers` 覆盖混合的镜像、zstd 层里的删除标记，以及损坏的 zstd 层不会入库。
- **测试**：`TestPullPrivateRegistry` 用假仓库覆盖三种认证方式，各测正确凭据、没有凭据、错误凭据，并检查跳转后的下载不带凭据；`TestLoadAuthFile` 覆盖配置文件的各种写法和凭据助手。另外从 Docker Hub 实际匿名拉取了 `alpine:3.20`，确认没有退化。

## 36. 被放弃的创建不再留下孤儿 sandbox（2026-10-23）

§33.1 留下的问题：apiserver 发给某个 edge 的创建迟迟没有结果（edge 卡住、太慢，连接被 keepalive 断开），placement 就换一个 edge 重试。重试用同一个 lease，IAM 把 lease 改绑到新的 edge。原来那个 edge 恢复后照样把创建做完，于是同一个 lease 有两个 sandbox：
- 原 edge 上那个没有人知道，调用方拿到的是新 edge 上的；
- 它不计配额，watcher 对账时只记一次 conflict；
- 到空闲 TTL（默认 1 小时）才回收，回收时还会把 lease 还给 IAM，把新 edge 上那个 sandbox 的配额也一起释放了，要等下一次对账才重新计上。

**修复**分两处：
- **edge 创建完成时先确认**（`internal/edge/edge.go` 的 `abandoned`）：后端创建成功后，向 IAM 查这个 lease 绑在哪里（新接口 `IAM.LeaseEdge`，edge 可以调用）。
  - 绑在别的 edge：调用方已经放弃、改到那里创建了；
  - lease 已经释放：调用方放弃了，所有重试也都失败了；

  这两种情况都当场停掉刚建好的 sandbox，记为 FAILED，返回 `unavailable`。lease 照常还给 IAM，由下面第二条保证不会误释放。
  - 迁移（`Move`）不检查：迁移时 lease 本来就先改绑到目标 edge。
  - 问不到 IAM 时保留 sandbox（和原来一样），由 watcher 对账发现 conflict。旧版 IAM 没有这个接口时，只记一次日志。
  - 剩下的窗口：edge 查完 IAM、回复还没送到调用方时连接恰好断开，调用方再去别处重试。这个窗口很小，出现时仍然按原来的方式在空闲 TTL 后回收。
- **IAM 按来源释放 lease**：edge 归还 lease 时带上自己的 id（`ReleaseRequest.edge`、`ReleaseLeasesRequest.edge`）。这个 lease 已经绑到别的 edge 时，IAM 不释放。
  - 走 mTLS 时，IAM 以调用方证书里的 edge id 为准，不信请求里写的。
  - apiserver 的释放（创建全部失败时）不带 edge，行为不变；没有绑定的 lease 照常释放。
  - Raft 日志里旧的释放命令没有 edge 字段，回放时行为不变。
- **批量创建的重试不受影响**：重试时列出各 edge 上这个请求已有的 sandbox。被删掉的那个是 FAILED，会换新的 lease 重建；正常的那个照常返回。
- **滚动升级**：新 edge 加旧 IAM 时保留 sandbox，和原来一样；旧 edge 加新 IAM 时，IAM 按证书识别 edge，释放规则照样生效。
- **测试**：
  - `TestReleaseFromEdge`（IAM）：改绑后原 edge 的释放被拒，绑定的 edge、未绑定的 lease、apiserver 的释放照常；
  - `TestAbandonedCreation`（edge）：lease 改绑、已释放时删掉，绑在自己这里、未绑定、问不到 IAM 时保留；删掉的不再占资源，lease 照常归还；
  - `TestAbandonedCreation`（e2e，真实 IAM）：慢 edge 做完被放弃的创建后，只剩新 edge 上的 sandbox 在运行，配额仍然计 1 个，lease 仍然绑在新 edge 上。

## 37. E2B 兼容（2026-10-23）

目的：用 E2B SDK 的程序（以及基于它的 Agent 框架）不改代码就能在 OpenDsec 上跑。用户设置

```sh
E2B_API_URL=http(s)://<网关>  E2B_SANDBOX_URL=http(s)://<网关>  E2B_API_KEY=<OpenDsec token>
```

### 37.1 结构

```
E2B SDK ──REST（管理接口）──┐
        ──Connect（envd）───┴─> opendsec-e2b（无状态） ──gRPC，带调用方自己的 token──> apiserver ─> edge ─> aether
```

- **网关 `opendsec-e2b`**（`internal/e2b`、`cmd/opendsec-e2b`）：
  - 一个端口上同时提供两套接口：
    - E2B 的管理接口（REST）；
    - E2B 在 sandbox 里的 envd 接口：进程和文件，走 Connect 协议，另有几个 HTTP 路由。
  - 带 `E2b-Sandbox-Id` 请求头（SDK 每次都带）或者主机名是 `<端口>-<id>.<域名>` 的请求，交给 envd 那一套处理，其余的是管理接口。
  - 不保存状态，每个请求都用调用方自己的 token 调 apiserver：权限、配额、审计全部照旧，和直接用 OpenDsec SDK 没有区别。
  - HTTP/1.1 和 HTTP/2 都支持，包括不加密的 h2c，Connect 的流式调用要用到。
- **envd 的协议**：E2B 的 `process.proto` 和 `filesystem.proto`（Apache-2.0）原样放在 `proto/e2b/`，只加了 `go_package`，用 connect-go v1.21.0 生成服务端代码。
- **sandbox id**：E2B 的 id 要能当 DNS 标签用，我们的是 `<edge>.<lease>`。对外写成 `<edge>-<lease>`：edge id 里可能有 `-`，lease 里没有，所以按最后一个 `-` 就能拆回来。
- **API key**：就是 OpenDsec 的 token。管理接口返回的 `envdAccessToken` 也是这个 token，SDK 访问 envd 时把它放在 `X-Access-Token` 头里带回来。持有它的人本来就拥有这个 token，没有扩大权限。

### 37.2 新增的 OpenDsec 接口

E2B 的命令模型和我们原来的不同：原来的命令跑在持久的 shell 会话里，用 cmd_id 标识；E2B 的每个命令是一个独立进程，用 pid 寻址，可以写 stdin、发信号、用 PTY，断开后还能重新连上。所以新增了：

- **进程接口**（Runtime、Edge、公开 API 三个服务都有）：`StartProcess`（流）、`ConnectProcess`（流）、`ListProcesses`、`SendProcessInput`、`CloseProcessStdin`、`SignalProcess`、`ResizeProcess`。
  - 由 aether 直接管理（`internal/agent/procs`），不经过 chronus 会话：E2B 的进程按 pid 寻址、可以跨会话列出，放在 aether 里路由最简单。切换用户和组装环境变量，复用 chronus 的 `Environ`。
  - 流断开不影响进程。`ConnectProcess` 从连上的时刻开始接收输出。
  - 有一路流连着时，输出有背压，进程会等慢的那一路；没有流连着时，输出直接丢弃。
  - 进程退出后还会继续读 2 秒输出：它留下的后台子进程可能一直占着管道或终端，2 秒后强制结束读取，退出事件照常送达。
  - PTY 用 `/dev/ptmx` 自己打开，没有引入新依赖。主端用非阻塞方式交给 Go 的轮询器，所以关闭时能打断正在进行的读。
  - 信号发给进程组，它启动的子进程一起收到。每个 sandbox 最多同时 1024 个进程。
  - 审计和 Exec 一样，只记命令的长度和 SHA-256，不记原文。
- **文件**：新增 `MakeDir`、`Move`。
- **超时** `SetSandboxTimeout`：E2B 的超时是「从现在起 N 秒后到期」，可以随时延长；我们的 `ttl_max` 是从创建时刻算起的上限。这个接口把 `ttl_max` 设成「已存活时长 + N」（不超过准入的上限），同时把空闲超时放宽到不短于 N，保证不会提前结束。

### 37.3 管理接口的对应关系

| E2B | OpenDsec |
|---|---|
| `POST /v2/sandboxes`（创建） | `CreateSandbox`：template 对应集群配置里 `e2b.templates` 的镜像、后端和资源；名字里带 `/` 时直接当镜像名用。`timeout` 同时设为 `ttl_max_s` 和 `ttl_running_stop_s`。metadata 和 envVars 存进 `e2b.` 前缀的标签 |
| `GET /sandboxes/{id}`、`GET /v2/sandboxes` | `GetSandbox`、`ListSandboxes`：只列网关创建的、运行中或暂停的 sandbox；支持按 state 和 metadata 过滤 |
| `DELETE /sandboxes/{id}` | `StopSandbox` |
| `POST /sandboxes/{id}/timeout` | `SetSandboxTimeout` |
| `POST /sandboxes/{id}/pause` | `PauseSandbox`，超时延长到 30 天（不超过准入上限）：E2B 的暂停 sandbox 会一直保留到被删除 |
| `POST /v2/sandboxes/{id}/connect` | 暂停的先 `ResumeSandbox`（返回 201），再设置超时 |
| `GET /sandboxes/{id}/metrics` | 空列表 |

envd 部分：
- 进程的 `Start`、`Connect`、`List`、`SendInput`、`StreamInput`、`SendSignal`、`CloseStdin`、`Update`（调整终端尺寸）都已支持。按请求头 `Keepalive-Ping-Interval` 定时发保活事件。
- 文件的 `Stat`、`MakeDir`（目录已存在时返回 AlreadyExists）、`Move`、`ListDir`（支持 depth）、`Remove` 都已支持。
- `GET`/`POST /files`：每块 2 MB 读写，远低于 gRPC 默认 4 MB 的消息上限；支持 multipart 和 octet-stream。
- 上报的 envd 版本是 0.5.7。SDK 会按这个版本开关功能：默认用户、stdin 开关、关闭 stdin、octet-stream 上传都可用。

### 37.4 还不支持的

- 监听目录变化（`WatchDir` 等）：返回 Unimplemented。
- 签名 URL（`download_url` / `upload_url`）：网关只认 token，不验签名。
- ~~访问 sandbox 里的其他端口~~：已支持，见 37.8。
- ~~E2B 的 `autoPause`~~、~~网络选项~~：已支持，见 37.11。
- ~~fork 和快照接口~~：已支持，见 37.10。
- 构建 template 的接口、MCP、volume。
- ~~只用 Python 同步 SDK 测过~~：JS SDK 和 Python 异步 SDK 也已测过，见 37.9。

### 37.5 部署

- 网关配置放在集群配置的 `e2b` 一节：`gateways`（每个实例的监听地址，可选 TLS）、`project`、`templates`、`default_template`、`domain`、`max_timeout_s`。
- fleet 增加角色 `e2b=<序号>`，对应单元 `opendsec-e2b@<序号>`，`/readyz` 在 9467 端口，检查到 apiserver 的连接是否可用。
- 单元用 `DynamicUser` 运行，只通过 `LoadCredential` 拿到集群配置和 CA 证书，看不到 `/etc/opendsec` 里的私钥和 `admin.token`：网关直接面对外部流量，要尽量少权限。
- 前面放负载均衡时，健康检查用 9467 的 `/readyz`，要支持长连接的流（空闲超时不低于 60 秒；SDK 每 50 秒发一次保活）。

### 37.6 测试

- `internal/agent/procs`：输出和退出码、stdin、信号、tag、断开重连、PTY 尺寸和调整、留下后台子进程时退出事件仍按时送达、切换用户。
- `TestProcessesEndToEnd`：在真实容器里，经 apiserver、edge、aether 全链路测进程接口，以及 MakeDir 和 Move。
- `TestE2BSDK`：用 E2B 官方 Python SDK 2.46.0（`OPENDSEC_E2B_PYTHON` 指向装了 e2b 的 python），连本地起的集群（真实容器）和网关，跑 `test/e2e/testdata/e2b_sdk_check.py` 的 23 项检查：
  - 命令：输出、环境变量和工作目录、非零退出码、流式输出、后台进程加 stdin、kill；
  - 文件：读写、10 MB 往返、列目录、建目录、改名、查询、删除、文件不存在；
  - PTY；
  - 管理：查询信息、列出、设置超时、`is_running`、从另一个客户端 connect、删除后不再列出。
  - 设置 `OPENDSEC_E2B_JS`（执行过 `npm install e2b` 的目录，`node` 在 PATH 里）时，再用 E2B 的 JS SDK 跑同样 23 项（`test/e2e/testdata/e2b_js_check.mjs`）。

  全部通过。

### 37.7 上线（2026-10-23）

- **发布**：0.11.0-202610230504 先只升级程序（1.5 分钟），再下发第 4 代配置（加上 `e2b` 一节），并给 bm1、bm2 加上 `e2b=0`、`e2b=1` 角色。期间压测（bm2 发起，container 和 microvm 混合）0 失败。
- **遇到的 fleet bug**：两台机器同时加了 `e2b` 角色后发起配置 rollout，三台机器一直停在 staged。
  - 原因：rollout 每升级一台机器前，要求其他控制面机器健康；而健康是按机器**现在的角色**算的，包括新加、还没部署的 `e2b` 单元。bm1 等 bm2 的 `opendsec-e2b@1` 就绪，bm2 等 bm1 的，这两个单元又都要靠这次 rollout 才会启动，互相等死。
  - 当时的处理：中止 rollout；先去掉 bm2 的角色，只对 bm1 和 ctl3 发 rollout；bm1 的网关就绪后，再给 bm2 加角色，单独对 bm2 发 rollout。
  - 修复：机器记录新增 `deployed_roles`，即上一次 rollout 或 sync 成功时的角色。判断「其他机器是否健康」时只看已部署的角色。正在升级的那台机器本身，仍然检查它的全部角色。旧记录没有这个字段，按全部角色算，和原来一样。`TestDeployed` 覆盖了这个逻辑。
  - 运维上，给已有机器加角色应该用 `fleet node sync <名字>`，一台一台来，已写进 OPERATIONS §6.3。
- **验收**：在 bm2 上用 E2B 官方 Python SDK 2.46.0，以压测调用方自己的 token，分别经两台网关跑 `e2b_sdk_check.py`。template `base` 是 `root/py:3.12`、microVM、2 vCPU、1 GB。两台网关上 23 项检查都通过，每次约 1.3 秒。
- **时延**（经网关，microVM 冷启动，连续 20 次）：`Sandbox.create()` p50 166 ms、最慢 200 ms；创建后第一条命令 p50 12 ms、最慢 19 ms。
- 两个网关单元都以 `DynamicUser` 运行，只通过 `/run/credentials` 拿到配置和 CA 证书；`/readyz` 返回 200。

### 37.8 sandbox 里的其他端口（2026-10-23）

E2B 的 `get_host(port)` 让调用方访问 sandbox 里自己起的服务（web 应用、Jupyter）。E2B 的 code-interpreter SDK 就是这样用的：它通过 49999 端口的服务执行代码，用流式响应（NDJSON）返回结果。

- **端口隧道 `ConnectPort`**（Runtime、Edge、公开 API 三个服务都有）：一个双向流。
  - 第一条消息指定 sandbox 和端口；aether 在 sandbox 里连 `127.0.0.1:<端口>`，连不上再试 `::1`，连上后回一条空消息确认，之后双向转发字节。
  - 一方发送完毕（关闭发送端）会传到另一方，即 TCP 的半关闭。
  - 权限要求 `sandbox.operate`；连接存续期间 sandbox 算作活跃。审计记录端口号。
  - 暂停的 sandbox 被访问时由 edge 自动恢复，和其他运行时调用一样。
- **网关**：envd 端口（49983）以外的请求，交给反向代理（`internal/e2b/ports.go`）。
  - 每个请求经 `ConnectPort` 新开一条连接，用调用方自己的 token。连接不在调用方之间复用，否则后来的调用方会借用前一个调用方的授权。
  - 流式响应边到边转发（`FlushInterval: -1`）；Upgrade（WebSocket 等）由 `httputil.ReverseProxy` 接管连接。
  - 转发前去掉网关自己用的请求头：`E2b-Sandbox-*`、`X-Access-Token`、`E2B-Traffic-Access-Token`、`X-API-KEY`，以及和 token 相同的 `Authorization`。token 不会进入 sandbox 里的服务。
  - 端口没开返回 502（和 E2B 一致），没有 token 返回 401。
- **认证**：创建和连接 sandbox 的响应里返回 `trafficAccessToken`（就是调用方的 token），SDK 访问其他端口时会带上 `E2B-Traffic-Access-Token` 头。
  - 不带任何头的访问（例如直接在浏览器里打开）会被拒绝。这相当于 E2B「不开放公网流量」的模式。
- **template 的启动命令**：`e2b.templates` 里可以配置 `start_cmd`、`ready_port`、`ready_timeout_s`。
  - 创建 sandbox 后，用 `bash -l -c` 在后台运行启动命令，并等端口可以连上再返回；超时就删掉这个 sandbox 并报错。
  - 如果镜像本身就是「服务已在运行」的内存快照，就不需要启动命令，创建也更快。
- **测试** `TestE2BPorts`：在真实容器里起一个 python 服务。
  - 流式响应：3 段输出、每段间隔 0.3 秒，第一段在 250 ms 内到达，说明是边到边转发；
  - Upgrade 后的连接双向回显，包括 100 KB 的数据；
  - 没开的端口返回 502，没带 token 返回 401；
  - 服务端检查过，收到的请求里没有网关用的请求头。
- **E2B code interpreter**（2026-10-23，线上）：
  - **镜像** `root/code-interpreter:v1`：由 `deploy/e2b/build-code-interpreter.py` 构建，用的是 E2B code-interpreter 仓库 `template/` 里的服务和配置（Apache-2.0）。
    - 在 microVM（`root/py:3.12`，2 vCPU、2 GB）里装上 curl、Jupyter、ipykernel 和 pandas、matplotlib、numpy 等库，拷入 E2B 的服务，启动服务并等健康检查通过，然后拍成带内存的快照。
    - 从这个镜像创建的 sandbox，Jupyter 和服务一恢复就在运行，不需要启动命令。
  - **和 E2B 原版的差别**：
    - 只装了 Python 内核。E2B 的服务启动时会建 JavaScript 上下文，没有 JS 内核就起不来，所以打了补丁：失败时只记警告。
    - 服务每次执行前会向 envd（`localhost:49983`）取 sandbox 的环境变量。我们的 sandbox 里没有 envd，所以加了一个只回 `{}` 的小服务。结果是：创建 sandbox 时设的 envVars 不会带进 `run_code`，`run_code(envs=...)` 照常可用。
    - 构建时发现 slim 镜像里没有 curl，而 E2B 的健康检查脚本要用。
  - **验收**（`test/e2e/testdata/e2b_code_interpreter_check.py`，e2b-code-interpreter 2.11.3、e2b 2.59.0，经两台网关）：9 项全部通过。
    - 覆盖：执行代码返回结果和 stdout、两次执行之间保留状态、异常、流式 stdout、pandas 表格（HTML）、matplotlib 图表（PNG）、新的独立上下文、`run_code(envs=...)`、和普通命令并用。
    - `Sandbox.create()` 约 280 ms（从 2 GB 的内存快照恢复），第一次 `run_code` 约 43 ms（内核已经是热的）。
  - 线上 `e2b.templates` 增加 `code-interpreter-v1`（第 5 代配置）。期间压测 39,072 个循环，0 失败。

### 37.9 JS SDK 和 Python 异步 SDK（2026-10-23）

- **JS SDK**：`test/e2e/testdata/e2b_js_check.mjs` 是 `e2b_sdk_check.py` 的 JS 版本，23 项检查一一对应；设置 `CI_TEMPLATE` 时再用 `@e2b/code-interpreter` 跑 code interpreter 的 9 项。
  - 线上（bm2 发起，Node 22.20，e2b 2.59.0、@e2b/code-interpreter 2.9.0，经两台网关）：32 项全部通过。code interpreter 创建约 210 ms，第一次 `runCode` 约 40 ms。
  - 本地集群：`TestE2BSDK/js`，见 37.6。
  - 不需要改网关：JS SDK 走的是同样的 REST、Connect RPC 和 `/files` 接口。
- **Python 异步 SDK**（`AsyncSandbox`，e2b 2.59.0、e2b-code-interpreter 2.11.3）：在一个事件循环里并发创建 8 个 sandbox（命令、流式输出、文件、`is_running`）和 2 个 code interpreter，经两台网关都通过。

### 37.10 fork 和快照（2026-10-23）

E2B 的 `sandbox.fork()`、`create_snapshot()`、`Sandbox.create(snapshot_id)` 直接对应 §19 的 `ForkSandbox`、`CreateSnapshot` 和「从快照镜像创建」。

| E2B | OpenDsec |
|---|---|
| `POST /sandboxes/{id}/fork`（`timeout` 默认 15 秒，`count` 1–100） | `ForkSandbox`，TTL 同创建。返回 201 和一个列表，每个副本一项：成功是 `sandbox`，失败是 `error`（code 按错误原因换成 HTTP 状态码）。源 sandbox 拍不了快照时整个请求失败 |
| `POST /sandboxes/{id}/snapshots`（`name`、`memory`） | `CreateSnapshot`，存成网关项目里的镜像，镜像名就是 `snapshotID` |
| `GET /snapshots`（`sandboxID`、`name`） | `ListImages`，只列 `CreateSnapshot` 做的镜像 |
| `DELETE /templates/{id}`（SDK 的 `delete_snapshot`） | `DeleteImage`，只删快照镜像，其他镜像返回 400 |
| `Sandbox.create(snapshot_id)` | 从镜像创建：名字里有 `/` 就当镜像名，已有的逻辑 |

- **镜像名**：没给名字时是 `<项目>/snapshot-<随机16位>:default`；给了 `name` 或 `name:tag` 就是 `<项目>/name:tag`，tag 默认用 E2B 的 `default`；带 `/` 的名字直接当 OpenDsec 镜像名。同名再拍一次会替换旧的，和 E2B 一样。
- **内存**：E2B 默认拍内存。`memory` 不填时，microVM 拍内存，容器不拍（容器没法拍）。明确要求的组合不支持时返回 400：容器加 `memory=true`，或 microVM 加 `memory=false`（运行中的 guest 只拷磁盘会丢页缓存，§19.2）。E2B 在不支持只拍文件系统时也是返回 400。
- **从内存快照创建**：内存只能恢复到同样大小的 VM 里，而 `Sandbox.create(snapshot_id)` 不带资源。
  - 改动：apiserver 创建时，如果镜像是内存快照、请求没填资源，就用快照里记录的 vCPU、内存和磁盘（`snapshotShape`）。这对所有调用方都生效，不只是 E2B。
  - 网关对不在 `e2b.templates` 里、带内存快照的镜像，把后端设成 microVM，资源留空。
- **测试** `TestE2BSnapshots`：本地集群、真实容器、共享镜像库，用 E2B Python SDK 跑 `test/e2e/testdata/e2b_snapshot_check.py` 的 21 项检查：
  - fork 两份：都能看到源的文件、各自独立修改、源继续运行；
  - 不带名字的快照：能按 sandbox 列出、在全部列表里、从它创建、从它创建的 sandbox 还能 fork；
  - 带名字的快照：`:default`、同名替换、按名字列出、从中创建拿到的是最新内容；
  - 删除返回 True，再删返回 False，删后不再列出。
  - 带 `MEMORY=1` 时（线上 microVM）还检查：fork 和从快照创建的 sandbox，保留了源里后台运行的进程。

### 37.11 autoPause、网络选项、refresh（2026-10-23）

**autoPause**：新增 `SandboxSpec.ttl_paused_s`（字段 15），所有调用方都能用。
- 大于 0 时，运行中的 sandbox 到了 `ttl_max_s` 或空闲超时，edge 不停止它而是暂停，并保留 `ttl_paused_s` 秒：`ttl_max_s` 改成「暂停时的年龄 + ttl_paused_s」。到期后停止。
- 暂停失败（后端不支持）就照常停止，消息里写明原因。
- 暂停后任何调用都会自动恢复它，和其他暂停的 sandbox 一样。恢复后由空闲超时控制，空闲了会再次暂停。
- apiserver 校验 `ttl_paused_s >= 0`，超过准入的寿命上限时截到上限。
- 网关：`autoPause`（SDK 的 `lifecycle={"on_timeout": "pause"}`）设 `ttl_paused_s` 为 30 天，和手动暂停一致。sandbox 信息里返回 `lifecycle`：`onTimeout` 是 `pause` 或 `kill`，`autoResume` 总是 true。
- **和 E2B 的差别**：
  - E2B 的 `autoResume` 默认关，关闭时流量不会唤醒暂停的 sandbox；我们任何调用都会唤醒。
  - 只拍文件系统的暂停（`autoPauseMemory=false`、`pause(mode="filesystem")`、`connect(on_resume="reboot")`）一律返回 400，不会悄悄改成带内存的暂停。
  - E2B 恢复后按原来的超时重新计时；我们恢复后按空闲超时。

**网络**：映射到 §20 的 `network_rules`。
- `allow_internet_access=false`，或 `denyOut` 里有 `0.0.0.0/0`：规则 `"*": false`，撤销集群默认规则里的 `"*"`。E2B 默认放行公网，所以集群默认规则也要有 `"*"`；线上就是这样配的。
- `allowOut`：每一项成为一条放行规则。`0.0.0.0/0` 对应 `"*"`；`*.example.com` 对应 `example.com`（我们的域名规则本来就包含子域名，也包含它自己，比 E2B 宽一点）；IP 和网段原样使用。和 E2B 一样，放行优先于拒绝。
- `denyOut` 里 `0.0.0.0/0` 以外的项返回 400：我们的模型是「默认拒绝、按规则放行」，没法表达「公网放行但拒绝某个地址」。
- `maskRequestHost`、`httpsPorts`、`rules`（请求改写）、`egressProxy`、`mcp`、`volumeMounts` 返回 400。`dnsServers` 忽略：sandbox 的 DNS 由 edge 的代理处理。`allowPublicTraffic` 接受，但端口访问始终要 token（37.8）。
- `PUT /sandboxes/{id}/network`（SDK 的 `update_network`）：调 `UpdateNetwork(replace=true)`，整体替换 sandbox 自己的规则，和 E2B「没给的字段清空」一致。
- sandbox 信息里的 `network` 由当前规则还原，`allowInternetAccess` 是创建时的值。

**refresh**：`POST /sandboxes/{id}/refreshes`（`duration` 不超过 3600 秒）：剩余时间不足 `duration` 时，把超时延长到从现在起 `duration` 秒；够的话不变。

**测试**
- edge `TestAutoPause`：截止时间和空闲超时都变成暂停（截止时间即使有活动也照样到期）；保留时间正确；调用唤醒后，空闲了再次暂停；保留期满后停止。
- `TestE2BSDK/lifecycle`：用 E2B Python SDK 跑 `test/e2e/testdata/e2b_lifecycle_check.py`，本地 9 项：
  - autoPause 到时暂停，connect 恢复后文件还在；
  - 默认到时删除；
  - refresh 延长；
  - 只拍文件系统的暂停被拒绝。
- 带 `NETWORK=1` 时（需要 edge 开网络、默认规则有 `"*"`，即线上）再查 9 项：
  - 默认能上网，`allow_internet_access=False` 不能；
  - `allow_out` 优先于 `deny_out`；
  - `update_network` 替换和拒绝；
  - 不支持的拒绝项被拒绝；
  - 信息里返回网络配置。

## 38. 离线安装（2026-10-23）

国内私有化部署的机房大多不能访问外网。原来的安装要在线获取：程序（从源码构建，或下载依赖打包）、edge 用的系统软件包（apt）、基础镜像（镜像仓库）、Python SDK 的依赖（pip）。离线安装包把这些一次带齐。

### 38.1 镜像存成文件
- **导入**：`opendsecctl image import <文件> -as ...`。`<文件>` 是磁盘上的路径时从文件导入，否则照旧从镜像仓库拉取。支持三种格式：
  - OCI 镜像布局，目录或 tar（skopeo 的 oci-archive，Docker 25 起的 `docker save`）；
  - Docker 25 之前 `docker save` 的 tar：`manifest.json` 列出配置和未压缩的层文件，层的摘要取配置里的 `diff_ids`；
  - 一个文件里有多个镜像时，用 `文件#名字` 选择。名字按镜像引用比较，`python:3.12` 和 `docker.io/library/python:3.12` 视为同一个。
- 拉取和导入共用一套代码（`source` 接口：镜像仓库或文件）：选平台、读配置、解层、处理 whiteout 和不透明目录、去重，都和拉取一致。每个 blob 都校验 sha256，篡改过的层不会进入镜像库。
- tar 只读一遍建立索引（每个文件的偏移和大小），之后按偏移直接读，不解开到临时目录。压缩过的 tar（gzip、zstd）直接报错，提示先解压：按偏移读需要未压缩的 tar。
- **保存**：`opendsecctl image save <镜像> -out FILE` 把镜像仓库里本平台的镜像写成 OCI 布局的 tar，不需要 docker，也不需要连集群。先写到 `.part`，成功后改名。镜像的索引里带上 `io.containerd.image.name` 和 `org.opencontainers.image.ref.name` 两个注解，导入时可以按名字选。
- 测试：
  - `TestSaveImport`：从假镜像仓库保存，再从 tar、解开的目录、`文件#名字` 三种方式导入，层的 id 和拉取的完全一样；名字不对、压缩过的 tar、篡改过的层都被拒绝，篡改的层不进镜像库。
  - `TestImportDockerSave`：旧格式、两个镜像、按标签选择；第二个镜像的层已经在库里时不重复导入。
  - 实测：从 Docker Hub 保存 `python:3.12`（7 层，412 MB 的 tar），导入到空的镜像库，结果和拉取一致。

### 38.2 离线安装包（`deploy/offline/`）
- **制作** `build-bundle.sh OUT_DIR`：在能访问外网、和目标机器同样系统（发行版、版本、架构）的机器上运行。生成 `opendsec-offline-<版本>-<系统>.tar.gz`，内容：
  - `release/<版本>/`：`opendsecops release` 打出的完整版本，包括 Firecracker 和 guest 内核；
  - `debs/`：本地软件源（`apt-ftparchive` 生成的 `Packages`）。包括 edge 要的 e2fsprogs、erofs-utils、nftables、iproute2，NFS 的客户端和服务端，python3-venv 和 pip，Prometheus、Alertmanager、node exporter，以及它们完整的依赖闭包（`apt-cache depends --recurse`）。
  - `images/`：基础镜像的 OCI tar，默认 `python:3.12`，可以用 `--image` 指定多个；
  - `wheels/`：Python SDK 和它依赖的 wheel；
  - `deploy/`、文档、`install.sh`、`OFFLINE.md`（即 `deploy/offline/README.md`）、`TARGET`、`SHA256SUMS`。
- **`apt-local.sh PKG...`**：只用这个软件源安装，用自己的一份软件包列表（`Dir::State::Lists` 指向临时目录），不改机器原有的 apt 源。机器上已有的依赖不会重装。
- **单机** `install.sh`：检查系统和 `TARGET` 是否一致，校验全部文件，然后用安装包里的版本、软件源和镜像运行 `quickstart.sh`。
- **多机**：
  - `OPENDSEC_DEBS=<安装包>/debs` 让 `opendsecops install`（edge 节点的软件包）和 `monitor`（Prometheus 等）从安装包装软件，`apt_on` 把软件源拷到节点上再安装；
  - 新命令 `opendsecops release-add DIR` 加入别处打好的版本：先按它的 `SHA256SUMS` 校验，再设为当前版本。
- **quickstart 的改动**：
  - `--release DIR` 用打好的版本，不构建；
  - 机器没有默认路由时（隔离网络），取第一个全局 IPv4 地址作为监听地址。原来 `ip route get` 失败会让脚本在 `set -e` 下直接退出，连错误提示都没有。
  - 在安装包里运行时，最后的提示改成从 `wheels/` 安装 SDK。

### 38.3 验证（2026-10-23）
- 在 bm1 上用 QEMU 起一台全新的 Ubuntu 24.04 云主机（8 vCPU、16 GB，嵌套 KVM），网络用 user 模式加 `restrict=on`：没有任何出站连接，只转发 ssh 进来。确认解析不了外网域名，并且没有 `mkfs.erofs`。
- 拷入 551 MB 的安装包，`./install.sh`：32 秒装完。它从安装包装上了 erofs-utils，导入了 `python:3.12`，容器和 microVM 的 sandbox 都跑通了 Python。
- 同一台机器上用 `apt-local.sh` 离线装 NFS 服务端和客户端、Prometheus、Alertmanager、node exporter，全部成功。
- 第一次验证时发现：隔离网络没有默认路由，quickstart 取不到地址就悄悄退出。已修复（38.2）。

### 38.4 限制
- 安装包只适用于制作它的系统。要支持多个系统，就在各个系统上分别制作。
- Ubuntu、Debian 以外（dnf 系）的离线软件包还没做：install.sh 在这些系统上照旧用 dnf。
- 升级还需要拷入新的安装包，然后 `release-add` 再 `fleet release push`。没有离线的镜像仓库代理。

## 39. 单点登录（企业版，2026-10-23）

企业版的 `ee/sso` 扩展：调用方直接用身份提供方（IdP）签发的 OIDC token（ID token，或 JWT 格式的 access token）作为 OpenDsec 的 token。SDK 和 opendsecctl 都不用改。配置和用法见企业版文档（`ee/README.md`，不在公开仓库里）。开源版这边只新增了一个扩展点。

- **新扩展点 `ext.Directory`**：扩展通过 apiserver 的 IAM 连接，以配置里的 actor 身份修改 IAM，IAM 照常鉴权。apiserver 在启动时安装它（`Server.Directory()`）。
  - `EnsurePrincipal`：不存在就创建；IAM 建 principal 时附带签发的 token 会立即吊销，所以这个 principal 只能经扩展认证。
  - `SetGrants`：把 principal 在某个项目上的权限改成恰好是给定的集合，先比较差异，再分别授予和撤销。
- **验证 token**：
  - 签名：RS256/384/512、PS256/384/512、ES256/384/512（曲线必须与算法对应）、EdDSA；拒绝 `none` 和 HMAC，防止拿公钥当 HMAC 密钥的伪造。
  - `iss` 必须等于配置的 issuer，`aud` 必须包含配置的某个 client id；`exp` 和 `nbf` 允许 1 分钟时钟偏差；
  - 公钥按 discovery 文档里的 JWKS 获取。遇到未知的 key id（密钥轮换）会重新获取，但 30 秒内最多一次，避免伪造的 kid 引发大量请求。
  - 只用标准库实现，没有引入新依赖。
  - issuer 不是本 IdP 的 token 交给 IAM，所以 IAM token 照常可用。
- **身份**：`principal_prefix`（默认 `sso-`）加上 `principal_claim`（默认 `sub`）的值，`.`、`/` 和空格换成 `_`。用户组取 `groups_claim`（默认 `groups`），可以写点分路径，例如 Keycloak 的 `realm_access.roles`。
- **自动开通**（可选的 `provision`）：
  - 用户第一次带 token 访问时，在指定项目下创建 principal；
  - 在映射表里出现的每个项目上，把权限设成该用户所在组映射出的集合。离开组后，下一个 token 就会撤销相应权限。映射表里的项目，这些 principal 的权限完全由 IdP 决定。
  - 用户组变化时，或每隔 `sync_s` 秒同步一次。
  - 同步失败时：以前同步过的用户保留 IAM 现有的权限，只记警告；新用户被拒绝。
- **授权**：apiserver 按 token 缓存认证结果，直到 token 过期；按「principal、项目、权限」缓存授权结果。所以撤销会在授权缓存过期后生效，旧 token 也一样。
- **许可证**：要有覆盖 `sso` 功能的有效许可证。没有或过期时，IdP 的 token 被拒绝，集群照常运行，IAM token 不受影响。
- **测试**（`ee/sso`，用假的 IdP：TLS，提供 discovery 和 JWKS）：
  - 4 种签名算法都能通过；
  - 拒绝：`none`、用 RSA 公钥做密钥的 HS256、错误的 issuer 或 audience、已过期、没有 exp、还没生效、别的密钥签的、被篡改的、算法和密钥类型不匹配；
  - 密钥轮换：30 秒内不重新获取，之后获取一次并通过；
  - principal 名字的转换、点分路径取用户组、拒绝 http 的 issuer；
  - 没有许可证时拒绝 IdP 的 token，IAM token 不受影响；
  - 真实 IdP：Keycloak 26.4.2（在 bm1 上的临时虚拟机里，HTTPS、自签证书），`TestRealIdP` 用它签发的 access token 和 ID token 都通过：组成员自动开通为 `sso-alice` 并能创建 sandbox，不在组里的用户被拒，篡改的 token 被拒。Keycloak 的配置要点（audience mapper、group mapper）写在企业版文档里。
  - `TestSSOCluster`（本地集群）：组成员第一次访问就被开通并能创建 sandbox；开通的 principal 没有 IAM token；不在组里的用户被拒；离开组后的下一个 token 失去权限；伪造的 token 被拒；admin 的 IAM token 照常可用。

## 40. 审计日志导出（企业版，2026-10-23）

企业版的 `ee/auditexport` 扩展：把每台 apiserver 的审计日志（§14.4）在写入的同时送到 SIEM 或归档存储，并对记录做哈希链，删掉或改动任何一条都能查出来。配置和用法见企业版文档（`ee/README.md`，不在公开仓库里）。

- **开源版这边的改动**：`ext.Env` 新增 `AuditDir`、`AuditName`（审计日志的目录，以及文件名里的实例名），新增 `ext.SetupWith(env, conf)`。apiserver 用它启动扩展，`ext.Setup` 保留原样。
- **读取方式**：直接读本地审计文件，不用内存里的审计 sink（`ext.AuditSink`）。
  - 本地文件是唯一的来源。每个目标有自己的游标（文件名、偏移、序号、链值），存在 `<audit_dir>/.export`，送达后才前移。
  - 所以目标宕机、导出进程重启，都不会丢记录；一个目标出问题也不影响其他目标。
  - 只读完整的行：最后一行没写完的留到下次。当前文件有了后继文件后，读完它就转到下一个（apiserver 一次只写一个文件，轮换前会写完并刷盘）。
  - 游标所在的文件已被 apiserver 删掉（超出 `audit_keep`）时，插入一条 `_gap` 记录，说明「从某文件某字节到某文件之间的记录可能丢失」，然后继续。
- **导出格式**：在原记录末尾追加 `_node`、`_seq`、`_prev`、`_chain`，其中 `_chain = sha256(_prev + "\n" + 原记录)`。字段追加在最后，去掉它们就能逐字节还原原记录，所以能重新计算哈希。
  - 只改一条记录：它自己的链值对不上。
  - 删掉一条：序号出现缺口。
  - 改了记录又重算链值：下一条的 `_prev` 对不上。
  - 同一序号出现两条不同的记录：报冲突。
  - 同一条记录重复送达（送达后、存游标前重启）可以容忍。
- **目标**：
  - syslog：RFC 5424，facility 为 log audit；TCP 和 TLS 用 RFC 6587 的长度前缀分帧，UDP 每条一个包。
  - S3 兼容存储：自己实现 SigV4 签名，没有引入 SDK。每批写成一个 gzip 的 NDJSON 对象，按序号命名，重发会覆盖同一个对象。带 Content-MD5；配置 `retain_days` 时用 Object Lock 合规模式写入，到期前谁都删不了、改不了。
  - HTTP：POST NDJSON。
- **失败重试**：退避从 1 秒开始，最长 1 分钟。指标包括：滞后字节数、最后成功时间、送达条数、失败次数（`opendsec_ee_audit_export_*`）。
- **校验工具** `opendsec-audit verify FILE...`：按 apiserver 分组，报告范围、缺失的序号段、断开的链接、`_gap` 记录。有记录缺失或被改动时退出码为 1。
- **许可证**：要覆盖 `audit_export` 功能。在导出循环里检查，没有就每 2 秒再查一次，错误只记一条日志。
  - 发现的问题：`ext` 按名字顺序设置扩展，`audit_export` 排在 `license` 前面，所以在设置时检查许可证一定失败，导出永远不会开始。SSO 因为名字排在 `license` 后面，侥幸没有遇到这个问题。
- **测试**：
  - `TestExport`：没写完的行留到下次；跨文件轮换；按批导出；投递失败后游标不动，重试时送的是同样的记录；文件被删时产生 gap 记录；重复送达可以容忍；改动、删除、重算链值、冲突都能查出。
  - `TestExportFromNow`：`from: now` 时不导出已有的记录。
  - 三种目标：
    - syslog（TCP、TLS）检查报文格式和分帧；
    - HTTP：401 不算送达；
    - S3 用假服务检查对象键、Content-MD5、Object Lock 头、SigV4 头的格式和对象内容。
  - `TestS3Real`：SeaweedFS 4.48 的 S3 接口真实写入。用 boto3 读回内容一致；在开了 Object Lock 的桶里保留期是 COMPLIANCE 7 天，删除被拒绝（AccessDenied）。用工具校验下载的对象：原样的通过，改动一个字的报出第 2 条被改。
  - `TestExportCluster`：本地集群的真实 apiserver 审计日志，经 HTTP 送到收集端，5 条 CreateProject 都到了，链完整。

## 41. 用量统计（2026-10-23）

按项目、按天统计 sandbox 用了多少资源、用了多久，作为分账和容量规划的数据基础。定价、部门映射、账单导出这些各家客户不同的部分以后另做。

- **数据来源**：IAM 的配额租约。每个 sandbox 创建时预留一份租约，上面有项目、资源（cpu_cores、memory_mb、gpus）和预留时间；sandbox 结束时 edge 释放它。这是集群里唯一由 Raft 复制、并且覆盖所有结束方式的记录：主动停止、TTL 到期、edge 失联后对账释放，都会经过它。
- **计量**：租约释放时，把「资源 × 持有时长」按 UTC 午夜切开，记到它所属项目当天的行上：
  - 启动数，记在开始那天；
  - sandbox·秒、CPU 核·秒、内存 MB·秒、GPU·秒。
  - 用的是 Raft 命令自带的时间（`c.Now`），所有副本算出的结果完全一致。暂停期间也计：资源仍然为它保留着。
- **查询**：`GetUsage(project, from, to)`，要求 `project.admin`。返回项目自己和所有子项目的行，按天、项目排序，单位换算成小时和 GB。还没释放的租约在查询时临时算到当前时刻（只读，不写入状态）。
  - 公开 API 和 IAM 都新增了这个 RPC；apiserver 转发时 actor 用调用方；审计日志把它算作只读查询。
  - `opendsecctl usage [项目] [-from] [-to] [-daily] [-csv]`：默认按项目汇总这段时间，带合计行。
  - Python SDK `get_usage`。
- **存储**：状态里新增 `usage` 行（`<项目>|<日期>`），随 Raft 快照和单机模式的状态文件一起保存（单机模式在下一次持久化操作时写盘）。保留 400 天：每当新建一行时，删掉早于「命令时间 − 400 天」的行。保留天数是常量，所有副本删掉的行一致。
- **升级注意**：用量从全部 IAM 副本升级之后开始计。升级过程中由旧版本 leader 处理的释放不计。旧快照里没有用量数据，从空开始。
- **测试**：
  - `TestUsage`（IAM）：跨午夜的租约分到两天；运行中的算到当前时刻；包含子项目、不含其他项目；按日期过滤；没有 `project.admin` 被拒绝；快照恢复后数据不变；超过 400 天的行被删除。
  - `TestUsageReport`（e2e，经 apiserver）：已停止和运行中的 sandbox 都计入；CPU 核·小时恰好是 sandbox·小时的 2 倍（2 核），内存同理；没有权限被拒绝。
  - `TestPrintUsage`：命令行按项目汇总、按天、CSV 三种输出。

## 12. 已确认决定
1. 语言：Go（服务端 + sandbox agent），Python（SDK）；协议 gRPC。
2. placement 内嵌在 apiserver，代码上独立成包 `internal/placement`。
3. load 定义、`k=2`、`cpu_overcommit=8` 按 §3.4 默认值，全部可配置。
4. P1 单机多进程部署；地址全部来自配置，多机部署无需改代码。
5. `ttl_running_stop` = 空闲超时，另提供 `ttl_max` 绝对寿命上限。
6. **[已确认 2026-10-15]** 通用任务的主力后端从容器改为 Firecracker microVM（§19，偏离论文）；容器保留给 GPU 任务和没有 KVM 的节点。
7. **[2026-10-15]** 网络策略用 nftables + DNS 代理实现（论文用 eBPF）：按域名放行时放行的是解析出的 IP；默认拒绝私网和元数据地址；撤销规则立即切断已建立的连接（§20）。
8. **[2026-10-15]** 容器 sandbox 只保留 Docker 默认的 capability（再去掉 `CAP_MKNOD`），并加 seccomp 拒绝列表；microVM / 完整 VM 依靠 VM 边界，guest 里的 root 不受限制（§21）。
9. **[2026-10-15]** DAMON 放在 guest 内核里，宿主机内核不改（§19.13）。
10. **[2026-10-15]** 暂停中 sandbox 的内存默认仍全额计入（`paused_mem_charge = 1`），由运维决定是否超配；恢复只在节点内存压力下失败（§24）。
11. **[2026-10-15]** 预建池中的 sandbox 不计入 edge 容量；`pause_reclaim` 不自动修改宿主机的 `vm.swappiness`，而是在启动时报错（§22）。
12. **[2026-10-16]** 生产拓扑为 2 台 BM + 1 台小云主机（只做 IAM 的第三个仲裁副本）+ 托管 NAS + 私网 CLB，用 systemd 部署；IAM 备份不含配额租约，由对账重建（§27）。
