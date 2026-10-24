# 核心概念

这一页介绍使用 OpenDsec 时会遇到的全部概念：sandbox 和它的后端、生命周期与超时、会话、任务、镜像与快照、网络、项目与权限、错误。读完它再看 [Python SDK 参考](PYTHON_SDK.md) 和 [命令行参考](CLI.md) 会顺畅很多。

## 1. 整体结构

```
 Python SDK / opendsecctl / E2B SDK
              |  gRPC + TLS, bearer token
              v
     +-----------------+  auth, quota  +-----------------+
     |  apiserver x N  | ------------> |   IAM x 3       |
     |  (stateless)    | <------------ |   (Raft)        |
     +-----------------+               +-----------------+
         |        ^     snapshot       +-----------------+
         |        +------------------- |   watcher       |
         |  create, exec, files        +-----------------+
         v
     +----------+   +----------+   +----------+
     |  edge    |   |  edge    |   |  edge    |   one per compute node
     | sandbox  |   | sandbox  |   | sandbox  |
     +----------+   +----------+   +----------+
           \             |             /
            shared image store (NFS / CephFS / JuiceFS)
```

- **apiserver** 是唯一的入口。它不保存状态，可以部署任意多个，放在负载均衡后面。
- **IAM** 保存项目、身份、权限、配额和 token，3 个副本用 Raft 复制。
- **watcher** 每秒探测所有 edge，把各节点的容量和负载汇总成一份快照给 apiserver 调度用。
- **edge** 运行在每台计算节点上，负责创建和管理本机的 sandbox。apiserver 选好节点后，由 edge 根据本机实际的内存、磁盘和 CPU 压力做最终决定。
- **共享镜像库**挂在所有 apiserver 和 edge 节点上，存放镜像层和快照。

每个组件的内部实现见[组件实现](COMPONENTS.md)。

## 2. sandbox

sandbox 是一个隔离的执行环境：有自己的文件系统、进程空间、网络和资源限制。你可以在里面执行命令、读写文件、访问它里面运行的服务，用完后停止。

每个 sandbox 有：

| 属性 | 说明 |
|---|---|
| `id` | 形如 `<edge_id>.<随机串>`，例如 `node-a1.k3m9x...`。前半部分是创建它的节点 |
| `project` | 所属项目，资源计入这个项目的配额 |
| `principal` | 创建它的身份 |
| `edge_id` | 当前所在的节点。暂停的 sandbox 迁移到别的节点后，这里会变，`id` 不变 |
| `spec` | 创建时的规格：后端、镜像、资源、超时、网络规则、任务、标签等 |
| `state` | 当前状态，见下文 |
| `created_at`、`last_active_at`、`ended_at` | Unix 时间戳（秒） |
| `message` | 进入 `FAILED` 或 `STOPPED` 的原因，例如 `idle timeout (ttl_running_stop) reached` |

### 2.1 后端

创建时必须明确指定后端（`backend`），SDK 不会替你选。

| 后端 | 实现 | 启动 | 隔离 | 暂停时 | fork 与快照 | 适合 |
|---|---|---|---|---|---|---|
| `microvm` | Firecracker 虚拟机 + jailer | 冷启动约 0.1 s，从内存快照约 55 ms | 最强：独立内核，每个 VM 独立 uid | 拍快照后结束进程，内存全部释放；恢复约 50 ms | 支持，连同内存 | 默认推荐，运行不可信代码 |
| `container` | Linux 容器：overlayfs、cgroup v2、namespace、seccomp | 约 0.1 s | 共享宿主机内核 | 冻结进程；开启 `pause_reclaim` 时内存换到 swap | fork 只复制文件；`pack_diff` 制作镜像 | 构建镜像、性能敏感且代码可信 |
| `fncall` | 预先启动好的容器池 | 约 2 ms | 同 container | 同 container | 同 container | 大量短小的函数调用 |
| `fullvm` | QEMU 完整虚拟机 | 约 0.23 s | 虚拟机 | 停止 vCPU，内存保留 | 不支持 | 需要完整系统（镜像自己的 init）或 PCI 直通（GPU） |
| `sim` | 只模拟生命周期，不运行任何东西 | — | — | — | — | 测试和调度压测 |

集群实际提供哪些后端，取决于管理员在每台节点上启用了哪些（[配置参考](CONFIGURATION.md#edges-backends)）。没有 `/dev/kvm` 的机器只能提供 `container` 和 `fncall`。

### 2.2 资源

| 参数 | 含义 | 默认 |
|---|---|---|
| `cpu_cores_limit` | CPU 核数上限，可以是小数 | 1 |
| `memory_limit_mb` | 内存上限（MB）。microVM 的 guest 内存就是这个值 | 2048 |
| `disk_mb` | 可写盘大小（MB），0 表示用后端的默认值 | 后端的 `default_disk_mb`：quickstart 和示例配置是 microvm 2048、container 1024；配置里没写时为 10240 |
| `gpus`、`gpu_mode` | GPU 个数；`exclusive` 独占或 `shared` 共享 | 0 |
| `qos` | `LS`（延迟敏感）或 `BE`（尽力而为）。BE 的 sandbox 以最低的 CPU 调度优先级运行（cgroup `cpu.idle`），节点内存紧张时也优先从它回收 | `LS` |

节点按**超配后**的容量接收 sandbox：CPU 默认超配 8 倍（`cpu_overcommit`），内存默认不超配。调度时同时看「已分配」和「实际使用」，取较高的那个。

### 2.3 状态

```
                create
                   |
                   v
               CREATING ---- error ----> FAILED
                   |
                   v
      +------> RUNNING -----------------+
      |            |                    |
  RESUMING      PAUSING              STOPPING
      ^            |                    |
      |            v                    v
      +-------- PAUSED -------------> STOPPED
```

| 状态 | 说明 |
|---|---|
| `CREATING` | 正在创建：准备文件系统、网络，启动进程或虚拟机 |
| `RUNNING` | 正在运行，可以执行命令和读写文件 |
| `PAUSING`、`PAUSED` | 暂停中、已暂停。**对暂停的 sandbox 发起运行时调用（执行命令、读写文件、HTTP 等）会自动恢复它**，调用方不需要先调用 `resume` |
| `RESUMING` | 正在恢复 |
| `STOPPING`、`STOPPED` | 正在停止、已停止。停止后文件系统和进程都被清理，配额立即归还 |
| `FAILED` | 创建或运行中出错，原因在 `message` 里 |

已结束（`STOPPED`、`FAILED`）的记录在节点上保留 10 分钟（`stopped_retention`），这期间还能查到；`list_sandboxes(include_ended=True)` 会列出它们。

### 2.4 超时

每个 sandbox 有两个超时，都在创建时设置，单位秒：

| 超时 | 含义 | 默认 | 上限 |
|---|---|---|---|
| `ttl_running_stop`（空闲超时） | 运行中的 sandbox 连续这么久没有任何调用、也没有命令在执行，就自动停止 | 3600（1 小时） | 无 |
| `ttl_max`（最长寿命） | 从**创建时**算起，到这个时间就停止，暂停的时间也计入 | 86400（1 天） | 604800（7 天） |

- 0 表示用集群默认值；默认值和上限由管理员在 `admission` 里设置（[配置参考](CONFIGURATION.md#admission)）。请求的 `ttl_max` 超过上限会被拒绝（`invalid`）。
- **空闲**的判断：没有运行时调用正在进行，并且距离上一次调用超过了空闲超时。一条执行了两个小时的命令期间，sandbox 不算空闲。
- 暂停期间不计空闲时间：恢复后从零开始计。
- `touch()` 刷新空闲计时，不做别的事。
- **超时后暂停而不是停止**：设置 `ttl_paused_s`（目前通过 API 和 E2B 的 `autoPause` 使用）后，空闲超时或最长寿命到期时，sandbox 被暂停，再保留 `ttl_paused_s` 秒。这期间任何调用都会恢复它。
- E2B 的 `set_timeout` 对应 API `SetSandboxTimeout`：把最长寿命改为「当前已运行时间 + timeout」。

**用完请及时 `stop()`**：sandbox 停止之前一直占用项目配额。

## 3. 在 sandbox 里执行命令：会话

命令在**会话**（session）里执行。会话是 sandbox 里一个持续存在的 shell：

- 同一个会话里，`cd`、`export` 设置的当前目录和环境变量在命令之间保留；
- 默认会话叫 `default`，你可以用任意名字开新的会话，各会话互不影响；
- 会话第一次执行命令时确定它的用户（`user` 参数，名字或 `uid[:gid]`，默认 `init_user`，即 root），之后不能更换；
- `close_session()` 结束会话，并杀掉它启动的所有进程。

**把 agent 和评测分开**：让 agent 的命令在一个普通用户的会话里执行（例如 `session="agent", user="1000"`），评测在另一个 root 会话里执行。普通用户的会话连不上其他会话、看不到它们的输出记录，也改不了系统文件。评测要对 agent 保密的文件，请用严格的权限写（例如 `umask 077`）。

**命令输出的限制**：

- 每条命令的 stdout、stderr 各记录前 64 MB，超出的部分读出后丢弃（命令照常运行），丢弃的字节数在 `ShellResult.dropped_bytes` 里；
- 每个会话保留最近 512 MB 的输出记录，更早的被删除，之后用 `get_output` 取不到。

**超时**：`timeout` 到期时，这条命令启动的进程被杀掉，会话本身保留。

**断线**：执行命令期间 edge 或 apiserver 重启，SDK 会重新连接并取回结果，不会把命令执行两次；流式输出会从断开的位置继续，不重复也不丢失。

除了会话，sandbox 里还可以运行独立的**进程**（API 的 `StartProcess` 等，E2B 的 `commands.run` 就是用它实现的）：有自己的 pid、stdin、信号，可以分配 PTY；调用方断开不影响进程，之后可以重新连上。

## 4. 任务

创建 sandbox 时可以给它一个 `task_id`（例如一个强化学习训练任务的名字）。之后可以对同一个任务的所有 sandbox 一起操作：

| 操作 | 作用 |
|---|---|
| `pause_task` | 暂停任务的所有 sandbox。训练被抢占时使用：microVM 的内存全部释放，容器开启 `pause_reclaim` 时内存换到 swap |
| `resume_task` | 恢复所有暂停的 sandbox。不调用也可以：对单个 sandbox 的下一次调用会自动恢复它 |
| `stop_task` | 停止所有 sandbox，任务结束时使用 |

返回值里有成功和失败的个数，以及失败的原因。

## 5. 批量创建与 fork

- **批量创建**：`run_sandboxes(args, count)` 一次最多 32768 个，服务端按限流速率排队，不会部分失败于限流。结果按序号返回，失败的那几个是 `DSecError`。
- **fork**：`sb.fork(count=N)` 把一个运行中的 sandbox 复制成 N 个（最多 256 个），全部处于运行状态。
  - 源 sandbox 短暂暂停（microVM 约 10 ms），之后继续运行，`id` 和超时都不变。
  - 副本继承源的规格；可以加标签、换 `task_id`、设置自己的超时。
  - microVM 的副本连同内存一起复制：进程从 fork 那一刻的状态继续运行。每个副本有自己的 hostname、machine-id 和随机数种子。同一节点上的副本共享内存页。
  - container 的副本只复制文件系统，进程不复制。
  - 副本优先放在源所在的节点；放不下时放到其他节点，从源节点直接拉取快照。
  - 每个副本单独计入配额。

批量创建和 fork 都带幂等键：服务端重启导致连接中断时，SDK 重试只会补齐还没创建的那部分，不会多建。

## 6. 镜像与快照

sandbox 从**镜像**启动。镜像存放在共享镜像库里，名字形如 `<项目>/<名字>:<标签>`，例如 `root/py:3.12`、`root/rl/swe-4821:v1`。标签省略时为 `latest`。

| 怎么来的 | 做法 | 说明 |
|---|---|---|
| 从镜像仓库导入 | `opendsecctl image import` | 任意 OCI 仓库，包括 Docker Hub 和私有仓库；也可以导入 `docker save` 的文件 |
| 组合 | `compose_image` | 把几个镜像按顺序叠在一起（基础环境 + 代码仓库 + 工具），不复制数据 |
| 从 sandbox 制作 | `pack_diff`（container） | 只保存 sandbox 相对它启动镜像的改动，清掉 `/tmp`、缓存、shell 历史等构建残留 |
| 快照 | `create_snapshot` | 原样保存。microVM 必须带内存（`memory=True`），用它创建的 sandbox 从快照时的状态继续运行 |

镜像的权限按它所属的项目判断：发布（导入、组合、`pack_diff`、快照、删除）需要 `layer.publish`，使用（创建 sandbox、查看）需要 `layer.use`。详见[镜像与快照](IMAGES.md)。

## 7. 网络

sandbox 的网络**默认拒绝**：除非放行，否则什么都连不上。放行用 `network_rules`，键可以是：

- 规则集的名字（管理员定义，例如 `pypi` = `pypi.org` + `files.pythonhosted.org`）；
- 域名（含子域名），例如 `github.com`；
- IPv4 地址或网段，例如 `1.2.3.4`、`10.20.0.0/16`；
- `*`：所有公网地址。

后面可以加 `:端口[/协议]`，例如 `pypi.org:443`、`10.0.0.0/8:5432/tcp`。值为 `true` 放行，`false` 收回集群默认规则里放行的某一项。运行中可以用 `update_network()` 修改。

内网、链路本地和组播地址，只有用网段规则明确写出才能访问；通过域名解析得到的内网地址一律拦截。详见[网络策略](NETWORK.md)。

## 8. 项目、身份与权限

- **项目**组成一棵树，根是 `root`，例如 `root/team-a/rl`。sandbox 和镜像都属于某个项目。
- **身份**（principal）是调用方，有一个或多个 **token**（形如 `dsk.<id>.<secret>`）。种类有 `user`、`service`、`agent`，只用于区分，权限上没有差别。
- **权限**授予在项目上，并向下继承到子项目：

| 权限 | 允许 |
|---|---|
| `sandbox.create` | 在项目里创建 sandbox（包括 fork） |
| `sandbox.operate` | 操作项目里的 sandbox：查看、列出、执行命令、读写文件、暂停、恢复、停止、改网络 |
| `layer.use` | 使用项目里的镜像：用它创建 sandbox、查看镜像 |
| `layer.publish` | 发布项目里的镜像：导入、组合、`pack_diff`、快照、删除 |
| `project.admin` | 管理项目：建子项目、建身份、授权、发 token、查用量；在 root 上还包括集群操作 |
| `fleet.view`、`fleet.operate` | 在 root 上：查看、操作集群管理服务（升级、改配置） |

- **配额**设在项目上，按项目树逐级检查：子项目的用量同时计入所有祖先。配额键是 `sandboxes`、`cpu_cores`、`memory_mb`、`gpus`。
- **有界委托**：项目管理员只能授予自己拥有的权限，子项目的配额不能超过任何祖先的配额。

详见[项目、身份与权限](IAM.md)。

## 9. 错误

所有错误都带一个稳定的原因字符串（Python SDK 里是 `DSecError.reason`）：

| reason | 含义 | 怎么办 |
|---|---|---|
| `unauthenticated` | token 无效、过期或被撤销 | 换 token |
| `forbidden` | 没有所需的权限 | 看错误信息里缺哪个权限，找项目管理员授予 |
| `not_found` | sandbox、项目、镜像不存在，或 sandbox 已经清理 | — |
| `quota_exceeded` | 超出项目或某个祖先项目的配额 | 停掉不用的 sandbox，或申请调高配额 |
| `rate_limited` | 超出限流 | 退避后重试 |
| `no_capacity` | 集群暂时放不下（所有候选节点都满了或处于压力下） | 稍后重试，或减少并发 |
| `invalid` | 参数错误，例如超时超过上限、规则写错、后端不存在 | 看错误信息 |
| `unavailable` | 服务端正在重启或切换 | SDK 已自动重试，默认最长 60 秒 |
| `timeout` | 调用超时 | 加大 `timeout`，或检查集群负载 |
| `internal` | 服务端内部错误 | 记下时间和 sandbox id，查服务端日志 |

**哪些调用可以放心重试**：创建、批量创建和 fork 带幂等键，重试不会多建；执行命令带请求 id，重试不会执行两次；查询都可以重试。SDK 在 `unavailable` 时已经自动重试，其他原因由调用方决定。

**节点宕机**：sandbox 所在的物理机宕机时，上面的 sandbox 随之丢失，之后的调用返回 `not_found` 或 `unavailable`。需要长期保留的结果请及时取出。
