# 组件实现说明

本文逐个说明 OpenDsec 各组件是怎么实现的：职责、代码位置、内部机制、状态存在哪、出故障时怎么办。部署方式见 README「Deploy a cluster」和 [OPERATIONS.md](OPERATIONS.md)；每个设计决定的来由和实测数据见 [SPEC.md](SPEC.md)（文中的 §x 指 SPEC 的章节）。

## 0. 总览

```
调用方 (Python SDK / opendsecctl)
   │ gRPC + TLS, bearer token
   ▼
apiserver ×N（无状态，内嵌 placement）──► IAM ×3（Raft：身份、配额、键值区）
   │        ▲ 每秒取快照                       ▲ 对账
   │        watcher ×N（探测 edge，汇总调度状态）┘
   │ mTLS
   ▼
edge（每台计算节点一个，root）──► 后端：container / fncall / microvm / fullvm
   │ unix socket 或 vsock
   ▼
aether（sandbox 内 PID 1）──► chronus（每个 shell 会话一个）

fleet ×3 + nodeagent（每台机器）：发布、配置、分批升级
共享镜像库（NFS / CephFS / JuiceFS）：镜像层、清单、快照、microVM 镜像盘
```

源码目录：

| 目录 | 内容 |
|---|---|
| `cmd/opendsec-*` | 各组件的 main，只做参数解析和启动，逻辑都在 `internal/` |
| `internal/cluster` | 按配置把各组件组装起来并启动 gRPC 服务，`opendsecctl cluster up` 也用它 |
| `internal/config` | 集群配置（一个 JSON 文件）的结构、默认值和校验 |
| `proto/opendsec/v1` | 所有 gRPC 接口：`opendsec.proto`（公开 API）、`iam.proto`、`cluster.proto`（watcher 和 edge）、`runtime.proto`（aether）、`fleet.proto` |
| `gen/go`、`sdk/python/opendsec/_pb` | 由 proto 生成的代码 |

### 一次创建的完整路径

以 `client.run_sandbox(...)` 为例：

1. **SDK** 调 `CreateSandbox`，带上 token 和项目。多个 apiserver 地址时轮询，遇到 `unavailable` 换一台重试。
2. **apiserver**（`internal/apiserver/apiserver.go` 的 `place`）：
   1. 按 principal 限流，检查进行中的创建数；
   2. 补上默认 TTL，检查镜像存在且调用方有 `layer.use`；
   3. 生成一个 lease id，sandbox id 就是 `<edge>.<lease>`；
   4. **先选节点**：调内嵌的 placement 选出一台 edge；
   5. **再准入**：调 IAM `Admit`，一次完成认证、`sandbox.create` 鉴权和配额预留，预留的配额绑定到选中的 edge。
3. **IAM** 把预留作为一条命令经 Raft 提交：项目和它所有祖先的用量都加上这个 sandbox 的资源，任何一级超了就整体失败。
4. **edge** 收到 `CreateSandbox`，做最终准入：容量、内存、磁盘和 CPU 压力。不满足就返回 `no_capacity`。通过后它依次：
   1. 记录 sandbox 并落盘；
   2. 分配网络；
   3. 调后端创建；
   4. 状态改为 RUNNING 再落盘。
5. edge 返回 `no_capacity` 或 `unavailable` 时，apiserver 给这台 edge 记一个短暂的惩罚，换一台重试，最多 `max_attempts` 次（默认 3）。IAM 里同一个 lease 只是改绑到新 edge。全部失败时释放 lease。
6. 之后对这个 sandbox 的操作，apiserver 都从 id 里解析出 edge 直接转发，不需要查任何表。

## 1. apiserver

**职责**：集群唯一的入口。负责认证、鉴权、准入、调度，以及把请求转发到 edge。代码在 `internal/apiserver`。

- **无状态**：sandbox id 里编码了所在 edge，所以任意一台 apiserver 都能处理任意请求，挂掉重启不丢任何东西。唯一的例外是换过节点的 sandbox（§26.2），它们的新位置从 watcher 快照（edge 上报的 `moved_in`）和原 edge 的回答里恢复（`move.go`）。
- **认证缓存**：
  - token 到 principal 的认证结果、以及鉴权结果，各缓存 30 秒，不会超过 token 本身的有效期；
  - 后台每秒查一次 IAM 的「安全纪元」（security epoch）。吊销 token 或权限时纪元会变，变了就清空缓存，所以吊销约 1 秒内在所有 apiserver 上生效（§14.3）。
- **调度状态**：每隔 `snapshot_refresh` 向 watcher 取一次集群快照，交给内嵌的 placement。快照取不到时沿用上一份。
- **就绪**：15 秒内没收到 IAM 应答或 watcher 快照，`/readyz` 就返回失败，负载均衡据此把它摘掉。
- **准入策略**（`admission.go`，§18）：
  - 默认 TTL 和生命周期上限；
  - 按 principal 的令牌桶限流，批量创建在服务端排队，不会部分失败；
  - 进行中的创建数上限（默认 2048）；
  - 同一来源地址认证失败太多时暂停认证。
- **批量创建** `CreateSandboxes`：一次最多 32768 个，以流的形式逐个返回结果。
- **fork**（`fork.go`）：
  - 对源 sandbox 拍一次快照，再创建 count 个副本，一次最多 256 个；
  - 每个副本都是一次普通的创建（单独鉴权、单独计配额），优先放在源节点；
  - 放到其他节点的副本，直接从源 edge 拉快照文件。
- **镜像接口**（`images.go`）：
  - 登记、组合、删除镜像清单，直接写共享镜像库；
  - 写操作要求 `layer.publish`，使用要求 `layer.use`，这样「构建环境的账号」和「跑任务的账号」可以分开。
- **运行时操作**（`runtime.go`）：exec、文件、HTTP 都先鉴权 `sandbox.operate`，再转发给 edge，由 edge 转给 sandbox 里的 aether。sandbox 处于暂停状态时由 edge 自动恢复；原节点放不下时，把它迁到别的节点再恢复。
- **审计**（`audit.go`）：每个公开调用写一行 JSON，按大小轮转。
- **扩展点**（`ext`，§34）：
  - 扩展的认证器排在 IAM 之前，它认出的 token（例如 SSO 的）直接得到 principal，IAM 不经手这个 token；之后的鉴权、配额照常由 IAM 做，Admit 改为带上这个 principal。
  - 审计扩展在每行写进本地文件之后收到同一行。
  - 开源版不链接任何扩展，这些都不起作用。
- **fleet 代理**（`fleet.go`）：在公开端口上提供 `FleetAdmin`，鉴权 `fleet.view` 或 `fleet.operate` 后，把调用方身份带上转给 fleet。

## 2. placement（内嵌在 apiserver 里）

**职责**：为每个新 sandbox 选一台 edge。代码在 `internal/placement/placement.go`（§3.4）。

- **两步**：
  1. **过滤**：健康、不在排空、有这个后端、硬件匹配（GPU）、可分配容量够、有这个镜像；从快照创建时还要求运行时版本一致；
  2. **power-of-k**：从候选里均匀随机抽 k 台（默认 2），取负载最低的。
- **负载**取三项中的最大值：
  - 已分配资源占容量的比例；
  - 实际 CPU 使用率（edge 按 10 秒平滑）；
  - 实际内存使用率。

  实际用量低于 `usage_floor`（默认 0.2）时不计入，避免机器空闲时各自的底噪不同把调度带偏。
- **不用协调的并发**：每个 apiserver 把自己刚放下、还没出现在快照里的 sandbox 叠加到快照上（in-flight overlay），所以多个 apiserver 同时调度也不会都挤到同一台。
- **惩罚**：edge 拒绝过的节点短时间内降为最后选择。不是直接排除：所有节点都在重启时，试一台总比直接失败好。
- **位置偏好**：
  - fork 的副本优先放在源节点；
  - 从快照创建时，优先放在已缓存这个快照的节点。
- **云上弹性**：`zone` 只有 `onprem` 和 `cloud` 两种。本地利用率超过 `burst_threshold` 时，部分可上云的镜像按概率放到 cloud 区。
- **报错**：没有节点放得下时，会区分「镜像根本不存在」（`not_found`）和「有镜像的节点都满了」（`no_capacity`），并附上各节点被跳过的原因（内存、磁盘、CPU 压力，运行时版本不一致）。

## 3. IAM

**职责**：身份、项目、权限和配额。同时提供分布式锁，以及给其他组件存小量持久状态的键值区。代码在 `internal/iam`（§3.2、§15）。

- **数据模型**：
  - **项目**：多级嵌套，如 `root/team-a/rl`；配额未设置的项继承父项目；
  - **principal**：属于某个项目，可以有多个 token；
  - **token**：形如 `dsk.<id>.<secret>`，只存 secret 的哈希，可以设置过期时间，可以吊销；
  - **权限**：授予在项目上，对子项目也生效；委托有边界，不能授出自己没有的权限。
- **确定性命令**（`commands.go`）：
  - 每个状态变更都是一条 Command。时间、token id、secret 哈希这类不确定的值由提议方生成后写进命令，所以每个副本应用后结果完全一样。
  - 单机模式：命令直接应用，状态写入一个 JSON 文件。
  - 多副本模式（`raft.go`，hashicorp/raft + BoltDB）：命令经 Raft 复制。follower 收到请求原样转发给 leader（`service.go`），所以客户端连哪个副本都行。
- **配额 lease**：
  - 每个 sandbox 对应一个 lease，记录它的资源，并计入项目及所有祖先的用量；
  - `Admit` 一次完成认证、鉴权和预留；对同一个 lease 重复预留是幂等的（只改绑 edge）；
  - lease 绑定到 edge，edge 被判定丢失后，它名下的 lease 被释放。
- **对账**（`reconcile.go`，§15.2）：
  - watcher 定期把每台 edge 上实际存活的 lease 报给 IAM；
  - IAM 只提交差异：edge 上有但 IAM 没有的收养回来，IAM 有但 edge 上没有的释放；
  - 刚创建、还没超过 `reconcile_min_age` 的 lease 不会被释放；
  - 平时的释放由 edge 发起：sandbox 结束后，edge 把它的 lease 放进队列，攒满 1000 条或等 50 ms 后用 `ReleaseLeases` 一次释放，一批只占一个 Raft 提交，所以一次停掉上百万个 sandbox 也不会堵住 IAM（§31）；
  - 长期没有任何 edge 认领的 lease 由 `SweepUnbound` 清掉。
- **锁**：带 TTL 的命名锁，watcher 和 fleet 用它选 leader。
- **键值区**（`kv.go`，§28.3）：
  - 只接受固定前缀（如 fleet 的节点、版本和升级记录）；
  - 每次写入分配一个全局递增的 revision，支持比较后写入；
  - IAM 不解释其中的内容。它和其余状态一起复制、一起备份。
- **备份和恢复**（`ops.go`）：gzip 的 JSON，含 principal、项目、token 哈希、安全纪元和键值区。不含 lease（恢复后由对账重建）。
- **成员变更**：`opendsecctl iam member add/remove`，新副本带 `-join` 启动后等待被加入（§27.2）。
- **自举**：第一次启动时，用配置里的 admin token 建出 root 项目和管理员。token 还是示例里的占位值（`change-me`）时拒绝启动。

## 4. watcher

**职责**：探测 edge 的健康，汇总调度状态，驱动配额对账。代码在 `internal/watcher/watcher.go`（§3.5）。

- **没有持久状态**：重启后从三个来源重建视图：配置里的 edge 列表、edge 定期的注册，以及轮询 edge。
- **探测**：
  - 每 `probe_interval`（默认 1 秒）并发调用每台 edge 的 `Status`；
  - 连续失败 3 次判为不健康；
  - 返回的 edge id 和预期不符也算失败。
- **快照**：每轮探测后生成一份带版本号的快照，包含每台 edge 的容量、已分配资源、实际用量、压力状态、已缓存的快照和运行时版本，供 apiserver 拉取。
- **多实例**：所有实例都探测，都能提供快照。只有持有 IAM 锁的那个实例做对账：锁每 TTL/3 续一次，本地按「请求时刻 + TTL − 2 秒」判断自己是否仍是 leader，所以和 IAM 的时钟偏差不会让两个实例同时对账。
- **对账**：每 `reconcile_interval`（默认 30 秒）做一次。
  - 健康的 edge：取它的存活 lease 交给 IAM 对账；
  - 不健康超过 `lost_edge_grace`（默认 120 秒）的 edge：按「已空」对账，释放它的配额。它带着 sandbox 回来的话，下一轮会收养回来；
  - 每台 edge 独立对账，一台连不上只跳过它自己。
- **注册鉴权**：开启 mTLS 时，edge 只能注册它自己（证书身份必须一致）。

## 5. edge（节点控制面）

**职责**：节点上的控制面。负责最终准入、sandbox 状态机、TTL 回收、存活探测、资源释放，向 watcher 上报，把运行时调用转给 aether。代码在 `internal/edge`，以 root 运行。

- **状态机**：CREATING → RUNNING ⇄ PAUSING/PAUSED/RESUMING → STOPPING → STOPPED，失败进入 FAILED。每个 sandbox 有一把操作锁，同一时间只做一个生命周期操作。
- **最终准入**（`create`）：按 sandbox 记账的容量（CPU、内存、磁盘、GPU、各后端的数量上限），另外三项压力检查：
  - 内存：MemAvailable 低于保留值，默认是总内存的 10%，至少 128 MB；
  - 磁盘：`state_dir` 所在文件系统的空闲空间；
  - CPU：PSI，可选。

  edge 是否接收由它自己说了算：placement 用的快照可能已经过时。
- **持久化和接管**（`store.go`、`recover.go`，§13）：
  - 每个存活的 sandbox 一个记录文件，写入方式是临时文件 → fsync → rename；
  - 创建时先落盘再调后端，所以 edge 在创建过程中崩溃，重启后也知道这个 sandbox 存在；
  - 创建完成时先问 IAM 这个 lease 绑在哪里（§36）：调用方已经放弃、改到别的 edge 创建，或者 lease 已经释放，就当场删掉这个 sandbox，不留孤儿；问不到 IAM 时保留；
  - 启动时、开始服务之前：RUNNING 和 PAUSED 的 sandbox 交给后端重新接管，其余的标为失败并释放；后端再清理节点上没有任何记录对应的残留（cgroup、进程、磁盘、网络）；
  - 配合 `keep_sandboxes_on_exit` 和 systemd 的 `KillMode=process`，edge 重启或升级不影响正在运行的 sandbox。
- **后台循环**（`Run`）：
  - 回收 TTL 到期的 sandbox：空闲超时 `ttl_running_stop`，总时长 `ttl_max`；
  - 探测后端存活；
  - 清理已结束的记录；
  - 内存紧张时给有 balloon 的 sandbox 充气（`balloon.go`，§24）：先挤尽力而为（best-effort）级别的、再挤空闲最久的，每轮收回四分之一，最多收回一半；节点宽裕后放气。
- **运行时调用**（`runtime.go`）：
  - 每次调用都会：sandbox 暂停中就先恢复（对调用方透明）；刷新空闲 TTL；调用进行期间不让空闲回收打断。
  - 然后经后端拿到 aether 的 gRPC 连接并转发。
- **上报**：`Status` 返回容量、已分配资源、实际用量和压力状态（`host/usage.go` 读 `/proc/stat`、`/proc/pressure/cpu`、`/proc/meminfo`，CPU 按 10 秒平滑）。对账时还附带存活的 lease。edge 也定期向 watcher 注册自己（`RegisterLoop`）。
- **节点之间**（`move.go`、`peerfile`，§26）：
  - 快照文件留在拍摄它的节点，其他节点需要时直接来拉；
  - 传输时只发非零数据：内存文件和磁盘大部分是空洞，接收方也保持为空洞；
  - 暂停的 sandbox 可以换节点：新节点用同一个 id 恢复，原节点放手后才算完成，期间不会两边都跑。
- **指标**：`internal/edge/metrics.go`，抓取时实时读取。

### 后端接口

`internal/edge/backend/backend.go` 定义所有后端都要实现的 `Backend` 接口：`Create`、`Stop`、`Pause`、`Resume`、`Probe`。另有一组可选能力，按需实现：

| 接口 | 作用 |
|---|---|
| `Runtime` | 返回 sandbox 里 aether 的 gRPC 连接 |
| `LossReporter` | 自己发现 sandbox 死亡（与 aether 的连接断开）时通知 edge |
| `Snapshotter` / `Packer` | fork、快照、`pack_diff` |
| `Networked` | 需要 sandbox 网络 |
| `ImageLister` | 只能跑本地固定的镜像（开发用） |
| `Versioned` | 报告运行时版本，例如 firecracker 1.17.0 |

`sim` 后端只模拟生命周期，供调度测试和 `cluster up -sim-edges` 使用。

## 6. 容器后端（container、fncall）

代码在 `internal/edge/backend/container`（§11.2、§21）。

- **根文件系统**：
  - 下层：镜像层在节点本地的副本（`layercache.go`，§33.1）：每一层第一次用到时从镜像库整层复制到 `<state_dir>/<edge>/layers/<层 id>`，节点上的所有容器后端共用。运行中的容器因此不再读镜像库，镜像库（NAS）中断时它们不受影响。
    - 层不可变，副本按层 id 区分；
    - 没有 sandbox 在用、6 小时没用过的副本由 edge 清理；
    - `layer_cache: false` 恢复为直接叠在镜像库的层上（按需加载，读到哪个文件才取哪个）；
  - 上层：每个 sandbox 一块稀疏的 ext4 镜像文件（`disk.go`），挂在 loop 设备上，大小即 `disk_mb`。

  这块盘在 sandbox 自己的 mount namespace 里挂载，不在宿主机上挂。否则每多一个 sandbox，宿主机挂载表就多一项，每个新 namespace 都要复制它，几千个 sandbox 时每次启动会慢约 0.1 秒。
- **启动方式**：和 runc 一样「重新执行自己」。edge 以特殊的 argv[0] 再启动一次自己的二进制，这个进程就是 sandbox 的 setup 进程（`init.go`），在新的 mount/pid/uts/ipc/net/cgroup namespace 里依次：
  1. 挂上可写盘和 overlay，再挂 proc、只读的 sys，以及 sandbox 自己的 cgroup（让里面的 Go、JVM 能按限额调整自己）；
  2. pivot_root 切到 sandbox 的根，设置 hostname；
  3. 按 `sandboxfs` 把内核接口设为只读或屏蔽（默认值和 Docker 一致），再加上调用方指定的路径；
  4. 降低 agent 的 OOM 分数：内存打满时被杀的是 sandbox 里的进程，不是 agent；
  5. 最后装上 seccomp 过滤器，丢掉多余的 capability（Docker 的默认集合再去掉 CAP_MKNOD），然后 exec aether 作为 PID 1。
- **资源**：cgroup v2，代码在 `linuxrt/cgroup.go`。
  - CPU、内存、pids 都有限额，可选磁盘 IO 限速；
  - BE 级别的 sandbox 设置 `cpu.idle`；
  - 每个 sandbox 有自己的核心调度 cookie（`linuxrt/coresched.go`，§29.1），不同 sandbox 不会同时跑在一个物理核的两个超线程上，既防止互相干扰，也挡住 SMT 侧信道。
- **暂停**：用 cgroup freezer 冻结。开启 `pause_reclaim` 时，再用 `process_madvise(MADV_PAGEOUT)` 把内存换到 swap，恢复时提前读回（`linuxrt/reclaim.go`，§22.1）。
- **GPU**（`linuxrt/gpu.go`）：
  - 独占模式：分配整张卡；
  - 共享模式：在没有独占使用者的卡上分配一个槽位。
- **快照和 `pack_diff`**：只含文件系统。拍快照时把可写层冻结成一个新的镜像层。`pack_diff` 会清理 /tmp、缓存和 shell 历史。容器的 fork 不带内存。
- **fncall**：同一个实现加一个预热池（`pool.go`，§22.3）。配置里列出的镜像会预先启动若干个 sandbox，请求到达时直接取一个，再设置它的限额、网络和 id。经 API 创建约 2 ms。

## 7. microVM 后端（Firecracker）

代码在 `internal/edge/backend/microvm`（§19）。这是主力后端。

- **每个 sandbox 一个 Firecracker 进程**，由 jailer 启动：
  - 独立的 chroot；
  - 每个 sandbox 一个 uid；
  - 新的 network/IPC/UTS namespace，进入 sandbox 自己的 cgroup。
- **磁盘**：所有 VM 共用一个 guest 内核，每个 VM 挂四块盘：
  1. **agent 盘**：只读，装着 aether 和 chronus（`BuildAgentDisk`）；
  2. **镜像盘**：只读，把镜像各层压平成一块盘（`disks.go` 的 `ImageCache`）。同一组层只做一次，节点上所有用这个镜像的 VM 共用；可以用 virtio-pmem + DAX，让它们共享宿主机的页缓存。开启 `erofs_images` 时，镜像盘是 EROFS，在镜像库里只构建一次：第一个需要它的节点构建，靠 `vmdisks/<key>.lock` 排他，其他节点只是复制过来（`images/vmdisk.go`，§29.4）；
  3. **可写盘**：sandbox 自己的，稀疏 ext4；
  4. **配置盘**：很小，guest 读完就卸载，所以从快照恢复的 VM 可以换一块新的。
- **guest 里**：aether 以 `--vm-init` 作为 PID 1，先组装根文件系统，再在 vsock 上提供和容器相同的 Runtime API（`internal/agent/aether/vminit.go`、`vsock.go`）。按配置开启 zram、DAMON 冷页回收和空闲页上报（`vmmem.go`）。
- **网络**：采用 Firecracker 的「克隆网络」布局：每个 VM 在自己的 netns 里用同名 tap 设备和同一个 guest 地址，由 netpol 在 netns 里做地址转换。这样从快照恢复的副本不用改 guest 里的网络配置。VM 暂停时没有 VMM 进程，由一个最小的占位进程保持 netns（`linuxrt/netnsholder.go`）。
- **暂停 = 拍快照并结束进程**（`Pause`）：
  1. 暂停 vCPU；
  2. 第一次拍完整快照，之后只拍脏页增量（Diff），合并进上一份内存文件（`diff.go`）；
  3. 结束 Firecracker 进程，内存真正还给宿主机；
  4. 内存文件里的零页打洞释放空间。

  恢复时在新进程里 restore，约 50 ms。
- **从快照创建、fork**（`createRestored`）：快照的文件硬链接进 jail。快照在别的文件系统或别的节点上时，先拉一份到节点本地（`snapcache.go`），之后同一节点的所有副本都链接这一份，共享页缓存。restore 之后，aether 收到 `PostRestore`，给副本新的时钟、随机数种子、hostname 和 machine-id（`aether/restore.go`）。
- **存活检测**：edge 与 aether 之间保持一条 `Watch` 流，流断了就算 sandbox 丢失。edge 重启后通过 `Adopt` 重新连上已经在跑的 VM。
- **指标**：每次创建按阶段（准备、网络、配置盘、启动或恢复）记录耗时。

## 8. 完整 VM 后端（fullvm，QEMU）

代码在 `internal/edge/backend/fullvm`（§23）。

- 每个 sandbox 一个 QEMU 进程（q35 机型，KVM），盘的布局和 microVM 一样，挂在 virtio-pci 上，aether 走 vhost-vsock。
- 和 microVM 的区别：有完整的 PCI 总线，可以用 VFIO 直通 GPU（还没在真实设备上测过）；开启 `full_init` 时用镜像自己的 `/sbin/init`（systemd）作为 PID 1。
- 暂停只停 vCPU，内存不释放；没有内存快照，也不能 fork。由 QMP 控制（`qmp.go`）。

## 9. 网络策略（netpol）

代码在 `internal/edge/netpol`（§20、§29.2）。论文用 eBPF，这里用 nftables。

- **拓扑**：每个 sandbox 有自己的 network namespace，用一对 veth 连到宿主机，分到 edge 子网（默认 10.88.0.0/16）里的一个 /30。microVM 在 netns 里再接 tap。
- **默认拒绝**：每个 edge 一张 nftables 表（`nft.go`）。
  - 发往 sandbox 的新连接一律丢弃，包括来自其他 sandbox、宿主机和外部的；应答包放行。
  - sandbox 发出的每个包进入它自己的链，按 veth 和源地址匹配，伪造源地址匹配不上，直接丢弃。已建立的连接也走这条链，所以收回一条规则会立刻切断相关连接。
  - 链里依次：放行允许的网段；丢弃私网、链路本地和组播地址；放行 DNS 代理解析出的地址；其余丢弃。
- **按域名放行**：edge 自带一个 DNS 代理（`dns.go`）。
  - 允许的域名（含子域名）才转发给上游，应答里的 IPv4 地址在 sandbox 拿到应答之前就加入它的放行集合；
  - 其他域名返回 NXDOMAIN；AAAA 查询返回空应答（sandbox 只有 IPv4）；
  - 代理按查询的源地址区分是哪个 sandbox。
- **规则**（`rules.go`）：
  - 可以是域名、IPv4 网段、集群配置里命名的规则集（如 `pypi`），或 `*`（所有公网地址）；
  - 每条规则可以限定协议和端口范围，每种端口组合对应一个 nftables 集合；
  - sandbox 运行中可以修改规则（`UpdateNetwork`）。
- **性能**：每个 sandbox 的规则通过 netlink 直接下发（`nl.go`）。`nft` 和 `ip` 命令每次都会重读整个规则集或复制挂载表，几千个 sandbox 时一次要 100–300 ms；只有 edge 的基础规则在启动时用 `nft` 设置一次。

## 10. 镜像库（images）

代码在 `internal/images`（§17、§24、§29）。镜像库是一个所有 edge 和 apiserver 都挂载的共享目录：

```
<root>/layers/<id>/rootfs/...      镜像层，overlay 格式（删除标记是 0:0 字符设备）
<root>/layers/<id>/meta.json
<root>/images/<项目>/<仓库>/<tag>.json   镜像清单：层列表、env、workdir、user
<root>/snapshots/<id>/             快照（文件系统层 + microVM 的内存和状态）
<root>/vmdisks/<key>.erofs         microVM 的 EROFS 镜像盘
<root>/inuse/<holder>              运行中 sandbox 使用的层（供 GC 判断）
```

- **层不可变**：写入时先写到临时目录，再整体 rename 成最终目录。清单同样是临时文件加 rename。
- **导入**（`oci.go`）：`opendsecctl image import` 直接从 OCI 仓库拉取（Docker Hub 是默认仓库），镜像层可以是 gzip、zstd 压缩或不压缩的。删除标记还原成 0:0 字符设备，这一步需要 root。
- **私有仓库**（`auth.go`，§35）：凭据来自 `-username` 加 `-password-stdin`，或者 docker login 保存的配置文件；支持令牌服务（Basic 认证换令牌）、identity token（OAuth2 refresh token）和仓库直接要求的 Basic 认证。跳转到其他主机或端口（CDN、对象存储）时不带凭据。
- **不透明目录**（`opaque.go`）：overlay 用 xattr `trusted.overlay.opaque` 标记不透明目录，NFS 不传这个 xattr。所以入库时把不透明目录展开：对下层能看到、而本层没有的每个名字，写一个删除标记。
- **组合**：一个镜像就是层的列表，`compose` 把几个镜像的层按顺序拼起来，不复制任何数据。
- **合并**（`merge.go`）：容器 fork 链太长时，把多层压成一层；压出的层仍是 overlay 格式，叠加效果与原来的多层相同。
- **GC**（`gc.go`）：清单、快照记录或运行中的 sandbox 还引用的层和快照都保留；其余超过宽限期的删除，中断的写入也一并清理。
- **自检**（`storecheck.go`）：`opendsecctl image store-check` 在目录里逐项试一遍镜像库需要的能力：root 不被映射成普通用户、chown、排他创建、rename、硬链接、0:0 设备、overlay 叠加等。

## 11. sandbox 内的 agent：aether 和 chronus

代码在 `internal/agent`。两者都静态编译，每个版本放在 `/opt/opendsec/agents/<版本>/` 下，以只读方式挂进 sandbox。已经在跑的 sandbox 继续使用启动时挂载的那一版。

- **aether**（`aether/aether.go`）：每个 sandbox 一个，通常是 PID 1。
  - edge 只和它通信：容器里走 unix socket，VM 里走 vsock。
  - 它按会话 id 把调用转给负责该会话的 chronus，第一次用到时启动；会话关闭时杀掉 chronus 的整棵进程树（`proctree`）。
  - 文件读写、目录列表和 sandbox 内发起的 HTTP 请求也一样转给会话的 chronus，所以它们以会话的用户身份执行，相对路径按会话的当前目录解析。
  - `Watch` 流让 edge 知道它还活着。
  - **进程接口**（`procs/`，§37）由 aether 自己管理，不经过会话：每个命令是一个独立进程，按 pid 或 tag 寻址，可以写 stdin、发信号、用 PTY。流断开不影响进程，可以重新连上。用户切换和环境变量复用 chronus 的 `Environ`。E2B 网关用它实现 envd 的进程接口。
- **chronus**（`chronus/`）：每个 shell 会话一个进程，持有一个常驻的 shell，所以 `cd`、export 的变量和函数在命令之间保留。
  - 命令输出写进记录文件，调用方可以断开后再按偏移量取（`GetOutput`），也可以流式接收（`ExecStream`）。
  - 每条命令有请求 id：SDK 重试时能找到已经在跑的命令，不会重复执行。
  - 它是子进程收割者（subreaper）：命令里放到后台的进程也留在会话的进程树里，关闭会话时一起清掉。
  - 输出上限（`record.go`，§29.3）：每个流最多记录一定字节，超出的部分读出后丢弃（结果里有 `dropped_bytes`）；每个会话的记录总量也有上限，超了先删最早结束的命令的记录。
  - 会话可以指定运行身份（`user`），不同会话可以是不同用户（§29.3）。

## 12. fleet 和 nodeagent（集群管理）

代码在 `internal/fleet`、`internal/nodeagent`、`internal/release`（§28）。

- **release**（`release.go`）：一个版本就是一个目录，包含：
  - `bin/`：各组件和 firecracker、jailer；
  - `agents/`、`units/`、`vm/`（guest 内核）；
  - `deps.lock`：固定版本的运行时依赖；
  - `SHA256SUMS`：其余每个文件的校验和。

  `opendsecctl fleet release pack` 打包。推送到 fleet 后，每个副本在本地保存一份 tgz。
- **fleet**：3 个副本，持有 IAM 锁 `fleet-controller` 的是 leader，其他副本把请求转给它。
  - 期望状态都存在 IAM 键值区，随 IAM 复制和备份：节点列表（角色、故障域、目标版本、配置代数）、各版本、各次升级。
  - 节点心跳是软状态，只保存在 leader 内存里。
- **控制器**（`controller.go`）：leader 定期执行一轮 `tick`，给落后的节点下发操作，推进进行中的升级：
  - 每个节点一个步骤，状态依次是 pending → staging（下载版本）→ staged → applying（切换版本、写配置、按顺序重启）→ verifying（等本机 `/readyz` 和 watcher 快照都正常）→ ok。
  - 先升管控节点，一台一台来，IAM leader 所在的节点最后；然后 edge 先升一台试点，观察 bake 时间后再按批推进，每批里同一故障域的机器有上限。
  - edge 升级前先排空（drain），升级后恢复调度。每批开始前检查：已升级的机器仍然正常，所有管控组件就绪；配置了 PromQL 门槛（`gates`）时一并检查。
  - 应用或验证阶段失败：这台机器退回原版本并被锁定（pinned），整个升级暂停，等人决定继续、回滚还是中止。
- **nodeagent**（`agent.go`）：每台机器一个，root 运行。
  - 每 10 秒向 fleet 上报一次（版本、单元状态、正在执行的操作），从应答里领取操作。
  - 只接受五种操作：`stage`、`apply`、`restart`、`start`、`stop`。只改 `/opt/opendsec`、`/etc/opendsec`（限白名单内的文件）和 OpenDsec 自己的 systemd 单元，不做任何自主决定。
  - fleet 全挂时它什么都不改，组件和 sandbox 照常运行。
  - 运行的是 `/opt/opendsec/agent/` 下的独立副本，不随版本切换；新版本里的 nodeagent 先通过 `-check` 自检，才会替换它。
- **opendsecops**（`deploy/prod/opendsecops`）：运维机上的 bash 工具，用于首次安装、签证书、加机器和应急，通过 ssh 操作各节点（inventory 里地址写 `local` 的节点直接在本机执行）。

## 13. 安全和 RPC 基础设施

代码在 `internal/pki`、`internal/rpcutil`（§14）。

- **组件之间用 mTLS**：
  - 每个组件实例一张证书，身份写在 URI SAN `opendsec://<角色>/<id>` 里；
  - 每个 gRPC 服务有一张 ACL，规定哪些角色可以调用哪些方法（`security.go`）。比如只有 apiserver 能调 IAM 的 `Admit`，edge 只能注册它自己。
  - 开发模式下可以改用共享的 service token，不按调用方鉴权。
- **公开端口**：apiserver 用服务端 TLS，调用方带 bearer token。apiserver 证书里有固定名字 `api.opendsec.internal`，SDK 按地址直连多台 apiserver 时用这个名字校验证书。
- **错误原因**：所有错误在 `ErrorInfo.reason` 里带一个稳定的字符串，例如 `no_capacity`、`quota_exceeded`、`not_found`、`unavailable`。SDK 和重试逻辑按它判断，不解析错误消息。
- **连接**：
  - 服务端：每 20 秒 ping 空闲连接，防止负载均衡按空闲超时掐断安静的流；
  - 内部客户端：每 30 秒 ping；重连退避上限 2 秒，edge 重启后能很快重新连上；
  - 连接池：按地址复用连接。
- **CA 轮换**：分三步，不停服（`opendsecops rotate-ca`，见 OPERATIONS.md）。

## 14. 客户端

- **Python SDK**（`sdk/python/opendsec/client.py`）：基于 grpc.aio 的异步接口。
  - `OPENDSEC_ADDR` 可以写多台 apiserver，SDK 用 round-robin 分发请求并避开坏掉的。
  - 遇到 `unavailable` 在 `retry_timeout` 内按退避重试。
  - `run_shell` 带请求 id，重试不会重复执行命令；`stream_shell` 断线后按已收到的偏移量续传，不丢也不重复。
  - 调用方要显式选择后端，SDK 不在后端之间做抽象。
- **Go 客户端**（`pkg/client`）：给 `opendsecctl` 和端到端测试使用。
- **opendsecctl**（`cmd/opendsecctl`）：
  - 公开 API 的命令行，包括 sandbox、exec、cp、镜像、IAM、fleet；
  - 本地工具：`cluster up`（进程内集群）、`bench`、`pki`、`image store-check`、`fleet release pack`。

## 15. 指标

代码在 `internal/metrics`（§26.3）。每个二进制用 `-metrics :<端口>` 提供：

- `/metrics`：Prometheus 格式；
- `/healthz`：进程存活；
- `/readyz`：能否服务，并返回不就绪的原因。

主要指标：

- 各 RPC 的次数和耗时（按方法和错误原因）；
- apiserver 创建的耗时和失败原因；
- placement 的重试次数；
- edge 各后端的 sandbox 数、容量和用量、各创建阶段的耗时；
- fleet 和 nodeagent 的状态；
- `opendsec_build_info`：运行的版本。

告警规则在 `deploy/monitoring/alerts.yml`。

## 16. E2B 网关（opendsec-e2b）

代码在 `internal/e2b`、`cmd/opendsec-e2b`（§37）。让 E2B 的 SDK 不改代码就在 OpenDsec 上运行。

- **两套接口共用一个端口**：
  - E2B 的管理接口（REST，`api.go`）：创建、查询、列出、删除、超时、暂停、重新连接；
  - 网络选项和 refresh（`network.go`）：对应 `network_rules` 和 `UpdateNetwork`；autoPause 对应 `ttl_paused_s`；
  - fork 和快照（`snapshots.go`）：对应 `ForkSandbox` 和 `CreateSnapshot`，快照就是网关项目里的镜像，`snapshotID` 是镜像名；
  - E2B 在 sandbox 里的 envd 接口（`envd.go`）：进程和文件服务走 Connect 协议，`/files` 走 HTTP。

  带 `E2b-Sandbox-Id` 请求头，或者主机名是 `<端口>-<id>.<域名>` 的请求属于 envd。
- **不保存状态**：每个请求都用调用方自己的 token（E2B 的 API key）调 apiserver，所以权限、配额和审计都照旧。唯一的缓存是 sandbox 创建时带的环境变量，保留 1 分钟。
- **对应关系**：
  - E2B 的 template 对应集群配置里 `e2b.templates` 的镜像、后端和资源；
  - metadata 和 envVars 存进 `e2b.` 前缀的标签；
  - sandbox id 的 `.` 换成 `-`；
  - 超时用 `SetSandboxTimeout`。
- **部署**：fleet 角色 `e2b=<序号>`，单元 `opendsec-e2b@`，`/readyz` 在 9467 端口。单元以 `DynamicUser` 运行，只通过 `LoadCredential` 拿到集群配置和 CA 证书。

