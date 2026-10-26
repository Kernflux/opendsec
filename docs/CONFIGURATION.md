# 集群配置参考

整个集群共用一份 JSON 配置文件，部署后在每台节点的 `/etc/opendsec/opendsec.json`。所有组件都读它，各自取用与自己相关的部分。这一页逐个说明它的字段和默认值。

- 完整的生产示例：`deploy/prod/cluster.example.json`；单机安装生成的配置在 `/root/opendsec-ops/opendsec.json`。
- 时长字段的单位都是**秒**（可以是小数）。
- 大部分数值字段写 0 或不写表示用默认值；有些字段写 -1 表示关闭，下表会注明。
- 修改配置：由 fleet 管理的集群用 `opendsecctl fleet config put` 和 `fleet rollout create -config-gen <代数>` 下发（见[运维手册 §6.2](OPERATIONS.md)）；还没交给 fleet 的用 `opendsecops push-config all` 和 `opendsecops restart`。
- 校验一份配置：`opendsecctl pki init -config <文件> -out $(mktemp -d)`，能通过说明格式和约束都没问题。

## 顶层结构

```json
{
  "tls":            { ... },   // 组件间 mTLS 和公共 API 的 TLS
  "service_token":  "...",     // 仅开发：没有 TLS 时组件间的认证
  "iam":            { ... },
  "watcher":        { ... },
  "apiserver":      [ ... ],
  "placement":      { ... },
  "admission":      { ... },
  "image_store":    { ... },
  "network":        { ... },
  "edges":          [ ... ],   // 逐台列出的 edge
  "edge_template":  { ... },   // 其他所有 edge（新加的机器、Kubernetes）
  "fleet":          { ... },
  "e2b":            { ... },
  "extensions":     { ... }    // 构建里包含的扩展（开源版没有）
}
```

`tls.dir` 和 `service_token` 至少设置一个，生产环境必须用 `tls`。

## tls

| 字段 | 说明 |
|---|---|
| `dir` | 证书目录，例如 `/etc/opendsec/pki`。里面是 `ca.crt` 和各组件的 `<角色>-<id>.crt`、`.key`（`opendsecctl pki init` 或 `opendsecops certs` 生成）。设置后组件之间使用 mTLS，公共 API 使用 TLS |

## service_token

开发集群用：没有 TLS 时，组件之间用这个共享密钥认证。生产集群不要设置；交给 fleet 下发的配置里不能有它。

## iam

| 字段 | 默认 | 说明 |
|---|---|---|
| `replicas` | — | Raft 副本列表，每项 `{"id", "addr", "raft_addr", "data_dir"}`。设置后 `addr` 和 `state` 不再使用，并且必须设置 `admin_token` 或 `admin_token_file` |
| `replicas[].id` | — | 副本 id，唯一，不能含 `/`、`.`、空格 |
| `replicas[].addr` | — | gRPC 地址，例如 `10.0.0.1:7001` |
| `replicas[].raft_addr` | — | Raft 复制地址，例如 `10.0.0.1:7011` |
| `replicas[].data_dir` | — | Raft 日志和快照目录，例如 `/var/lib/opendsec/iam`，放在本地 SSD 上 |
| `addr` | — | 单副本（不复制）时的地址 |
| `state` | 内存 | 单副本时的状态文件；不设置则只在内存里，重启丢失 |
| `admin_id` | `admin` | 自举时创建的管理员身份 |
| `admin_token` | — | 管理员 token，格式 `dsk.<admin_id>.<secret>`。含 `change-me` 的占位值会被拒绝 |
| `admin_token_file` | — | 从这个文件读管理员 token，配置文件里就不必写密钥。只有 IAM 节点需要这个文件 |
| `root_quota` | 不限 | root 项目的配额，例如 `{"sandboxes": 10000}` |
| `max_token_ttl_s` | 0（不限） | 签发的 token 最长有效期。设置后不能再签发永不过期的 token |

管理员 token 只在 IAM 第一次启动（自举）时使用：创建 `admin_id` 这个身份，在 root 上授予全部权限。

## watcher

| 字段 | 默认 | 说明 |
|---|---|---|
| `replicas` | — | 多个 watcher，每项 `{"id", "addr"}`。全部都探测 edge、提供快照；持有 IAM 锁的那个负责对账 |
| `addr` | — | 单个 watcher 时的地址 |
| `probe_interval` | 1 | 探测每个 edge 的间隔 |
| `probe_timeout` | 0.5 | 单次探测的超时 |
| `unhealthy_after` | 3 | 连续失败几次判定为不健康 |
| `reconcile_interval` | 30 | 与 IAM 对账配额的间隔 |
| `reconcile_min_age` | 60 | 比这个更新的租约在对账时不会被释放 |
| `lost_edge_grace` | 120 | edge 不健康超过这么久，释放它上面 sandbox 的配额 |
| `unbound_max_age` | 600 | 没有任何 edge 认领的租约，过这么久后释放 |
| `lock_ttl` | 10 | 对账锁的租期 |

## apiserver

数组，每项是一个 apiserver 实例；`opendsec-apiserver -index N` 运行第 N 项。

| 字段 | 默认 | 说明 |
|---|---|---|
| `addr` | — | 监听地址，例如 `10.0.0.1:7100` |
| `audit_dir` | 关闭 | 审计日志目录，例如 `/var/log/opendsec/audit` |
| `audit_max_mb` | 256 | 单个审计日志文件达到这个大小后轮转 |
| `audit_keep` | 8 | 保留的文件个数（包括当前文件），最旧的先删 |
| `audit_runtime` | false | 也审计运行时调用（执行命令、文件、HTTP、进程、端口）和只读查询（查看、列出 sandbox，集群状态，项目、用量、token 列表）。默认审计其余全部调用：创建、fork、停止、暂停、恢复、改网络、镜像发布和删除、项目、身份、权限、token、集群操作。执行命令只记录命令的长度和 SHA-256，不记录命令内容 |
| `snapshot_refresh` | 1 | 从 watcher 刷新集群快照的间隔 |

## placement

调度参数，每个 apiserver 执行。

| 字段 | 默认 | 说明 |
|---|---|---|
| `k` | 2 | power-of-k：每次随机取 k 个候选节点，选负载最低的 |
| `max_attempts` | 3 | 被 edge 拒绝后换节点重试的次数 |
| `reject_penalty` | 2 | 拒绝过的节点在这段时间内被降低优先级 |
| `overlay_grace` | 2 | 刚放上去的 sandbox 在快照反映出来之前，按这么久计入节点负载 |
| `usage_floor` | 0.2 | 节点实际的 CPU、内存使用率低于这个比例时不计入负载（主机自身的基础占用）；-1 表示总是计入 |
| `burst_threshold` | 0.8 | 只对 `burst_eligible_images` 里的镜像、`container` 后端生效：本地（`onprem`）节点的利用率超过这个比例后，按超出的程度以一定概率优先放到 `zone: cloud` 的节点上；没超过时云上节点只作为本地放不下时的后备。≤0 关闭 |
| `burst_eligible_images` | — | 允许放到云上节点的镜像（这些镜像的层已同步到云上）。其他镜像和后端从不放到云上节点 |

## admission

每个 apiserver 执行的准入策略。超时字段：0 表示用内置默认值，-1 表示不设。限流按每个身份、每个 apiserver 实例计算（N 个 apiserver 合计最多是 N 倍）；-1 关闭。

| 字段 | 默认 | 说明 |
|---|---|---|
| `default_ttl_running_stop_s` | 3600 | 请求没有设置空闲超时时使用 |
| `default_ttl_max_s` | 86400 | 请求没有设置最长寿命时使用 |
| `max_ttl_max_s` | 604800（7 天） | 请求允许的最长寿命，超过返回 `invalid` |
| `request_rate` | 10000 | 每个身份每秒的调用数（包括执行命令和文件调用） |
| `request_burst` | 2 × `request_rate` | 突发 |
| `create_rate` | 2000 | 每个身份每秒创建的 sandbox 数 |
| `create_burst` | 32768 | 突发：允许一整个批量请求立即开始 |
| `auth_fail_rate` | 5 | 每个客户端地址每秒允许的认证失败次数，超过后暂时不再为它认证新 token |
| `max_inflight_creates` | 2048 | 每个 apiserver 同时进行的创建数 |

单个创建超速返回 `rate_limited`；批量创建在服务端按速率排队，不会因为限流部分失败。apiserver 在负载均衡后面时，请让负载均衡保留客户端源地址，否则认证失败会全部算到负载均衡的地址上。

## image_store

| 字段 | 说明 |
|---|---|
| `root` | 共享镜像库的挂载点，例如 `/mnt/opendsec-images`。所有 apiserver 和 edge 节点都要在同一路径挂载。没有设置时只能使用 edge 上配置的本地镜像（`edges[].images`） |

文件系统的要求见[镜像与快照 §5](IMAGES.md)。

## network

全集群的网络策略。

| 字段 | 说明 |
|---|---|
| `rule_sets` | 规则集：名字 → 目标列表（域名、IPv4 地址或网段，可带 `:端口[/协议]`）。例如 `{"pypi": ["pypi.org", "files.pythonhosted.org"], "github": ["github.com", "codeload.github.com", "objects.githubusercontent.com"]}` |
| `default_rules` | 每个 sandbox 默认带的规则，sandbox 自己的 `network_rules` 叠加在上面。例如 `{"*": true}` 让所有 sandbox 默认能访问公网，`{"pypi": true}` 默认只放行 PyPI |
| `upstream_dns` | edge 上 DNS 代理使用的上游解析服务器，默认用宿主机的 `/etc/resolv.conf` |

规则的语法和行为见[网络策略](NETWORK.md)。

## edges 与 edge_template

`edges` 逐台列出 edge；`edge_template` 用于没有列出的 edge（`opendsec-edge -id <id>` 启动时找不到同名项就用模板）。新加的机器通常不必写进 `edges`。

| 字段 | 默认 | 说明 |
|---|---|---|
| `id` | — | edge id，只能是 `[a-z0-9-]`，1 到 32 个字符；`edges` 里必填 |
| `addr` | — | 监听地址，例如 `0.0.0.0:7201` |
| `advertise` | 实际监听的地址 | 向 watcher 登记的地址 |
| `zone` | `onprem` | `onprem` 或 `cloud`，只能是这两个值。`cloud` 的节点只在本地负载超过 `burst_threshold` 时使用 |
| `capacity` | 自动 | `{"cpu_cores", "memory_mb", "gpus", "disk_mb"}`。有真实后端时：`cpu_cores` 和 `memory_mb` 都不写则取本机的 CPU 数和内存总量（只写其中一个时另一个不会自动填）；`disk_mb` 不写则取 `state_dir` 所在文件系统的大小。超配倍数在此基础上计算 |
| `cpu_overcommit` | 8 | CPU 超配倍数 |
| `mem_overcommit` | 1 | 内存超配倍数 |
| `disk_overcommit` | 1 | 可写盘超配倍数 |
| `mem_reserve_mb` | 自动 | 本机 MemAvailable 低于这个值时拒绝创建。0 表示自动（内存的 10%，至少 128 MB）；-1 关闭 |
| `disk_reserve_mb` | 自动 | 状态目录剩余空间低于这个值时拒绝创建。0 表示自动（文件系统的 5%，至少 1024 MB）；-1 关闭 |
| `cpu_pressure_limit` | 0（关闭） | CPU 压力（`/proc/pressure/cpu` 的 some avg10，百分比）高于这个值时拒绝创建。批量创建本身也会推高压力，请按本机的实测值设置，例如 50 |
| `paused_mem_charge` | 1 | 暂停时释放了内存的 sandbox（microVM；开了 `pause_reclaim` 的容器）仍按这个比例计入内存占用，取值 0 到 1 |
| `persist_state` | 有真实后端时开启 | 把 sandbox 记录写到磁盘，edge 重启后重新接管 |
| `keep_sandboxes_on_exit` | false | edge 退出时不停止 sandbox。滚动升级需要开启 |
| `stopped_retention` | 600 | 已结束的 sandbox 记录保留多久 |
| `state_dir` | `/var/lib/opendsec` | sandbox 的磁盘、快照、记录放在这里，应当是本地 NVMe；XFS 可以用 reflink 复制 |
| `agent_dir` | edge 程序所在目录 | `opendsec-aether` 和 `opendsec-chronus` 所在的目录 |
| `images` | — | 本地静态镜像：镜像名 → overlay 下层目录列表（最上层在前）。有共享镜像库时一般不需要 |
| `network` | 关闭 | sandbox 网络，见下文 |
| `gpu` | — | GPU 设备，见下文 |
| `backends` | `{"sim": {...}}` | 这台 edge 提供的后端，见下文 |

### edges[].network

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | false | 启用 sandbox 网络。关闭时 sandbox 只有回环接口 |
| `subnet` | `10.88.0.0/16` | sandbox 地址池，每个 sandbox 占一个 /30 |
| `dns_port` | 15353 | edge 的 DNS 代理在宿主机上的端口 |

同一台机器上运行多个 edge 时，它们的 `subnet` 和 `dns_port` 要各不相同。

### edges[].gpu

| 字段 | 说明 |
|---|---|
| `devices` | GPU 设备节点，例如 `["/dev/nvidia0", "/dev/nvidia1"]`。`capacity.gpus` 默认是设备个数 |
| `extra` | 每个 GPU sandbox 都需要的其他设备，例如 `/dev/nvidiactl`、`/dev/nvidia-uvm` |
| `mounts` | 以只读方式挂进 sandbox 的宿主机文件或目录（驱动库、`nvidia-smi`） |
| `shared_slots` | `gpu_mode: shared` 时每块卡最多几个 sandbox，默认 4 |
| `pci` | 直通给 `fullvm` sandbox 的 PCI 设备，例如 `["0000:3b:00.0"]`（VFIO） |

### edges[].backends

后端名 → 后端配置。后端名就是创建时 `backend` 的取值，例如：

```json
"backends": {
  "microvm":   {"runtime": "firecracker", "max_sandboxes": 4000, "default_disk_mb": 2048,
                "kernel": "/opt/opendsec/current/vm/vmlinux-6.1.167-opendsec",
                "firecracker": "/opt/opendsec/current/bin/firecracker",
                "jailer": "/opt/opendsec/current/bin/jailer",
                "image_pmem": true, "erofs_images": true, "free_page_reporting": true, "cold_age_s": 120},
  "container": {"runtime": "linux", "max_sandboxes": 8000, "default_disk_mb": 1024},
  "fncall":    {"runtime": "linux", "max_sandboxes": 4000, "default_disk_mb": 1024,
                "warm_pool": {"root/py:3.12": 64}}
}
```

通用字段：

| 字段 | 默认 | 说明 |
|---|---|---|
| `runtime` | `sim` | `linux`（容器）、`firecracker`（microVM）、`qemu`（完整虚拟机）、`sim`（模拟） |
| `max_sandboxes` | — | 这个后端在本机最多同时运行几个 sandbox |
| `default_disk_mb` | 10240 | 请求没有设置 `disk_mb` 时的可写盘大小 |
| `disk_io` | 不限 | 每个 sandbox 的磁盘 IO 上限：`{"read_mbps", "write_mbps", "read_iops", "write_iops"}`，0 为不限 |
| `core_sched` | 内核支持时开启 | 每个 sandbox 一个核心调度 cookie：两个 sandbox 不会同时运行在同一个物理核的两个超线程上，关闭超线程侧信道，也让延迟敏感的 sandbox 不受 BE 负载干扰。`true` 要求内核支持，`false` 关闭 |

`linux` 运行时（container、fncall）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `pids_max` | 4096 | 每个 sandbox 的进程数上限 |
| `pause_reclaim` | false | 暂停时把内存换出到 swap，恢复时提前读回。需要宿主机有 swap，且 `vm.swappiness` 大于 0 |
| `warm_pool` | — | 镜像 → 预先启动的个数（fncall 后端）。没有快照、用户、工作目录、路径限制、GPU，并使用默认磁盘的请求直接取一个，几毫秒就能用 |
| `layer_cache` | true | 容器使用镜像层在节点本地的副本（首次使用时复制），镜像库（NFS）中断时运行中的容器不受影响 |

`firecracker` 运行时（microvm）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `kernel` | 必填 | guest 内核（vmlinux）路径 |
| `firecracker`、`jailer` | PATH 上的同名程序 | Firecracker 和 jailer 的路径 |
| `uid_base` | 1000000000 | 每个 VM 以独立的 uid 运行，取自 `[uid_base, uid_base+65536)` |
| `vm_overhead_mb` | 64 | 加在 guest 内存上作为 VM 的 cgroup 内存上限（VMM 自身、页表、设备缓冲） |
| `erofs_images` | false | 镜像以 EROFS 盘的形式在镜像库里构建一次，复制到各节点，而不是在每个节点上展平成 ext4。需要支持 EROFS 的 guest 内核和节点上的 `mkfs.erofs`（erofs-utils） |
| `image_pmem` | false | 镜像以 virtio-pmem 挂载并用 DAX：同一镜像的 VM 共享宿主机页缓存 |
| `free_page_reporting` | false | guest 释放的内存通过 virtio-balloon 还给宿主机 |
| `cold_age_s` | 0（关闭） | 大于 0 时，guest 里的 DAMON 把闲置这么久的内存换出到压缩的 zram |
| `zram_pct` | 100 | zram 大小，占 VM 内存的百分比（0 到 400） |
| `cold_boot_dirty_tracking` | true | 冷启动的 VM 记录脏页，暂停时只写改动过的页。`false` 时内存写入更快（宿主机大页），但第一次暂停或快照要写全部内存 |

`image_pmem`、`free_page_reporting`、`cold_age_s` 需要 OpenDsec 的 guest 内核（`deploy/guest-kernel`，发布在 GitHub Release）。

`qemu` 运行时（fullvm）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `qemu` | PATH 上的 `qemu-system-x86_64` | QEMU 路径 |
| `kernel` | — | guest 内核 |
| `full_init` | false | 把 PID 1 交给镜像自己的 `/sbin/init`（aether 在旁边运行） |

`sim` 运行时：`create_latency_ms`（创建耗时的中位数，对数正态分布）、`latency_sigma`、`failure_rate`，用于调度压测。

## fleet

集群管理服务，可选。

| 字段 | 默认 | 说明 |
|---|---|---|
| `replicas` | — | 每项 `{"id", "addr", "data_dir"}`；`addr` 例如 `10.0.0.1:7300`，`data_dir` 默认 `/var/lib/opendsec/fleet` |
| `heartbeat_s` | 10 | 节点代理上报的间隔 |
| `lock_ttl` | 10 | leader 锁的租期 |
| `max_downloads` | 64 | 每个副本同时提供的版本下载数 |
| `keep_releases` | 10 | 除了正在使用的，额外保留的版本数 |
| `edge_port` | 7201 | edge 在节点私网地址上监听的端口 |
| `ready_ports` | iam 9461、watcher 9462、apiserver 9463、edge 9464、fleet 9465、e2b 9467 | 各角色的 `/readyz` 端口，节点代理重启服务后用它判断就绪 |
| `prometheus_url` | — | 发布闸门使用的 Prometheus 地址 |
| `gates` | — | 发布闸门：`[{"name", "query", "max"}]`。观察期内和每批开始前，每个 PromQL 的值都必须不大于 `max`，否则暂停；读不出来也暂停，没有样本按 0 处理 |

```json
"fleet": {
  "replicas": [{"id": "0", "addr": "10.0.0.1:7300"}, {"id": "1", "addr": "10.0.0.2:7300"}, {"id": "2", "addr": "10.0.0.3:7300"}],
  "heartbeat_s": 10,
  "prometheus_url": "http://10.0.0.3:9090",
  "gates": [{"name": "create errors", "query": "sum(rate(opendsec_apiserver_create_seconds_count{reason!=\"ok\"}[5m]))", "max": 1}]
}
```

## e2b

E2B 兼容网关，可选。

| 字段 | 默认 | 说明 |
|---|---|---|
| `gateways` | — | 网关实例：`[{"addr", "tls_cert", "tls_key"}]`。`addr` 例如 `10.0.0.1:7400`；`tls_cert` 和 `tls_key` 要么都设置（网关自己提供 HTTPS），要么都不设置（明文 HTTP，在前面的负载均衡上终止 TLS） |
| `project` | 有网关时必填 | sandbox 创建在这个项目里。请求可以用 `X-OpenDsec-Project` 头指定别的项目 |
| `domain` | — | 返回给 SDK 的 sandbox 域名，SDK 会访问 `<端口>-<id>.<domain>`（需要泛域名解析和证书指向网关）。不设置时客户端设置 `E2B_SANDBOX_URL` |
| `templates` | — | E2B template id → sandbox 规格。SDK 默认用 `base`。含 `/` 的 template id 直接当作镜像名，其余设置取 `default_template` |
| `default_template` | — | 同上，作为默认值 |
| `max_timeout_s` | 0（只受准入上限约束） | sandbox 超时的上限 |

template 的字段：

| 字段 | 默认 | 说明 |
|---|---|---|
| `image` | 必填 | 镜像 |
| `backend` | `microvm` | 后端 |
| `cpu` | 2 | CPU 核数 |
| `memory_mb` | 512 | 内存。镜像是带内存的快照时必须和快照一致 |
| `disk_mb` | 后端默认 | 可写盘 |
| `start_cmd` | — | 每个新 sandbox 里用 `bash -l -c` 启动的命令（E2B template 的 start command） |
| `ready_port` | — | 交给调用方之前等这个端口开始监听 |
| `ready_timeout_s` | 60 | 最多等多久 |

详见[从 E2B 迁移](E2B.md)。

## 各组件的启动参数

一般由 systemd unit（`deploy/systemd/`）传入，不需要手动设置。

| 程序 | 参数 |
|---|---|
| `opendsec-iam` | `-config`、`-replica <id>`（复制模式下运行哪个副本）、`-join`（新副本：不自举，等 `opendsecctl iam member add` 加入）、`-metrics`、`-log` |
| `opendsec-watcher` | `-config`、`-replica <id>`、`-metrics`、`-log` |
| `opendsec-apiserver` | `-config`、`-index <N>`（运行 `apiserver` 数组的第 N 项）、`-drain-delay`（收到 SIGTERM 后先让 `/readyz` 失败、继续服务这么久，默认 6s）、`-grace`（再给进行中的调用这么久，默认 30s）、`-metrics`、`-pprof`、`-log` |
| `opendsec-edge` | `-config`、`-id <id>[,<id>...]`（`all` 表示配置里的全部；没有列出的 id 用 `edge_template`）、`-addr`、`-advertise`、`-metrics`、`-pprof`、`-log` |
| `opendsec-fleet` | `-config`、`-replica <id>`、`-metrics`、`-log` |
| `opendsec-e2b` | `-config`、`-index <N>`、`-ca`（默认 `tls.dir/ca.crt`）、`-drain-delay`（默认 5s）、`-metrics`、`-log` |
| `opendsec-nodeagent` | `-config`（默认 `/etc/opendsec/opendsec.json`）、`-name`、`-addr`、`-fleet`、`-root`（默认 `/opt/opendsec`）、`-check`、`-metrics`、`-log` |

`-metrics <地址>` 同时提供 `/metrics`、`/healthz` 和 `/readyz`。各角色的默认端口见[监控与告警](MONITORING.md)。
