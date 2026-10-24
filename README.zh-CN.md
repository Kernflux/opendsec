# OpenDsec：面向智能体训练的 sandbox 基础设施

[English](README.md) | 中文 | [主页](https://kernflux.github.io/)

> **本项目借鉴自 DeepSeek 的 DSec 论文**：[*DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*](https://arxiv.org/abs/2609.22978)（arXiv:2609.22978）。
>
> - OpenDsec 是按照这篇论文描述的系统做的开源实现，整体架构和大部分设计都来自论文，详见下文「借鉴自 DSec 论文」。
> - 这是一个独立项目：**与 DeepSeek 没有任何关系，没有得到 DeepSeek 的认可，也不由 DeepSeek 维护**，不包含 DeepSeek 的代码。

设计与分阶段计划见 **[docs/SPEC.md](docs/SPEC.md)**。版本兼容策略见 [docs/VERSIONING.md](docs/VERSIONING.md)，各版本变更见 [CHANGELOG.md](CHANGELOG.md)。各组件的实现说明见 **[docs/COMPONENTS.md](docs/COMPONENTS.md)**。许可证：服务端和工具是 AGPL-3.0（[LICENSE](LICENSE)）；客户端部分，即 Python SDK（`sdk/python/`）、Go 客户端（`pkg/`）、API 定义和生成的代码（`proto/`、`gen/`），是 Apache-2.0，调用 OpenDsec 的程序不受 AGPL 约束。AGPL 不允许的用法（闭源修改、不公开修改就作为服务对外提供）和企业版需要商业授权，联系 zhyb1528@aliyun.com。详见 [NOTICE](NOTICE)；贡献代码需要签署 CLA，见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 借鉴自 DSec 论文

OpenDsec 是照着 DSec 论文做的。论文描述了 DeepSeek 用于智能体强化学习训练的 sandbox 基础设施，感谢论文作者把设计公开得如此详细。

**来自论文的部分：**
- **整体架构和组件名称**：
  - 无状态的 apiserver；
  - 带多级项目、配额和有界委托的 IAM；
  - 汇总调度状态的 watcher；
  - power-of-k 调度，由各节点上的 edge 做最终准入；
  - sandbox 内的 aether 和 chronus。
- **镜像**：分层、按需加载、组合，以及 `pack_diff`。
- **网络**：默认拒绝的网络策略，规则按 sandbox 设置。
- **后端**：容器、FnCall、microVM、完整 VM。
- **面向 RL 训练的功能**：
  - 按任务批量暂停和恢复，暂停时把内存换到 swap；
  - GPU 共享；
  - CPU QoS；
  - 核心调度；
  - EROFS 镜像盘；
  - 命令输出上限和按会话的用户。
- **Python SDK 的接口形式**。

[docs/SPEC.md](docs/SPEC.md) 把每一处设计都标成了 **[论文]**（注明论文章节）或 **[决定]**（我们自己的决定）。

**我们自己的部分**（论文没有说明，或者我们做了不同的选择）：
- **网络策略**：用 nftables 和 DNS 代理执行，论文用的是 eBPF。
- **镜像库**：用任意共享文件系统（NFS、CephFS、JuiceFS），论文用的是 3FS。
- **以 Firecracker 为主力后端**：加上内存快照、暂停即快照和 `fork`，接口形式参考了 [E2B](https://github.com/e2b-dev/infra) 的开源实现。
- **集群运维**：fleet 集群管理服务和节点代理、`opendsecops`、单机一键部署。
- **数据**：本文和 SPEC 里的所有数字都是我们在自己的机器上测的，不是论文里的数据。

**引用**：如果在研究中用到 OpenDsec，请引用它所实现的论文：*DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*，arXiv:2609.22978，2026。

「DeepSeek」和「DSec」归各自的所有者所有，本项目使用这两个名称只为指明所实现的论文。

## 单机部署（约 10 分钟）

一台 Linux x86_64 机器（在 Ubuntu 24.04 上测过；需要 systemd、cgroup v2，跑 microVM 还需要 `/dev/kvm`，没有的话只装容器）。下面每一步都以 root 执行：脚本要安装系统服务，生成的文件也放在 `/root/opendsec-ops`。

```sh
sudo -i                                      # 之后都以 root 执行
apt update && apt install -y make git python3-venv   # Debian、Ubuntu
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz   # Go 1.27 或更新
git clone https://github.com/kernflux/opendsec && cd opendsec
deploy/quickstart.sh                         # 或 --no-microvm 只跑容器
. /root/opendsec-ops/demo.env                # 调用方的地址、token、CA，以及 E2B SDK 用的变量
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
.venv/bin/python sdk/python/examples/quickstart.py
```

脚本会下载 Firecracker 和 guest 内核（按 `deploy/deps.lock` 校验），以 systemd 服务装好 IAM、watcher、apiserver、edge 和 E2B 网关，导入 `python:3.12` 镜像，创建项目 `root/demo` 和它的调用方，并各跑一个容器和 microVM sandbox 做检查。不想下载内核时，`--kernel FILE` 用现成的内核，`--build-kernel` 自己编译。在全新的 8 核虚拟机上整个过程约 11 分钟，大部分时间在编译。卸载：以 root 执行 `deploy/quickstart.sh --uninstall`。多机生产集群见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

**不能访问外网的机器**：在能上网的机器上做离线安装包（`deploy/offline/build-bundle.sh`），在目标机器上用 `./install.sh` 安装，单机和多机都支持，见 [deploy/offline/README.md](deploy/offline/README.md)。

**当前进度**：
- P1 管控面 + 调度、P2 真实容器运行时 + aether / chronus：已完成。
- 管控加固：edge 状态恢复、mTLS、token 生命周期、审计日志、IAM 高可用、watcher 多实例：已完成。
- 准入补强：默认 TTL 与上限、磁盘准入、按 principal 限流：已完成。
- P3 镜像部分：共享镜像库、OCI 导入、组合镜像、`pack_diff`：已完成。
- P3 网络策略（默认拒绝、按域名或网段放行、运行中修改，SPEC §20）与容器加固（capability、seccomp、只读和屏蔽路径，§21）：已完成。
- P4 RL 协同（§22）：容器暂停时把内存换到 swap、GPU 分配（独占或共享）、带预建池的 FnCall 后端（经 API 创建约 2 ms）、CPU QoS、解耦 rollout 示例：已完成。
- P5 QEMU 完整 VM 后端（§23）：PCI 设备直通、可用镜像自己的 init 作为 PID 1，启动约 0.23 s：已完成（VFIO 直通没有在真实设备上测过）。
- 两节点验证（§25）：NFS 共享镜像库、跨节点 fork、edge 宕机与恢复；突发创建 8192 个容器、5120 个 microVM，全部成功，宿主机挂载表恒定；一次批量创建 5120 个 microVM 用时 37 s。
- 断线续传、跨节点 fork、暂停 sandbox 换节点、指标（§26）：
  - SDK 在 edge 重启时自动续上命令和流式输出，命令不会重复执行；
  - fork 的快照留在源节点，其他节点直接从源节点拉取，到另一节点 fork 8 个副本从 1.47 s 降到 0.58 s；
  - 暂停的 microVM 在原节点排空或内存紧张时，用同一个 id 在别的节点恢复，512 MB 的 VM 约 0.35 s；
  - 各服务用 `-metrics` 输出 Prometheus 指标。
- 运维收尾（§24）：镜像库和镜像盘缓存的垃圾回收、磁盘 IO 限速、暂停 sandbox 的内存记账比例、内存紧张时给 balloon 充气、暂停内存文件打洞：已完成。
- Firecracker 主力后端 + 快照 / fork（SPEC §19）：
  - F0 已完成：fork / 快照接口、管控面、容器后端只含文件系统的 fork。
  - F1 已完成：microVM 冷启动，约 0.1 s，已在 KVM 裸金属机上验证。
  - F2 已完成：
    - 暂停时拍快照并结束进程，内存真正释放；恢复约 50 ms；
    - 从内存快照创建约 55 ms；
    - 带内存的 fork，同一节点上的副本共享内存页。
  - F3 已完成：
    - 增量快照：暂停和 fork 只写脏页，fork 时源 VM 只暂停约 10 ms；
    - 64 个副本并发恢复约 0.2 s，宿主机内存约为不共享时的十分之一；
    - `state_dir` 在 XFS 上时用 reflink 复制磁盘和内存；
    - 跨节点：快照拉到节点缓存，调度优先选有缓存的节点；
    - 容器 fork 链的层自动合并；
    - userfaultfd 按需拉页没有做（SPEC §19.12）。
  - F4 已完成（需要 `deploy/guest-kernel` 编出的 guest 内核，宿主机内核不用改）：
    - 镜像盘用 virtio-pmem + DAX，同一镜像的 VM 共享宿主机页缓存；
    - guest 释放的内存经 balloon 交还宿主机；guest 里的 DAMON 把冷内存换出到 zram；
    - 16 个闲置 VM 的宿主机内存降到不开时的 31%。

## 组件

| 二进制 | 作用 |
|---|---|
| `opendsec-iam` | 多级嵌套项目、有界委托、层级配额、配额 lease、token 生命周期；单机或 Raft 多副本（`-replica <id>`） |
| `opendsec-watcher` | edge 健康探测、调度状态汇总、驱动 IAM lease 对账 |
| `opendsec-apiserver` | 无状态入口；内嵌 placement（power-of-k、in-flight 叠加、云上弹性） |
| `opendsec-edge` | 节点本地准入（含内存压力）、sandbox 状态机、TTL、统计上报；sandbox 网络与网络策略（nftables + DNS 代理）；container / fncall 后端（overlayfs + ext4 可写盘 + cgroup v2 + namespace + seccomp）；microvm 后端（Firecracker + jailer，aether 走 vsock）；fullvm 后端（QEMU，vhost-vsock，VFIO） |
| `opendsec-aether` / `opendsec-chronus` | sandbox 内代理 / shell 会话（静态编译，以只读方式挂载进 sandbox） |
| `opendsecctl` | 命令行工具：本地集群、基准、sandbox / task / IAM 操作 |
| `sdk/python/opendsec` | Python SDK（异步） |

协议定义在 `proto/opendsec/v1/`（gRPC）。

## 快速开始

```sh
make build                       # 需要 Go 1.27+；修改 proto 后执行 make proto（需要 protoc）
./bin/opendsecctl cluster up -sim-edges 4
# 按输出设置环境变量：export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=root

./bin/opendsecctl project create root rl -quota sandboxes=100
./bin/opendsecctl sandbox create -backend container -cpu 2 -mem 4096 -task job-1 -project root/rl
./bin/opendsecctl sandbox create -backend container -count 500 -task job-1 -project root/rl
./bin/opendsecctl task pause job-1 -project root/rl
./bin/opendsecctl status
```

真实容器（需要 root、cgroup v2、overlayfs、mkfs.ext4）：

```sh
./bin/opendsecctl cluster up -sim-edges 1 -runtime linux     # 开发用 "host" 镜像：宿主机 / 作为只读底层
ID=$(./bin/opendsecctl sandbox create -backend container -image host -mem 256 | grep -m1 '"id"' | cut -d'"' -f4)
./bin/opendsecctl exec $ID -- 'cd /tmp && echo hello from $(hostname)'
./bin/opendsecctl cp ./main.py $ID:/work/main.py
```

`host` 镜像只用于开发。较新的内核（6.8 之后）不允许 overlay 的下层互相重叠：用 `host` 镜像的 sandbox 做 fork、快照或 `pack_diff` 时，镜像库（`-image-store`）要放在根文件系统以外的文件系统上。

部署方式（systemd / Kubernetes、证书签发、升级步骤）见 **[deploy/README.md](deploy/README.md)**。多进程部署的配置参考 `deploy/opendsec.example.json`；其中 `e003` 是真实容器 edge 的生产配置示例：`persist_state` + `keep_sandboxes_on_exit` 让 edge 重启或升级时不影响正在运行的 sandbox（重启后自动重新接管）。

```sh
opendsec-iam -config opendsec.json -replica 0 &   # 每个 IAM 节点各运行一个副本（单机模式不带 -replica）
opendsec-edge -config opendsec.json -id e001,e002 &
opendsec-watcher -config opendsec.json &
opendsec-apiserver -config opendsec.json -index 0 &
```

生产部署的安全配置（mTLS、对外 TLS、token 过期与吊销、审计日志）：

```sh
opendsecctl pki init -config opendsec.json -out /etc/opendsec/pki   # 集群 CA + 各组件证书；ca.key 请离线保存
# 在 opendsec.json 中设置 "tls": {"dir": "/etc/opendsec/pki"}，并为 apiserver 设置 "audit_dir"
export OPENDSEC_CA=/etc/opendsec/pki/ca.crt                      # opendsecctl / SDK 通过 TLS 连接 apiserver
opendsecctl token create -ttl 3600 -desc rollout-worker      # 签发短期 token
opendsecctl token revoke <principal> <token-id>              # 约 1 秒内在所有 apiserver 上失效
```

开发时可以用 `opendsecctl cluster up -tls -audit-dir ./audit` 一键启用以上配置。

Python SDK：

```python
from opendsec import DSecClient, DSecContainerRunArgs

async with DSecClient() as client:          # 读取 OPENDSEC_ADDR / OPENDSEC_TOKEN / OPENDSEC_PROJECT / OPENDSEC_CA
    sb = await client.run_container(DSecContainerRunArgs(
        container_image="registry.example/sphinx-9658:official",
        memory_limit_mb=4096, cpu_cores_limit=4, ttl_running_stop=300,
        network_rules={"npm": False, "pypi": True}, task_id="job-1"), timeout=120)
    r = await sb.run_shell("echo hello world")             # 持久会话：cd / export 在命令之间保留
    async for kind, data in sb.stream_shell("make test"):  # 流式输出
        ...
    await client.pause_task("job-1")        # RL 抢占时整批暂停；之后对暂停的 sandbox 发请求会自动恢复
    await sb.stop()
```

microVM（需要 `/dev/kvm`、firecracker + jailer、guest 内核，见 deploy/README.md）：

```sh
./bin/opendsecctl cluster up -sim-edges 1 -runtime linux -image-store /mnt/opendsec-images -microvm-kernel /opt/opendsec/vm/vmlinux-6.1.155
./bin/opendsecctl sandbox create -backend microvm -image root/python:3.12 -cpu 2 -mem 1024
```

## 使用 E2B SDK

E2B 网关（`opendsec-e2b`，SPEC §37）提供 E2B 的 API，按 E2B SDK 写的程序和基于它的 Agent 框架不用改代码就能在 OpenDsec 上运行：

```sh
export E2B_API_URL=http://<网关>:7400 E2B_SANDBOX_URL=http://<网关>:7400 E2B_API_KEY=<OpenDsec token>
python -c 'from e2b import Sandbox; print(Sandbox.create().commands.run("echo hi").stdout)'
```

- 启用方法：在集群配置里加 `e2b` 一节，写上网关地址、sandbox 所在的项目，以及各个 template（E2B 的 template id 对应哪个镜像、后端和资源；SDK 默认用 `base`）。然后给一台机器加上 fleet 角色 `e2b=<序号>`。详见 docs/OPERATIONS.md。`deploy/quickstart.sh` 在本机已经装好一个。
- 已支持：sandbox 的创建、查询、列出、删除、超时、暂停、重新连接；命令的输出、退出码、后台运行、stdin、信号、环境变量、工作目录；PTY；文件的读写、列目录、建目录、改名、删除；访问 sandbox 里其他端口上的服务（HTTP、流式响应、WebSocket），E2B 的 code interpreter 就靠这个。fork 和快照（`fork()`、`create_snapshot()`、`Sandbox.create(snapshot_id)`；microVM 上连内存一起）；autoPause；网络选项（`allow_internet_access`、`allow_out`、拒绝全部流量的 `deny_out`、`update_network()`）。E2B 官方的 Python SDK（同步和异步）和 JS/TS SDK 的验收检查全部通过。
- E2B 的 code interpreter（`e2b_code_interpreter`）：用 `deploy/e2b/build-code-interpreter.py` 构建的 template 即可使用（Python 内核）。它是内存快照，`Sandbox.create()` 约 280 ms，第一次 `run_code` 约 45 ms。
- 还不支持：监听目录、签名的文件 URL、不带 token（浏览器直接打开）访问 sandbox 端口、构建 template。
- **从 E2B 迁移**：[docs/E2B.md](docs/E2B.md) 列出了支持的功能、和 E2B 的差别，以及实测耗时。

## 镜像

```sh
# 共享镜像库：所有 edge 和 apiserver 都挂载的同一个目录（生产上可以是 CephFS / JuiceFS / NFS）
opendsecctl cluster up -sim-edges 1 -runtime linux -image-store /mnt/opendsec-images

# 从镜像仓库导入（在挂载了镜像库的机器上以 root 运行；需要 layer.publish 权限）
opendsecctl image import docker://python:3.12-slim -as root/rl/python:3.12 -store /mnt/opendsec-images
# 私有仓库：默认用本机 docker login 保存的凭据，也可以直接传入（密码或访问令牌从标准输入读）
echo "$HARBOR_TOKEN" | opendsecctl image import harbor.example.com/team/app:1.0 -as root/rl/app:1.0 \
    -store /mnt/opendsec-images -username 'robot$ci' -password-stdin
# 组合：base + workspace + toolkit 按顺序叠加，不复制数据
opendsecctl image compose root/rl/swe-4821:v1 root/rl/python:3.12 root/rl/django-ws:a1b2 root/tools/agent-kit:3
```

```python
sb = await client.run_container(DSecContainerRunArgs(container_image="root/rl/python:3.12"))
await sb.run_shell("git clone https://... /srv/repo && pip install -e /srv/repo")
img = await sb.pack_diff("root/rl/swe-4821:env")   # 把当前环境存成新镜像，/tmp、缓存、shell 历史会被清理
# 之后创建的 sandbox 直接用这个镜像启动，不必重复构建环境
```

fork 与快照（SPEC §19）：

```python
forks = await sb.fork(count=8, ttl_max=600)          # 8 个副本，从 sb 此刻的状态开始；失败的副本是 DSecError
img = await sb.create_snapshot("root/rl/swe-4821:step3")   # 原样保存（不清理 /tmp），可反复用来创建 sandbox
```

副本优先放在源 sandbox 所在节点，放不下时落到其他节点（直接从源节点拉取快照），每个副本单独计入配额。容器后端的 fork 只复制文件系统。microvm 后端的 fork 和快照包含内存：副本从源 sandbox 当时的进程和内存状态继续运行，每个副本有自己的 hostname、machine-id 和随机数。用 `create_snapshot(..., memory=True)` 生成的镜像创建 sandbox 时，直接从快照恢复，`memory_limit_mb` 要和快照一致。

权限：发布镜像（导入、组合、`pack_diff`、`create_snapshot`）需要对镜像所属项目有 `layer.publish`，使用镜像需要 `layer.use`。只给跑任务的账号 `layer.use`，即可实现「构建环境的账号」与「跑任务的账号」分离。

## 准入策略

配置里的 `admission` 段由每个 apiserver 执行（详见 SPEC §18）：
- **TTL**：请求没有设置时，空闲 TTL 默认 1 小时、生命周期默认 1 天；生命周期最多 7 天，超过返回 `invalid`。实际生效的值写在 sandbox 的 spec 里。
- **限流**：每个 principal 每秒 10000 次调用、2000 个创建（突发一整批 32768 个）。单个创建超速返回 `rate_limited`；批量创建在服务端按速率排队，不会部分失败。同一客户端地址认证失败过多时，暂停为它认证新 token。
- **磁盘**：edge 按每个 sandbox 的可写盘大小记账（默认不超配），并在 `state_dir` 所在文件系统空闲空间低于保留值时拒绝创建；placement 会避开磁盘不足或处于压力下的节点。

## 测试与基准

```sh
make test        # Go 单元测试 + 端到端测试（真实 gRPC，进程内集群；以 root 运行时包含真实容器测试）
make pytest      # Python SDK 测试（需先建 venv，见 sdk/python/gen.sh）
make bench       # opendsecctl bench -compare：对比随机放置与 power-of-2
```
