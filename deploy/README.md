# OpenDsec 部署

- **单机试用**：`sudo deploy/quickstart.sh`（见仓库 README），一台机器上装好全部组件并跑通一个 sandbox。
- **多机生产集群**：`deploy/prod/opendsecops` + [docs/OPERATIONS.md](../docs/OPERATIONS.md)。
- **Kubernetes**：`k8s/` 下的清单是**实验性**的，没有在真实集群上验证过，也还没有 fleet 和节点代理；镜像需要自己用 `Dockerfile` 构建。

| 文件 | 用途 |
|---|---|
| `quickstart.sh` | 单机部署、检查和卸载 |
| `fetch-deps.sh`、`deps.lock` | 发布包里固定版本的 firecracker、jailer 和 guest 内核 |
| `prod/` | 多机部署工具 opendsecops、示例 inventory 和集群配置 |
| `node/` | 计算节点的系统设置（内核模块、sysctl、udev、所需软件包） |
| `opendsec.example.json` | 裸机 / 虚拟机部署的配置示例（3 副本 IAM、2 个 apiserver、静态 edge 列表） |
| `Dockerfile` | 包含全部二进制的镜像；sandbox 内 agent 按版本放在 `/opt/opendsec/agents/<版本>/` |
| `systemd/` | 每个组件一个 unit（集群级组件用模板 unit，实例名为副本 id 或序号） |
| `k8s/` | Kubernetes 清单：IAM / watcher / apiserver 用 StatefulSet，edge 用 DaemonSet |

## 组件与部署级别

| 组件 | 级别 | 实例数 | 状态 | 运行身份 |
|---|---|---|---|---|
| IAM | 集群 | 3 或 5（Raft） | 有状态：`data_dir` 放在本地 SSD | 普通用户 |
| watcher | 集群 | ≥ 2（所有实例都探测；持锁的实例负责对账） | 无状态 | 普通用户 |
| apiserver | 集群 | ≥ 2，放在负载均衡后面 | 无状态 | 普通用户 |
| edge | 节点 | 每台 sandbox 节点 1 个 | 有状态：`state_dir`、cgroup、可写盘 | **root** |
| aether / chronus | sandbox | 每个 sandbox / 每个会话 1 个 | 由 edge 挂载进 sandbox，不单独部署 | — |

## 共享镜像库

配置 `"image_store": {"root": "/mnt/opendsec-images"}` 后，这个目录必须挂载到**所有 apiserver 和 edge** 上。可以用 CephFS、JuiceFS、NFS 等共享文件系统；论文用的是 3FS。
- edge 直接从这里叠加镜像层，sandbox 读到哪个文件才取哪个文件（按需加载）；edge 执行 `pack_diff` 时也会往这里写新层。
- apiserver 在这里写镜像清单。
- `opendsecctl image import` 需要在挂载了这个目录的机器上以 root 身份运行，因为还原 overlay 的删除标记需要 root。
- Kubernetes：`k8s/images-pvc.yaml` 定义了一个 RWX 存储卷，storageClass 请换成集群里支持多节点读写的存储类。

## microVM（Firecracker）节点
backend 的 `runtime` 设为 `"firecracker"` 后，这个 edge 用 Firecracker microVM 运行 sandbox（SPEC §19）。同一个 edge 可以同时提供 `container` 和 `microvm` 两个 backend。

- **节点要求**：
  - 能用 `/dev/kvm`（裸金属，或开了嵌套虚拟化的云主机）、cgroup v2、`mkfs.ext4`；
  - `firecracker` 和 `jailer` 在 PATH 上，或者在配置里用 `firecracker`、`jailer` 指定路径；验证过的版本是 v1.17.0。
- **guest 内核**：配置项 `kernel`，所有节点用同一个版本。推荐用仓库里的脚本自己编，下面的内存优化都需要它：
  ```sh
  # 需要 gcc make flex bison bc libelf-dev libssl-dev；384 线程上约 20 秒
  OUT=/opt/opendsec/vm/vmlinux-6.1.167-opendsec deploy/guest-kernel/build.sh
  ```
  - 脚本用 kernel.org 的 6.1.167 源码和 Firecracker v1.17 的 CI guest 配置，再叠加 `deploy/guest-kernel/opendsec.config`（zram、关闭启动时的加密自检等）。
  - 不开内存优化时，也可以直接用 Firecracker 官方 CI 内核：
    ```sh
    curl -fsSL -o /opt/opendsec/vm/vmlinux-6.1.155 https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155
    ```
- **内存优化**（SPEC §19.13，都需要上面的 opendsec 内核，默认关闭）：
  - `image_pmem`：镜像盘改用 virtio-pmem 挂进 VM，guest 以 DAX 方式挂载。同一镜像的 VM 直接共享宿主机页缓存里的镜像文件，guest 里不再各缓存一份。
    - 镜像相同的 sandbox 共享同一批物理页，这和容器共享宿主机页缓存一样；对跨租户侧信道敏感的场景不要开。
  - `free_page_reporting`：guest 释放的内存通过 balloon 设备交还宿主机。
  - `cold_age_s`：guest 里运行 DAMON_RECLAIM，把闲置超过这么多秒的内存换出到压缩的 zram swap，空出来的页再经 `free_page_reporting` 交还宿主机。
    - `zram_pct` 是 zram 盘大小占 VM 内存的百分比，默认 100，限制的是压缩前的数据量。
    - 生产环境建议 60–300 秒；太小会频繁换入换出。
  - 实测（16 个闲置的 512 MB VM）：三项全开后宿主机内存约为不开时的 31%。
  - 打开之后，可以考虑调高 `mem_overcommit`（按申请内存计算的超配比例）。节点 MemAvailable 低于 `mem_reserve_mb` 时，edge 照常拒绝新建。
- **`cold_boot_dirty_tracking`**（默认 `true`）：冷启动的 VM 是否开 KVM 脏页跟踪（SPEC §19.14）。
  - 开着时，暂停只写碰过的页，但 guest 内存用不上宿主机的大页：内存密集的负载慢 9–67%。
  - 设为 `false` 时，冷启动的 VM 用大页运行，代价是它第一次暂停、以及每次在它上面拍快照（fork 的源），都要写整份内存，VM 冻结的时间随内存大小增长：4 GB 约 2.6 秒，8 GB 约 4–5 秒（开着时约 0.3 秒）。从快照恢复的 VM 总是开跟踪，不受影响。
  - 适合长时间计算、很少暂停或 fork 的负载。
- **每个 VM 一个 uid**：每个 VM 以独立 uid 运行，范围是 `[uid_base, uid_base+65536)`，默认 `uid_base = 1000000000`。这个范围不能和节点上已有的用户或 subuid 重叠。
- **内存**：VM 的 cgroup 内存上限 = 申请的内存 + `vm_overhead_mb`（默认 64）。最小申请 128 MB。
- **节点本地缓存**：在 `<state_dir>/<edge>/microvm/cache/`。
  - 镜像第一次使用时展平成只读 ext4 盘，同一镜像的所有 VM 共用；
  - 缓存目前不会自动清理。
  - jailer 要把 guest 内核和镜像盘硬链接进每个 VM 的 chroot，所以这个目录和 `state_dir` 必须在同一个文件系统上，否则会退化成复制。
- **网络**：VM 目前没有网卡，只有 lo，和容器一样。网络要和网络策略一起做。
- **暂停与磁盘**：
  - 暂停中的 microVM 在 `state_dir` 里保留一份完整的内存文件，大小等于申请的内存。按暂停中 sandbox 数 × 内存大小预留磁盘。
  - 运行中的 VM 只要暂停过一次（或者是从快照恢复的），也保留这样一份文件，用作下次暂停的基础。
  - 第一次暂停写全量内存；之后每次只写这期间改过的页，再合并进这份文件。
- **`state_dir` 建议用 XFS**（`mkfs.xfs -m reflink=1`，xfsprogs 5.1 起默认开启）：
  - 复制可写盘和内存文件时，XFS 共享数据块（reflink），几乎不花时间，fork 和暂停的耗时因此和 VM 的磁盘、内存大小基本无关；
  - ext4 上这些复制都是真实复制，功能一样，只是更慢。
- **镜像库**：
  - 内存快照存在 `<image_store>/snapshots/` 下，包含内存、可写盘和当时挂载的只读盘。
  - 镜像库和 `state_dir` 在同一个文件系统上时，节点直接用硬链接。
  - 不在同一个文件系统上时（例如镜像库在共享存储上），节点第一次用某份快照时会把它拉到 `<state_dir>/<edge>/microvm/cache/snapshots/`。同一节点上的副本共用这份缓存。
  - 快照从镜像库删除后，节点在一分钟内清掉对应的缓存；正在运行的副本不受影响。
  - edge 会上报自己缓存了哪些快照，调度时优先选这些节点。

## 网络与网络策略（SPEC §20）
- **开启**：在 edge 配置里写 `"network": {"enabled": true, "subnet": "10.88.0.0/16", "dns_port": 15353}`。同一台机器上的多个 edge 需要不同的网段和端口。
- **宿主机要求**：`ip`（iproute2）、`nft`、`nsenter`。edge 会打开 `net.ipv4.ip_forward`，并建自己的 nftables 表 `inet opendsec_<edge>`。
  - 宿主机上如果有别的防火墙（例如 Docker 的 FORWARD 链默认 DROP），要放行 edge 的网段。
- **规则集**在集群配置里定义，例如：
  ```json
  "network": {
    "rule_sets": {"pypi": ["pypi.org", "files.pythonhosted.org"], "npm": ["registry.npmjs.org"]},
    "default_rules": {},
    "upstream_dns": []
  }
  ```
  - 域名同时覆盖它的子域名；也可以写 IPv4 网段，或者 `"*"`（所有公网地址；私网和元数据地址仍然不通）。
  - `upstream_dns` 不填时用宿主机的 `/etc/resolv.conf`。
- **使用**：创建时指定 `network_rules`；运行中用 `UpdateNetwork` / `opendsecctl sandbox network <id> pypi !npm` 修改。撤销立即切断已有连接。
- **限制**：按域名放行实际放行的是解析出的 IP，和该域名共用 CDN IP 的其他站点也能访问；不支持 IPv6。

## 容器加固与文件访问限制（SPEC §21）
- **默认生效**：容器 sandbox 里的 root 只有 Docker 默认的 capability（没有 `CAP_MKNOD`），并带 seccomp：不能 mount、加载模块、创建 user namespace 等。`/proc/sys` 等只读，`/proc/kcore` 等被屏蔽。
- **路径限制**：创建时的 `readonly_paths` / `masked_paths` 可以把指定路径设为只读或隐藏。
  - 容器里 root 无法撤销；microVM / 完整 VM 里 guest 的 root 可以撤销，这类场景请配合非 root 的 `init_user`。

## GPU、FnCall 与暂停回收（SPEC §22）
- **GPU**：edge 配置 `"gpu": {"devices": ["/dev/nvidia0", "/dev/nvidia1"], "extra": ["/dev/nvidiactl", "/dev/nvidia-uvm"], "mounts": ["/usr/lib/x86_64-linux-gnu/libcuda.so.1", "/usr/bin/nvidia-smi"], "shared_slots": 4}`。
  - `resources.gpus = n` 独占 n 张卡，`gpu_mode = "shared"` 共用一张卡上的一个槽位。
  - `capacity.gpus` 不填时取设备数。
  - 测试机没有 GPU，这部分只用假的设备节点验证过。
- **FnCall**：配一个容器运行时的后端，加上预建池，例如 `"fncall": {"runtime": "linux", "max_sandboxes": 2000, "warm_pool": {"root/tools:1": 32}}`。
  - 普通请求直接取一个已启动的 sandbox，经 API 创建约 2 ms；
  - 预建的 sandbox 不计入 edge 容量，请在 `capacity` 里预留出来。
- **暂停回收**：容器后端加 `"pause_reclaim": true`，暂停时把内存换到 swap。
  - 需要宿主机有 swap，且 `vm.swappiness > 0`（例如 `sysctl vm.swappiness=10`）；swappiness 为 0 时 edge 启动会报错。

## 完整 VM（QEMU，SPEC §23）
- **配置**：后端 `"runtime": "qemu"`，`kernel` 用 opendsec guest 内核；`qemu` 指定 QEMU 路径，默认在 PATH 里找 `qemu-system-x86_64`。
  - 需要 `/dev/kvm`、`/dev/vhost-vsock`，以及 kvm 组。QEMU 以每个 VM 独立的 uid（`uid_base` 起，默认 1100000000）运行，附加 kvm 组。
- **`full_init: true`**：用镜像自己的 `/sbin/init`（比如 systemd）作为 PID 1。
- **设备直通**：edge 配置 `gpu.pci` 列出 PCI 地址。这些设备要先绑定到 `vfio-pci` 驱动，`/dev/vfio/<group>` 要能被 kvm 组访问。

## 资源与清理（SPEC §24）
- **磁盘 IO**：后端配置 `"disk_io": {"read_mbps": 200, "write_mbps": 100, "read_iops": 0, "write_iops": 0}`，0 表示不限。
  - 容器按可写盘限速，microVM 用 Firecracker 的限速器（读写合计，取两者中较低的值），完整 VM 用 QEMU 的 throttling。
- **暂停 sandbox 的内存**：edge 配置 `paused_mem_charge`（默认 1）。
  - 例如设为 0.2，表示释放了内存的暂停 sandbox（microVM；开启了 `pause_reclaim` 的容器）只按 20% 计入内存容量。
  - 恢复时重新全额计入，只在节点内存压力下失败。
- **内存紧张时**：可用内存低于 `mem_reserve_mb` 的 1.5 倍时，edge 给开启了 `free_page_reporting` 的 microVM 充气 balloon，BE 和空闲最久的优先；回到 3 倍以上时放气。
- **镜像库清理**：定期运行 `opendsecctl image gc -store <镜像库目录> -grace 24h`（先加 `-dry-run` 看一下要删什么）。
  - 删除的是没有被镜像、快照或运行中 sandbox 引用、且超过宽限期的层和快照。
  - 节点上的镜像盘缓存由 edge 自己清理：24 小时没用过、也没有 VM 在用的盘会被删除。

## 容器层的本地副本（SPEC §33.1）
- 默认开启（后端配置 `layer_cache`，写 `false` 关闭）：容器挂载镜像层在节点本地的副本，不再直接挂镜像库里的层。每一层第一次用到时整层复制到 `<state_dir>/<edge>/layers/`，之后同一节点上的容器都用这份。
- 好处：镜像库（NFS）中断时，运行中的容器不受影响（关闭时，读到不在页缓存里的文件就会卡住，直到镜像库恢复）；冷读走本地盘。
- 代价：一个节点第一次用某个镜像时，要多花复制整层的时间；占用 `state_dir` 所在磁盘。没有 sandbox 在用、6 小时没用过的层由 edge 删除。

## microVM 镜像盘（SPEC §29.4）
- 后端配置 `erofs_images: true`：镜像在镜像库里只做一次 EROFS 盘（`<镜像库>/vmdisks/`），各节点第一次用到时顺序复制一份，不再各自展平成 ext4。完整的 python:3.12 上，一台机器第一次用到它的耗时从约 20 秒降到约 1 秒。
- 需要：guest 内核开启 EROFS（`deploy/guest-kernel/build.sh` 用当前的 `opendsec.config` 重新编译）；节点上有 `mkfs.erofs`（`apt install erofs-utils`）。
- 不改已有的镜像和快照：打开后新建的 VM 用 EROFS 盘，已有的 ext4 盘照常可用，没人用了由缓存清理删掉。

## CPU 核心调度（SPEC §29.1）
- 每个 sandbox 一个核心调度 cookie，不同 sandbox 不会同时跑在同一物理核的两个超线程上：延迟敏感的 sandbox 不受同核邻居拖累，也挡住了 sandbox 之间的 SMT 侧信道。
- 后端配置 `core_sched`：不写时内核支持就开（Ubuntu 24.04 的 6.8 内核支持）；`false` 关闭。

## 节点准备（密集部署时，SPEC §25.3–25.4）
- 运行 `deploy/node/install.sh`：
  - 安装 udev 规则：edge 的 loop 盘不做块设备探测，veth 和 loop 不生成 systemd 设备单元；
  - 安装 `.link` 和 `.network` 文件：udev 和 networkd 不接管 `ds*` 网卡；
  - 停用 udisks2；
  - `vm.swappiness = 10` 写进 `/etc/sysctl.d/99-zz-opendsec.conf`，并注释掉 `/etc/sysctl.conf` 里的 swappiness：有的云镜像在那里设成 0，而 tuned 每次启动都会在所有 sysctl.d 文件之后再应用一遍 `/etc/sysctl.conf`；
  - edge 等存放 `state_dir` 的文件系统挂好再启动（`opendsec-edge.service.d/10-node.conf`，`OPENDSEC_STATE_DIR`，默认 `/data/opendsec-state`）：`/data` 一般带 `nofail`，没挂上时 edge 不会把状态写到系统盘上；
  - `OPENDSEC_SWAP_FILE=/data/swapfile`（可选，`OPENDSEC_SWAP_GB` 默认 16）：没有就创建，写进 fstab，开机自动启用。`pause_reclaim` 需要 swap。
  - 停用 tuned，由 `opendsec-node-tuning.service`（开机时运行一次）设置 CPU 调速器 `performance`、真实磁盘的预读至少 4 MB；`vm.dirty_ratio = 30`、`vm.dirty_background_ratio = 10` 写在同一个 sysctl 文件里。这些就是 tuned 原来在这些机器上设的值（Ubuntu 云镜像默认开着 tuned，profile 是 `virtual-guest`，裸金属上也是）。
    - 为什么停用：tuned 对每块盘执行 `hdparm`，包括 sandbox 的 loop 盘。节点上 sandbox 多了以后，重启 tuned 会卡住，90 秒超时后被杀掉，而且它停下时会把设置恢复成内核默认值（调速器变成 `schedutil`）。
    - `install.sh` 用 SIGKILL 结束正在运行的 tuned，不让它回滚，再由 `opendsec-node-tuning` 设置一遍。
- 云厂商的监控和安全代理会对大量网卡和设备事件做出反应，需要评估它们的采集频率。
- 镜像库放在 NFS 上时，挂载参数建议 `vers=4.2,nconnect=8`；节点的 `state_dir` 用本地盘，最好是 XFS。
- 运维命令：`opendsecctl edge drain <edge>` 排空一个节点做维护，`-undo` 恢复。

## 指标（SPEC §26.3）
- 每个服务加 `-metrics ADDR`（例如 `-metrics :9464`）后，在 `http://ADDR/metrics` 输出 Prometheus 指标。这是独立的端口，不带 pprof，可以只对监控网段开放。
- 指标名都以 `opendsec_` 开头，完整列表见 SPEC §26.3。常用的几类：
  - 各服务每个接口的调用次数、错误原因和延迟；
  - edge 的容量、已分配量和压力；
  - 创建的分阶段耗时；
  - fork、迁移和快照传输的耗时。
- edge 之间会互相调用（拉取 fork 的快照、迁移暂停的 sandbox，SPEC §26.1–26.2），所以 edge 的监听地址要对其他 edge 可达，防火墙规则也要放行 edge 之间的流量。

## 准入与限流
- `admission` 段（TTL 默认值与上限、限流）由每个 apiserver 独立执行，限额按实例计算：N 个 apiserver 时，一个 principal 最多拿到 N 倍。
- 认证失败按**客户端地址**限流。如果 apiserver 前面的负载均衡做了 SNAT（例如 Kubernetes Service 的 `externalTrafficPolicy: Cluster`），所有客户端会显示为同一个地址：请保留源地址（`externalTrafficPolicy: Local`，或 L4 直通），或者把 `auth_fail_rate` 设为 -1。
- edge 的磁盘：`capacity.disk_mb` 不填时取 `state_dir` 所在文件系统的大小；`disk_overcommit` 默认 1（不超配）。`state_dir` 最好单独放在一块盘上，避免和系统日志、镜像缓存等抢空间。

## 证书

```sh
# 运维机上执行：生成集群 CA 和集群级组件的证书（apiserver 的对外域名用 -hosts 加进去）
opendsecctl pki init -config opendsec.json -out pki -hosts opendsec.example.com
# 每台 sandbox 节点上线时：给该节点签发它自己的 edge 证书（CA 私钥不离开运维机）
opendsecctl pki issue -ca pki -role edge -id node-17 -hosts 10.1.2.17 -out node-17-pki
scp -r node-17-pki/* node-17:/etc/opendsec/pki/
```
`pki/ca.key` 请离线保存。分发给各组件的只有 `ca.crt` 和它们各自的证书与私钥。

## systemd（裸机 / 虚拟机）

```sh
useradd --system --no-create-home opendsec
install -m 0755 bin/opendsec-* bin/opendsecctl /usr/local/bin/
install -d -m 0755 /opt/opendsec/agents/0.1.0 && install -m 0755 bin/opendsec-aether bin/opendsec-chronus /opt/opendsec/agents/0.1.0/
install -D -m 0640 -g opendsec opendsec.json /etc/opendsec/opendsec.json   # 含 admin token
cp systemd/*.service /etc/systemd/system/ && systemctl daemon-reload

systemctl enable --now opendsec-iam@0          # 每个 IAM 节点各起一个副本：@0 / @1 / @2
systemctl enable --now opendsec-watcher@0      # 以及另一台机器上的 @1
systemctl enable --now opendsec-apiserver@0
# sandbox 节点：在 /etc/opendsec/edge.env 中设置 OPENDSEC_EDGE_ID 和 OPENDSEC_EDGE_ADVERTISE
systemctl enable --now opendsec-edge
```
- `opendsec-edge.service` 使用 `KillMode=process`：sandbox 所在的 cgroup 在 `/sys/fs/cgroup/opendsec/` 下，不在这个 unit 里，所以 `systemctl restart opendsec-edge` 或升级 edge 不会杀掉 sandbox，edge 重启后会重新接管它们（需要配置 `persist_state` + `keep_sandboxes_on_exit`）。
- 未列在 `edges` 里的节点会套用 `edge_template`，并通过注册被 watcher 发现。

## Kubernetes

```sh
docker build -f deploy/Dockerfile -t <registry>/opendsec:0.1.0 .   # 并把清单里的 image 改成这个地址
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n opendsec create secret generic opendsec-config --from-file=opendsec.json=deploy/k8s/opendsec.json
opendsecctl pki init -config deploy/k8s/opendsec.json -out pki -hosts opendsec-apiserver.opendsec.svc,opendsec-apiserver.opendsec.svc.cluster.local
kubectl -n opendsec create secret generic opendsec-pki --from-file=pki/ --dry-run=client -o yaml \
  | grep -v 'ca.key' | kubectl apply -f -          # 不要把 ca.key 放进集群
kubectl label node <sandbox 节点> opendsec.io/sandbox-node=true   # 并按上文用 pki issue 为每个节点签发证书
kubectl apply -k deploy/k8s
```

edge DaemonSet 的几项设置**缺一不可**，否则 edge Pod 一重启，所有 sandbox 都会丢失：
- `hostPID: true`：sandbox 是 edge 的子孙进程。如果它们在容器的 PID 命名空间里，容器的 1 号进程一退出，内核会把它们全部杀掉。
- state 目录挂载使用 `mountPropagation: Bidirectional`：sandbox 的可写盘挂载点必须落在宿主机的挂载命名空间里，不能只存在于容器中。
- 挂载宿主机的 `/sys/fs/cgroup`、`/dev`（loop 设备），并以 `privileged` 运行。
- 节点名即 edge id，必须符合 `[a-z0-9-]{1,32}`。

## 升级

| 组件 | 方式 |
|---|---|
| apiserver | 直接滚动重启（无状态） |
| IAM | 逐个副本重启，始终保持多数派在线 |
| watcher | 逐个重启；正常退出时会释放对账锁，另一个实例立刻接任 |
| edge | 逐台重启，sandbox 会被重新接管（实测约 200 ms 后恢复服务） |
| aether / chronus | 发布新的版本目录 `/opt/opendsec/agents/<新版本>`，把 `agent_dir` 指过去：之后新建的 sandbox 用新版本，已经在跑的 sandbox 继续用它挂载的旧版本 |

## 验证情况
- systemd unit：用 `systemd-analyze verify` 检查通过（拿一个故意写错的 unit 作对照，确认检查确实生效）；没有在这台机器上把它们安装为系统服务实际运行。
- Kubernetes：`deploy/k8s/opendsec.json` 可以被 OpenDsec 加载并据此签发证书；清单经过 YAML 解析和结构检查（selector 与 label 一致、挂载与卷对应、副本数与配置一致）。**没有在真实的 Kubernetes 集群上运行过**，尤其是 edge 的 `hostPID`、挂载传播和 cgroup 这几项，需要在目标集群上验证。
