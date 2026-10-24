---
name: opendsec-deploy
description: Deploy and operate OpenDsec clusters - a single-node install with deploy/quickstart.sh, a new multi-node cluster with opendsecops, handing a cluster over to the fleet service, releases and upgrades, config rollouts, adding machines, and turning on features such as erofs_images. Use it whenever the user asks to deploy, install, upgrade, release, roll out, migrate, or change the configuration of an OpenDsec cluster, including a production one.
---

# 部署和运维 OpenDsec

本 skill 覆盖从零部署到日常变更的全部流程。命令都以仓库根目录为当前目录。背景文档：
- `README.md`「Deploy a cluster」：多机部署的完整步骤；
- `docs/OPERATIONS.md`：运维手册（证书、故障处理、fleet）；
- `docs/COMPONENTS.md`：各组件的实现；
- `docs/SPEC.md` §27–§30：设计和实测记录。

## 0. 先判断场景

| 用户要的 | 走哪一节 |
|---|---|
| 在一台机器上试用 | §2 单机 |
| 新建一个多机集群 | §3 多机，然后 §4 交给 fleet |
| 已有集群，还在用 opendsecops 管理（inventory 里没有 `fleet=` 角色） | §4 迁到 fleet，或 §5 中「opendsecops 升级」 |
| 已有集群，由 fleet 管理 | §5 发版和改配置 |
| 加机器、维护机器 | §6 |
| 开启某个功能（`erofs_images` 等） | §7 |
| 目标机器不能访问外网 | 先读 `deploy/offline/README.md`：做离线安装包，单机用 `./install.sh`，多机设 `OPENDSEC_DEBS` 并用 `opendsecops release-add`，其余照 §2–§5 |

判断现状用这些命令：
- 看 inventory 有没有 fleet 角色：`grep -v '^#' $OPENDSEC_OPS/inventory`；
- 各组件是否就绪：`deploy/prod/opendsecops status`；
- 各组件运行的版本：`deploy/prod/opendsecops versions`；
- 由 fleet 管理时，看各机器状态：`opendsecctl fleet nodes`。

## 1. 规则（每次都要遵守）

- **线上变更先说再做**：说清楚要改什么、影响什么、怎么回退，得到用户同意后再执行。用户已经明确要求的那一项可以直接做，但遇到超出范围的改动（比如顺手换内核）要先问。
- **先备份**：
  - IAM：`deploy/prod/opendsecops backup`；
  - 配置和 inventory：复制一份，加日期后缀；
  - 系统文件（如 fstab）：同样先备份。
- **一次只动一台机器**。每台动完都要检查：就绪、edge 健康、能跑通一个 sandbox，再动下一台。
- **线上变更时跑压测**：用调用方的接入包跑 `sdk/python/examples/load_test.py <秒数> 8`，变更前后看失败数。结论以压测结果为准，不以「命令没报错」为准。
- **不要泄露密钥**：不打印 admin token、调用方 token、`ca.key`，不打印含 token 的接入包。需要 token 时用 `$(cat file)` 直接传进命令。
- **远程执行的规矩**：
  - 不要在 ssh 里用 `pkill -f <模式>`：它会匹配到执行这条命令的远程 shell 本身，把会话杀掉。要停服务用 `systemctl kill`，或者把模式写成 `[x]yz` 的形式。
  - 远程长时间运行的命令要和 ssh 会话完全脱离，否则 ssh 不返回：
    `ssh -f host 'setsid nohup cmd > log 2>&1 < /dev/null &'`
    之后再用一个带超时的循环等它的日志出现结束标记。
  - rsync 源目录用绝对路径，每条命令只给一个源目录，排除 `.venv` 和 `bin`。目标端带 `--delete` 时，源路径写错会把目标清空。
- **不要用 `OPENDSEC_FORCE=1` 绕过 fleet**：只在从 opendsecops 迁到 fleet 的那一次，或者 fleet 全挂的应急时使用。

## 2. 单机部署

前提：Linux x86_64、systemd、cgroup v2、内核 5.15 以上、Go 1.27 以上、root。跑 microVM 还需要 `/dev/kvm`。

```sh
sudo deploy/quickstart.sh --build-kernel   # 编 guest 内核（需要 build-essential flex bison bc libelf-dev libssl-dev）
sudo deploy/quickstart.sh --kernel FILE    # 用现成的 guest 内核
sudo deploy/quickstart.sh --no-microvm     # 只跑容器
sudo deploy/quickstart.sh --uninstall      # 全部移除
```

- 脚本会先检查机器，然后依次：构建、打包、安装、启动；导入 `python:3.12`；建项目 `root/demo` 和它的调用方；各跑一个容器和 microVM sandbox 做检查。
- 结束后，管理员环境在 `/root/opendsec-ops/env`，调用方环境在 `/root/opendsec-ops/demo.env`。
- 不带内核参数时，如果 `deploy/deps.lock` 里的内核下载地址还没发布，脚本会提示改用上面三个参数之一。

## 3. 新建多机集群

照 README「Deploy a cluster」做。要点和容易漏掉的地方：

1. **基础设施先就位**：
   - **共享存储**：挂到所有 apiserver 和 edge 节点的 `/mnt/opendsec-images`。NFS 的挂载参数用 `vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev`，服务端必须关闭 root squash（`no_root_squash`）。挂好后执行 `opendsecctl image store-check -store /mnt/opendsec-images`，必需项全部 ok 才能继续。
   - **负载均衡**：四层 TCP 7100；健康检查用 HTTP，端口 9463，路径 `/readyz`；空闲超时不低于 30 秒。
   - 节点之间是私网，运维机能以 root ssh 到所有节点。
2. **打包**：`make build && deploy/prod/opendsecops release bin/`。
   - 内核下载失败时，设置 `OPENDSEC_KERNEL=<文件>`，或者把内核放进 `~/.cache/opendsec-deps/<deps.lock 里的文件名>`（sha256 要和 deps.lock 一致）。
   - 只跑容器的集群设置 `OPENDSEC_DEPS_SKIP=guest-kernel`。
3. **写 inventory、配置和 admin token**：
   - 从 `deploy/prod/inventory.example` 和 `cluster.example.json` 改。
   - admin token 用 `dsk.admin.$(openssl rand -hex 16)` 生成，权限 0600。IAM 发现示例里的占位值 `change-me` 会拒绝启动。
   - `edge_template` 和 `edges` 里的 `zone` 只能是 `onprem` 或 `cloud`。
4. **签证书**：`deploy/prod/opendsecops certs <LB地址或域名>`。每张 apiserver 证书都会自动带上 `api.opendsec.internal`。
5. **安装**：`deploy/prod/opendsecops install all`。edge 节点需要的软件包（erofs-utils、e2fsprogs、nftables、iproute2）会自动装上。
6. **启动和检查**：
   ```sh
   deploy/prod/opendsecops start all
   deploy/prod/opendsecops status
   deploy/prod/opendsecops monitor [webhook]
   ```
7. **验收**：
   - 导入镜像：在挂了共享存储的节点上以 root 执行 `opendsecctl image import ... -store /mnt/opendsec-images`；
   - 建项目、调用方，授予权限；
   - 用 `scripts/smoke.sh` 做冒烟检查，或者跑 SDK 的 quickstart。

## 4. 交给 fleet（新集群或从 opendsecops 迁移）

1. **inventory 和配置**：
   - inventory 里给管控节点加 `fleet=<id>`；
   - 配置里加 `fleet` 段：`replicas` 写每个副本的 `id`、`addr`（端口 7300）和 `data_dir`（`/var/lib/opendsec/fleet`），再加 `heartbeat_s: 10`。
   - 改完用新程序校验：`opendsecctl pki init -config <新配置> -out $(mktemp -d)`，能通过就说明配置有效，输出的临时目录删掉即可。
2. **证书**：执行 `deploy/prod/opendsecops certs`，补签 fleet、node 和运维用的证书。
3. **单元文件**：在已有的集群上（`install` 早就跑过的），把 `deploy/systemd/opendsec-fleet@.service` 和 `opendsec-nodeagent.service` 拷到各节点，再执行 `systemctl daemon-reload`。
4. **下发并重启**：
   ```sh
   deploy/prod/opendsecops push-config all
   OPENDSEC_FORCE=1 deploy/prod/opendsecops restart     # fleet 副本随之启动
   deploy/prod/opendsecops start all                    # 设为开机自启
   deploy/prod/opendsecops install-agent all
   ```
5. **登记到 fleet**：
   ```sh
   V=$(basename $(readlink $OPENDSEC_OPS/current))
   opendsecctl fleet release push $OPENDSEC_OPS/releases/$V
   opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json -note "..."
   opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release $V -config-gen 1
   opendsecctl fleet node set <name> -domain <域>      # 可选：故障域
   opendsecctl fleet nodes                            # 每台都上报，RUNNING = RELEASE，UNITS 全部就绪
   ```
6. **监控**：重跑 `deploy/prod/opendsecops monitor`，加上 fleet 和 nodeagent 的抓取目标。不带 webhook 参数会把告警接收方重置为「不发送」，所以先看 ctl 节点上 `/etc/prometheus/alertmanager.yml` 里原来的接收方，有的话照原样带上。

## 5. 发版和改配置

**由 fleet 管理的集群**：
```sh
make build && deploy/prod/opendsecops release bin/                 # 打包（做法同 §3 第 2 步）
opendsecctl fleet release push $OPENDSEC_OPS/releases/<版本>
opendsecctl fleet rollout create -release <版本> [-bake 60 -pause 30]
opendsecctl fleet rollout status -steps

# 只改配置：
opendsecctl fleet config get -gen <当前代> -out cur.json           # 先确认它和运维机上的那份一致
# 编辑 $OPENDSEC_OPS/opendsec.json（先备份），校验（§4 第 1 步）
opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json -note "..."
opendsecctl fleet rollout create -config-gen <新代> [-bake 60 -pause 30]
```
- **顺序**：管控节点一台一台来，IAM leader 所在的最后；带 edge 的机器先排空、再重启、再恢复调度；纯 edge 节点先升一台试点，观察后按批推进。
- **出问题时**：失败的机器自动退回原版本并被锁定（pinned），升级暂停，然后由人决定：
  - `opendsecctl fleet rollout resume <id>`：接受失败，继续升其余机器；
  - `opendsecctl fleet rollout rollback <id>`：已升级的按相反顺序退回；
  - `opendsecctl fleet rollout abort <id>`：停在当前位置。

  查明原因后，用 `opendsecctl fleet node unpin <名字>` 解锁。

**还在用 opendsecops 的集群**：
```sh
OPENDSEC_ADDR=<任一 apiserver> deploy/prod/opendsecops backup
deploy/prod/opendsecops upgrade <版本>       # 回滚：deploy/prod/opendsecops rollback <旧版本>
```
- 它只换程序、按顺序重启，不安装新的单元文件。新版本带了新的单元文件时，要先手动拷过去。
- 0.11 之前的 opendsecctl 不认 `OPENDSEC_ADDR` 里逗号分隔的多个地址，这时临时设成单个地址。

**每次发版或改配置后**：
- 再执行一遍 `status` 或 `fleet nodes`；
- 两台 edge 都健康、没有停在排空状态（看 `opendsecctl status` 里的 `healthy` 和 `draining`）；
- 冒烟检查和压测都没有失败；
- 看 `journalctl -u 'opendsec-*' -p warning --since <开始时间>` 有没有新的告警。

## 6. 加机器和维护

- **加计算节点**：
  1. 新机器先挂好共享存储；
  2. `deploy/prod/opendsecops add-node <名字> <ssh地址> <私网地址> edge=<名字>`；
  3. `opendsecctl fleet node accept <名字> -roles edge=<名字> -domain <域>`；
  4. 确认它出现在 `opendsecctl status` 里且 healthy。
- **维护**：`opendsecctl fleet node cordon <名字>` 停止往它调度 → 维护 → `opendsecctl fleet node uncordon <名字>`。要等上面的 sandbox 全部结束，用 `node evacuate`。
- **整机重启**：上面的 sandbox 会全部丢失，暂停中的 microVM 也一样。重启后检查：
  - `/data`、`/mnt/opendsec-images` 和 swap 都挂上了；
  - `sysctl vm.swappiness` 是 10；
  - 各组件的 `/readyz` 都正常。
- **改 NFS 挂载参数**：remount 改不了，要用 `umount -l` 再 `mount`。edge 和 apiserver 只用 `Requires=` 依赖这个挂载，懒卸载不会把它们停掉；正在运行的 sandbox 继续用旧挂载。

## 7. 开启功能

- **`erofs_images`**（microVM 的 EROFS 镜像盘，SPEC §29.4）：
  1. 先确认每台 edge 都有 `mkfs.erofs`（erofs-utils）。缺了的话，配置下发到那台时 edge 会启动失败，被 fleet 退回并锁定。
  2. 确认 guest 内核支持 EROFS：发布包里的 `.2` 版本支持。
  3. 在各 edge 的 `microvm` 后端加 `"erofs_images": true`，按 §5 改配置下发。
  4. 验证：
     - 镜像库 `vmdisks/` 下每组层只有一个 `vd-*.erofs`；
     - 各节点缓存里有 `img-*.erofs`；
     - 新 microVM 里有 `/sys/fs/erofs/pmem0`（开了 pmem 时）。
- **guest 内核放进发布包**：把各 microVM、fullvm 后端的 `kernel` 指向 `/opt/opendsec/current/vm/vmlinux-...`，这样以后发版时内核也随版本更新。
- **告警**：`deploy/prod/opendsecops monitor <webhook>`。

## 8. 冒烟检查

`scripts/smoke.sh` 在每种后端上各创建一个 sandbox，执行 `python3 -c "print(6*7)"`，检查输出是 42，然后停掉。用当前环境里的 `OPENDSEC_*` 变量：
```sh
.claude/skills/opendsec-deploy/scripts/smoke.sh [镜像，默认 root/py:3.12] [后端，默认 container,microvm]
```
有一种失败，退出码就不是 0。要分别检查每台 apiserver 时，把 `OPENDSEC_ADDR` 设成那一台的地址再跑。

## 9. 实际遇到过的问题

| 现象 | 原因 | 处理 |
|---|---|---|
| 创建全部 `no_capacity`，但 edge 是健康的 | edge 的 `zone` 不是 `onprem` 或 `cloud` | 改 zone。新版本配置校验会直接报错 |
| edge 启动失败：`erofs_images needs mkfs.erofs` | 节点缺 erofs-utils | 装上；`install.sh` 新版会自动装 |
| `image import` 中途 `context deadline exceeded` | 旧版 CLI 有 5 分钟总超时 | 用新版：import 不设总时限，其他命令用 `-deadline` |
| 通过负载均衡的批量创建报 `Stream removed`，LB 日志里是 `cD` | LB 的空闲超时掐断了安静的流 | 新版服务端每 20 秒 ping 一次；LB 的空闲超时不低于 30 秒 |
| 镜像刚登记，某台 edge 约 1 分钟内报 `image ... not found` | NFS 客户端缓存了「文件不存在」 | 挂载参数加 `lookupcache=positive` |
| `too many colons in address` | 0.11 之前的 opendsecctl 不认多个地址 | 升级，或临时设成单个地址 |
| 多地址连接时 TLS 报 `not api.opendsec.internal` | 旧证书里没有这个名字 | 新版签发时自动带上；旧证书要重签：`certs <名字>` → `push-config` → 滚动重启 |
| `opendsecops release` 下载内核失败 | deps.lock 里的下载地址还没发布 | 用 `OPENDSEC_KERNEL`，或把内核放进下载缓存（§3 第 2 步） |
| ssh 一直不返回 | 远程后台进程没有和会话脱离 | 用 `ssh -f` 加 `setsid nohup ... &` |
| `opendsecops upgrade` 报 `this cluster has fleet replicas` | 集群已经由 fleet 管理 | 走 §5 的 fleet 流程 |
