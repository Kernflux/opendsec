# 单机安装详解

`deploy/quickstart.sh` 在一台 Linux 机器上装好 OpenDsec 的全部组件。它用的是和多机集群相同的工具（`opendsecops`），所以装好的单机集群以后可以升级，也可以加机器。这一页说明它的要求、选项、具体做了什么、装在哪里，以及常见问题。简要步骤见[快速开始](https://kernflux.github.io/docs/quickstart)。

## 1. 要求

| 项目 | 要求 | 检查方法 |
|---|---|---|
| 架构 | x86_64 | `uname -m` |
| 内核 | 5.15 以上（Ubuntu 24.04 上完整验证过） | `uname -r` |
| init | systemd | `ls /run/systemd/system` |
| cgroup | v2（unified） | `stat -fc %T /sys/fs/cgroup` 输出 `cgroup2fs` |
| 文件系统 | 支持 overlay | `grep overlay /proc/filesystems` |
| 命令 | `curl`、`tar`、`sha256sum`、`mkfs.ext4`、`ip`、`awk`（Ubuntu 自带） | — |
| 编译 | Go 1.27 以上、`make`（使用预编译程序或 `--release` 时不需要） | `go version` |
| 权限 | root | — |
| 端口 | 7001、7002、7011、7100、7201、7400、9461–9464、9467 未被占用 | `ss -ltn` |
| microVM | `/dev/kvm`：裸金属，或开启了嵌套虚拟化的云主机。没有时只装容器 | `ls /dev/kvm` |
| 资源 | 建议 4 核、8 GB 内存、40 GB 磁盘以上 | — |

脚本开始时会逐项检查并打印 `[ok]` 或 `[x]`，有 `[x]` 时停下，不改动机器。

## 2. 安装

```sh
sudo -i                                                   # 以下都以 root 执行
apt update && apt install -y make git python3-venv
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz
git clone https://github.com/kernflux/opendsec && cd opendsec
deploy/quickstart.sh
```

在全新的 8 核虚拟机上约 8 到 11 分钟，大部分时间在编译。

### 选项

| 选项 | 说明 |
|---|---|
| （无） | 有 `/dev/kvm` 时装 container 和 microVM，没有时只装 container。guest 内核从 GitHub Release 下载，并按 `deploy/deps.lock` 校验 sha256 |
| `--no-microvm` | 只装 container |
| `--kernel FILE` | 使用已有的 guest 内核文件，不下载 |
| `--build-kernel` | 自己编译 guest 内核（多几分钟，需要 `build-essential flex bison bc libelf-dev libssl-dev`） |
| `--release DIR` | 使用打包好的版本目录，不编译（离线安装包用这个） |
| `--uninstall` | 卸载，见 §6 |
| `--help` | 显示用法 |

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `OPENDSEC_IMAGE` | `docker.io/library/python:3.12` | 导入的基础镜像；也可以是镜像文件 |
| `OPENDSEC_ADDR_IP` | 默认路由的源地址 | 组件监听的地址。机器有多块网卡、或者要让其他机器访问时指定 |
| `OPENDSEC_OPS` | `/root/opendsec-ops` | 运维目录 |
| `OPENDSEC_DEBS` | — | 离线安装包里的软件包仓库（`debs/`），从它安装系统软件包而不是用 apt 源 |

例如只让本机访问：`OPENDSEC_ADDR_IP=127.0.0.1 deploy/quickstart.sh`。

## 3. 脚本做了什么

1. **检查机器**（§1 的各项），确定节点名（主机名）、地址、sandbox 状态目录（`/data` 是挂载点时用 `/data/opendsec-state`，否则 `/var/lib/opendsec/edge-state`）和是否装 microVM。
2. **编译并打包**：`make build`，然后 `opendsecops release` 把程序、systemd unit、Firecracker、jailer 和 guest 内核打成一个版本，放在 `/root/opendsec-ops/releases/<版本>`。
3. **写配置**：在运维目录生成 inventory（本机，ssh 地址为 `local`）、集群配置 `opendsec.json` 和管理员 token。配置要点：
   - 单副本 IAM（Raft，以后可以扩成 3 副本），root 配额 10000 个 sandbox，token 最长 90 天；
   - 镜像库在 `/mnt/opendsec-images`（本机目录）；
   - 规则集 `pypi`，**没有默认网络规则：sandbox 默认不能访问网络**；
   - container 后端（最多 2000 个，默认盘 1 GB）；有 KVM 时加 microvm 后端（最多 1000 个，默认盘 2 GB，开启 EROFS 镜像盘、pmem、内存回收）；
   - E2B 网关，项目 `root/demo`，模板 `base` = `root/py:3.12`。
4. **签证书并安装**：`opendsecops certs` 生成 CA 和各组件证书；`opendsecops install all` 创建用户和目录，下发版本、配置、证书、systemd unit，设置节点参数（sysctl、模块、NFS 客户端标识等）。
5. **启动**：`opendsecops start all`，按 IAM → watcher → apiserver → E2B 网关 → edge 的顺序启动，等每个都就绪。
6. **导入镜像**：把 `OPENDSEC_IMAGE` 导入为 `root/py:3.12`。
7. **建项目和调用方**：项目 `root/demo`（配额 100 个 sandbox），身份 `demo`，授予它 `root/demo` 上的 `sandbox.create`、`sandbox.operate`、`layer.publish` 和 `root` 上的 `layer.use`。
8. **检查**：用 `demo` 身份各创建一个 container 和 microVM sandbox，执行 `python3 -c 'print(6*7)'`，确认输出 42，然后停止。

最后打印管理员和调用方的使用方法。

## 4. 装好之后

### 环境

```sh
. /root/opendsec-ops/env         # 管理员：admin token，项目 root
. /root/opendsec-ops/demo.env    # 调用方：项目 root/demo 的 token；也设置了 E2B_API_URL、E2B_SANDBOX_URL、E2B_API_KEY
```

### 文件和目录

| 路径 | 内容 |
|---|---|
| `/root/opendsec-ops/` | 运维目录：inventory、`opendsec.json`、`admin.token`、`pki/`（含 CA 私钥）、`releases/`、`env`、`demo.env`。**含有密钥，请妥善保管和备份** |
| `/opt/opendsec/current` | 当前版本（指向 `/opt/opendsec/releases/<版本>`）：`bin/`、`vm/`（guest 内核）、`agents/`、`units/` |
| `/usr/local/bin/opendsec-*`、`opendsecctl` | 指向当前版本的程序 |
| `/etc/opendsec/` | 本机使用的配置、证书、`admin.token` |
| `/var/lib/opendsec/iam` | IAM 数据（Raft 日志和快照） |
| `/data/opendsec-state` 或 `/var/lib/opendsec/edge-state` | sandbox 的磁盘、快照和记录 |
| `/mnt/opendsec-images` | 镜像库 |
| `/var/log/opendsec/audit` | 审计日志 |
| `/var/backups/opendsec` | IAM 每日备份 |

### 服务

| unit | 端口（指标、`/readyz`） |
|---|---|
| `opendsec-iam@0` | 7001、Raft 7011（9461） |
| `opendsec-watcher@0` | 7002（9462） |
| `opendsec-apiserver@0` | 7100（9463） |
| `opendsec-edge` | 7201（9464） |
| `opendsec-e2b@0` | 7400（9467） |
| `opendsec-iam-backup.timer` | 每天 03:00 备份 IAM |

```sh
systemctl status 'opendsec-*'
journalctl -u opendsec-edge -f
deploy/prod/opendsecops status          # 每个组件是否就绪
opendsecctl status                      # 集群快照（先 . /root/opendsec-ops/env）
```

### 让其他机器访问

- 安装时用 `OPENDSEC_ADDR_IP` 指定其他机器能访问的地址（默认就是默认路由的地址）。
- 把 `/root/opendsec-ops/pki/ca.crt`、调用方的 token 和地址交给调用方；调用方设置 `OPENDSEC_ADDR=<地址>:7100`、`OPENDSEC_CA=<ca.crt 路径>`。
- 防火墙只放行 7100（以及用 E2B SDK 时的 7400）。

### 重启机器

所有服务开机自启。重启后 sandbox 全部丢失（包括暂停中的），镜像、项目、身份和 token 都保留。

## 5. 升级

单机集群没有 fleet，用 `opendsecops` 升级：

```sh
cd opendsec && git pull
make build && deploy/prod/opendsecops release bin/
deploy/prod/opendsecops upgrade <新版本>          # 版本号在上一条命令的输出里
deploy/prod/opendsecops status
```

升级时各组件逐个重启，运行中的 sandbox 不受影响。回退：`deploy/prod/opendsecops rollback <旧版本>`。升级前请看 `CHANGELOG.md` 里的「Breaking」一节。

## 6. 卸载

```sh
deploy/quickstart.sh --uninstall
```

停止并禁用所有服务，杀掉残留的 sandbox，删除 nftables 表、网络接口和命名空间、挂载点，以及 `/etc/opendsec`、`/opt/opendsec`、`/var/lib/opendsec`、`/var/log/opendsec`、`/var/backups/opendsec`、运维目录、镜像库和 sandbox 状态目录。

保留的：节点参数（`/etc/sysctl.d`、udev 规则、`/etc/modules-load.d`、networkd 文件），以及 Go、make 等你自己装的软件。

## 7. 常见问题

| 现象 | 原因与处理 |
|---|---|
| `[x] command make` | `apt install -y make` |
| `[x] Go 1.27+ to build` | 按 §2 安装 Go；或者在别处编译好，把 `bin/` 拷过来 |
| `[x] cgroup v2` | 系统还在用 cgroup v1：内核参数加 `systemd.unified_cgroup_hierarchy=1` 后重启 |
| `[x] port 7100 is in use` | 有其他程序占用端口；或者之前装过：先 `--uninstall` |
| `[x] /root/opendsec-ops already holds a cluster` | 之前装过：先 `--uninstall`，或者用 `opendsecops` 管理已有的集群 |
| `warning: no /dev/kvm: containers only` | 机器不支持 KVM。云主机请开启嵌套虚拟化，或者改用裸金属 |
| `could not fetch the guest kernel pinned in deploy/deps.lock` | 访问不了 GitHub：用 `--kernel FILE`、`--build-kernel`，或 `--no-microvm` |
| 导入 `python:3.12` 很慢或失败 | 访问 Docker Hub 慢：用 `OPENDSEC_IMAGE` 指定国内镜像源的地址，或者先 `docker save` 成文件再用文件路径 |
| `python3 -m venv` 报 ensurepip 不可用 | `apt install -y python3-venv` |
| 最后的检查报 `... sandbox ... python printed '...', want 42` | sandbox 建好了但命令没有得到预期输出：看 `journalctl -u opendsec-edge` 和 `opendsecctl status`，再手动执行 `opendsecctl exec <id> python3 -c 'print(6*7)'` 看报错 |
| microVM 创建失败 | `journalctl -u opendsec-edge` 里看具体原因；`ls -l /dev/kvm` 确认存在；云主机确认嵌套虚拟化已开启 |

更多问题见[故障排查](TROUBLESHOOTING.md)。
