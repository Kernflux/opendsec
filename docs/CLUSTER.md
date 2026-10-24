# 多机集群部署

这一页从零开始部署一个生产集群：规划、准备基础设施、安装、交给 fleet 管理、开通第一个调用方，以及验收。部署完成后的日常操作（升级、改配置、加机器、证书、故障处理）见[运维手册](OPERATIONS.md)。

整个流程在一个 3 台管控节点、3 台计算节点、NFS 和 HAProxy 组成的全新集群上按本文验证过，安装约 8 分钟（不含准备机器）。

## 1. 规划

### 机器

| 角色 | 台数 | 配置建议 | 运行 |
|---|---|---|---|
| 管控节点 | 3（每个故障域一台） | 4 核、8 GB 起步，本地 SSD | IAM、watcher、apiserver、fleet 各一个副本；其中一台另跑 Prometheus 和 Alertmanager |
| 计算节点 | 按需 | 裸金属或开启嵌套虚拟化的云主机；本地 NVMe 放 sandbox 状态；内存决定能跑多少 sandbox | edge、节点代理 |
| 运维机 | 1（可以是一台管控节点） | 任意 | `opendsecops`，保存集群的全部密钥 |

- 任意一台管控节点宕机，集群仍能创建和使用 sandbox。IAM 是 3 副本 Raft，最多容忍 1 台故障。
- 计算节点宕机时，它上面的 sandbox 随之丢失，新的 sandbox 调度到其他节点。
- 小集群可以让管控组件和 edge 共用机器（inventory 里同一行写多个角色）。

### 组件与端口

| 组件 | 在哪里 | 实例数 | 端口（指标） | 状态 |
|---|---|---|---|---|
| `opendsec-iam` | 管控节点 | 3（或 5），Raft | 7001，Raft 7011（9461） | `/var/lib/opendsec/iam`，本地 SSD |
| `opendsec-watcher` | 管控节点 | 2–3 | 7002（9462） | 无 |
| `opendsec-apiserver` | 管控节点，负载均衡后面 | 2 个以上 | 7100（9463） | 无；审计日志在 `/var/log/opendsec/audit` |
| `opendsec-fleet` | 管控节点 | 3 | 7300（9465） | 版本文件在 `/var/lib/opendsec/fleet`；期望状态存在 IAM 里 |
| Prometheus、Alertmanager | 一台管控节点 | 1 | 9090、9093 | 本地 |
| `opendsec-edge` | 每台计算节点，root | 每台 1 个 | 7201（9464） | `state_dir`，本地 NVMe |
| `opendsec-nodeagent` | 每台机器，root | 每台 1 个 | （9466） | 无 |
| `opendsec-e2b`（可选） | 任意节点 | 按需 | 7400（9467） | 无 |
| node_exporter | 每台机器 | 每台 1 个 | 9100 | 无 |

**网络**：只对调用方开放负载均衡的 7100（用 E2B SDK 时还有 7400）。其余端口只在私网内放行：7001、7011、7002、7201、7300 是组件间的 mTLS 流量，9461–9467 和 9100 是指标，9090、9093 给运维人员用。

## 2. 准备基础设施

### 2.1 所有节点

- Linux x86_64、systemd、cgroup v2、内核 5.15 以上（验证环境是 Ubuntu 24.04、内核 6.8）。
- 节点之间有私网。
- 运维机能以 root ssh 到每台节点，默认私钥 `/root/.ssh/opendsec-ops`（`OPENDSEC_SSH_KEY` 可改）：

```sh
ssh-keygen -t ed25519 -N '' -f /root/.ssh/opendsec-ops
# 把 /root/.ssh/opendsec-ops.pub 加到每台节点 root 的 authorized_keys
```

- 计算节点：`/dev/kvm` 存在（`ls -l /dev/kvm`）；本地 NVMe 挂在 `/data`（sandbox 状态目录默认 `/data/opendsec-state`，XFS 可以用 reflink 复制，更快）。edge 需要的软件包（erofs-utils、e2fsprogs、nftables、iproute2）在安装时自动装上。

### 2.2 共享存储

挂在每台 apiserver 和 edge 节点的 `/mnt/opendsec-images`。可以用 NAS（NFS）、CephFS、JuiceFS：

- **必须关闭 root squash**（NAS 的权限组里设为「不限制 root」）。
- NFS 的挂载参数，写进 `/etc/fstab`：

```
<nas地址>:/<导出路径>  /mnt/opendsec-images  nfs4  vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev  0 0
```

用一台 Linux 机器自建 NFS（测试或小集群）：

```sh
apt install -y nfs-kernel-server
mkdir -p /srv/opendsec-images
echo '/srv/opendsec-images 10.0.0.0/16(rw,sync,no_subtree_check,no_root_squash)' >> /etc/exports
exportfs -ra
```

参数的原因见[镜像与快照 §5](IMAGES.md)。

### 2.3 负载均衡

四层 TCP 转发 7100 到所有 apiserver。要求：

- 只做 TCP 转发，不要用七层 HTTP/gRPC：TLS 由 apiserver 自己终止；
- 健康检查用 HTTP：端口 9463，路径 `/readyz`，间隔 2 秒，连续 2 次失败判定不健康；
- 空闲超时不低于 30 秒：apiserver 每 20 秒给空闲连接发一次 ping；
- 能保留客户端源地址的话请保留（否则认证失败的限流会集中在负载均衡的地址上）。

HAProxy 示例（`/etc/haproxy/haproxy.cfg` 里追加）：

```
frontend opendsec_api
    bind 10.0.0.10:7100
    mode tcp
    timeout client 120s
    default_backend opendsec_apiservers

backend opendsec_apiservers
    mode tcp
    balance roundrobin
    timeout server 120s
    option httpchk GET /readyz
    default-server check port 9463 inter 2s fall 2 rise 2
    server ctl-1 10.0.0.11:7100
    server ctl-2 10.0.0.12:7100
    server ctl-3 10.0.0.13:7100
```

云上用云厂商的四层负载均衡（TCP 监听），健康检查按上面设置。

没有负载均衡也可以：调用方把所有 apiserver 的地址用逗号连起来作为 `OPENDSEC_ADDR`，SDK 会轮询并自动避开宕机的那台。

### 2.4 运维机

```sh
apt update && apt install -y make git
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xz
export PATH=$PATH:/usr/local/go/bin
git clone https://github.com/kernflux/opendsec && cd opendsec
export OPENDSEC_OPS=/root/opendsec-ops
mkdir -p -m 0700 $OPENDSEC_OPS
```

`$OPENDSEC_OPS` 会保存 inventory、集群配置、管理员 token 和 CA 私钥。**它就是整个集群的钥匙**：只给需要的人访问，并备份到安全的地方。

## 3. 安装

### 3.1 打包版本

```sh
make build && deploy/prod/opendsecops release bin/
```

把程序、systemd unit、Firecracker、jailer 和 guest 内核（按 `deploy/deps.lock` 下载并校验）打成一个版本，放在 `$OPENDSEC_OPS/releases/<版本>`。

- 下载不了 guest 内核时：`OPENDSEC_KERNEL=<内核文件> deploy/prod/opendsecops release bin/`，或者把文件放进 `~/.cache/opendsec-deps/vmlinux-6.1.167-opendsec.2`（sha256 要和 deps.lock 一致）。
- 只跑容器的集群：`OPENDSEC_DEPS_SKIP=guest-kernel`。

### 3.2 描述集群

```sh
cp deploy/prod/inventory.example $OPENDSEC_OPS/inventory
cp deploy/prod/cluster.example.json $OPENDSEC_OPS/opendsec.json
```

**inventory**：每行一台机器：名字、ssh 地址、私网地址、角色。

```
ctl-1     203.0.113.11   10.0.0.11   iam=0 watcher=0 apiserver=0 fleet=0
ctl-2     203.0.113.12   10.0.0.12   iam=1 watcher=1 apiserver=1 fleet=1
ctl-3     203.0.113.13   10.0.0.13   iam=2 watcher=2 apiserver=2 fleet=2 monitor
node-a1   203.0.113.21   10.0.1.21   edge=node-a1
node-b1   203.0.113.22   10.0.1.22   edge=node-b1
node-c1   203.0.113.23   10.0.1.23   edge=node-c1
```

- 角色：`iam=<副本 id>`、`watcher=<id>`、`apiserver=<序号>`、`fleet=<id>`、`edge=<edge id>`、`e2b=<序号>`、`monitor`（Prometheus 和 Alertmanager 装在这台）。
- 集群配置里的每个 IAM 副本、watcher、apiserver、edge 都要在 inventory 里恰好出现一次。
- ssh 地址写 `local` 表示就在本机执行，不经过 ssh。

**opendsec.json**：把示例里的地址改成你的私网地址（IAM、watcher、apiserver、fleet 各段），然后按需调整：

- `iam.root_quota`：整个集群的配额上限；
- `admission`：限流（示例里调高了：每秒 2 万次创建、10 万次调用）；
- `network.rule_sets`、`network.default_rules`：网络规则集和默认规则（示例没有默认规则，sandbox 默认不能访问网络）；
- `edge_template.backends`：计算节点提供哪些后端、每个后端最多几个 sandbox、默认磁盘大小；
- `edges`：需要单独配置的节点。新机器不必写进来，用 `edge_template` 即可。

每个字段的含义见[集群配置参考](CONFIGURATION.md)。改完后校验：

```sh
bin/opendsecctl pki init -config $OPENDSEC_OPS/opendsec.json -out $(mktemp -d)
```

**管理员 token**：

```sh
printf 'dsk.admin.%s\n' "$(openssl rand -hex 16)" > $OPENDSEC_OPS/admin.token
chmod 0600 $OPENDSEC_OPS/admin.token
```

### 3.3 证书

```sh
deploy/prod/opendsecops certs api.opendsec.internal,10.0.0.10
```

生成集群 CA（私钥只留在 `$OPENDSEC_OPS/pki`）和每个组件的证书。参数是负载均衡的地址或域名，会写进 apiserver 的证书；每张 apiserver 证书还都带有 `api.opendsec.internal`（SDK 连多个地址时用这个名字校验）。

### 3.4 安装到所有节点

```sh
deploy/prod/opendsecops install all
```

在每台节点上：创建用户和目录，下发版本、配置、证书和 systemd unit，安装需要的软件包，设置节点参数（sysctl、内核模块、NFS 客户端标识、日志过滤）。**不启动任何服务**。

每台节点只拿到 CA 证书和本机组件的证书与私钥；管理员 token 只下发到 IAM 节点。

### 3.5 挂载共享存储

在每台 apiserver 和 edge 节点上按 §2.2 写 fstab 并挂载，然后在其中一台上检查：

```sh
mount /mnt/opendsec-images
/opt/opendsec/current/bin/opendsecctl image store-check -store /mnt/opendsec-images
```

必需项全部 `ok` 才能继续。NFS 客户端标识在 `install` 时设置，需要重新挂载后才生效：如果节点在 `install` 之前已经挂过，请重启一次节点。

### 3.6 启动

```sh
deploy/prod/opendsecops start all
deploy/prod/opendsecops status
```

按 IAM → watcher → apiserver → E2B 网关 → fleet → edge 的顺序启动，每个都等 `/readyz` 返回 200。IAM 第一次启动时用管理员 token 自举。`status` 显示每个组件是否就绪和当前的 IAM leader，有组件没就绪时退出码为 1。

### 3.7 监控

```sh
deploy/prod/opendsecops monitor https://alerts.example.com/hook
```

在每台机器上装 node_exporter，在 `monitor` 角色的节点上装 Prometheus 和 Alertmanager，加载告警规则（`deploy/monitoring/alerts.yml`），告警发往 webhook。不带 webhook 时告警不发给任何人。指标和告警的说明见[监控与告警](MONITORING.md)。

## 4. 交给 fleet 管理

从这一步起，升级、改配置、加机器都由 fleet 分批执行，失败自动回退。

```sh
deploy/prod/opendsecops install-agent all              # 每台机器启动节点代理
export PATH=$PATH:$OPENDSEC_OPS/current/bin
export OPENDSEC_ADDR=10.0.0.10:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
V=$(basename $(readlink $OPENDSEC_OPS/current))
opendsecctl fleet release push $OPENDSEC_OPS/releases/$V
opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json -note "initial"
opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release $V -config-gen 1
opendsecctl fleet node set node-a1 -domain a           # 故障域：rollout 按它分散，每批同一域最多一半
opendsecctl fleet node set node-b1 -domain b
opendsecctl fleet node set node-c1 -domain c
opendsecctl fleet nodes
```

`fleet nodes` 里每台机器都应在上报（`SEEN` 几秒前），`RUNNING` 等于 `RELEASE`，`UNITS` 全部就绪。

交给 fleet 之后，`opendsecops upgrade` 和 `restart` 会拒绝执行，升级用 `opendsecctl fleet rollout`（[运维手册 §6](OPERATIONS.md)）。`opendsecops` 继续用于证书、加机器和应急。

## 5. 第一个镜像和第一个调用方

在一台挂载了镜像库的节点上，以 root：

```sh
export OPENDSEC_ADDR=10.0.0.10:7100 OPENDSEC_TOKEN=<管理员 token> OPENDSEC_CA=/etc/opendsec/pki/ca.crt
opendsecctl image import docker.io/library/python:3.12 -as root/py:3.12 -store /mnt/opendsec-images
```

开通一个团队（在运维机上）：

```sh
opendsecctl project create root team-a -quota sandboxes=1000
opendsecctl principal create root/team-a trainer -kind agent       # 输出里的 token 只显示这一次
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl grant root trainer layer.use                           # 可以使用 root/ 下的镜像
```

交给调用方：负载均衡的地址、token（单独通过安全渠道）、`$OPENDSEC_OPS/pki/ca.crt`、SDK（`sdk/python` 或打包好的 wheel），以及[接入指南](USER_GUIDE.md)。

## 6. 验收

```sh
# 冒烟：每种后端各建一个 sandbox，执行 python3 -c 'print(6*7)'
OPENDSEC_TOKEN=<trainer 的 token> OPENDSEC_PROJECT=root/team-a \
    .claude/skills/opendsec-deploy/scripts/smoke.sh root/py:3.12 container,microvm

# 功能：逐项检查创建、命令、文件、网络、暂停、fork、批量、镜像
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
OPENDSEC_TOKEN=<trainer 的 token> OPENDSEC_PROJECT=root/team-a .venv/bin/python sdk/python/examples/test_features.py

# 压测：600 秒、8 并发，结束时打印成功数、失败数和延迟分位数
OPENDSEC_TOKEN=<trainer 的 token> OPENDSEC_PROJECT=root/team-a .venv/bin/python sdk/python/examples/load_test.py 600 8
```

建议在压测的同时做一次故障演练：硬重启一台管控节点，或者停掉 IAM leader 所在的进程，确认压测的失败数为 0。

## 7. 不能访问外网的机房

用离线安装包：在能上网的机器上 `deploy/offline/build-bundle.sh`，拷到运维机上解压。步骤与上文相同，区别是：

- 系统软件包从安装包的 `debs/` 安装：设置 `OPENDSEC_DEBS=<解压目录>/debs`；
- 版本用安装包里打包好的：`<解压目录>/deploy/prod/opendsecops release-add <解压目录>/release/<版本>`；
- 镜像从安装包的 `images/` 导入，例如 `opendsecctl image import <解压目录>/images/python-3.12.tar -as root/py:3.12 -store /mnt/opendsec-images`；
- SDK 和 E2B SDK 从安装包的 `wheels/` 安装：`pip install --no-index --find-links wheels opendsec`。

详见 `deploy/offline/README.md`。

## 8. 下一步

- 升级、改配置、加机器、维护、证书、故障处理：[运维手册](OPERATIONS.md)
- 监控与告警：[监控与告警](MONITORING.md)
- 服务目标：[SLO](SLO.md)
- 安全加固：[安全模型](SECURITY_MODEL.md)
- 让 E2B SDK 接入：[运维手册 §4「E2B 网关」](OPERATIONS.md)
