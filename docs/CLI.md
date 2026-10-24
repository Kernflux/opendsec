# 命令行参考：opendsecctl

`opendsecctl` 是 OpenDsec 的命令行工具，管理员和调用方都用它：创建和操作 sandbox、管理镜像、项目、身份和 token、查看集群、签发证书、管理集群版本（fleet）。

```
opendsecctl <命令> [参数] [选项]
opendsecctl help                 # 列出全部命令
opendsecctl fleet                # fleet 子命令的帮助
```

- 安装后在 `/usr/local/bin/opendsecctl`（单机安装）或 `/opt/opendsec/current/bin/opendsecctl`（集群节点）；运维机上是 `$OPENDSEC_OPS/current/bin/opendsecctl`。
- 选项可以写在位置参数前面或后面，例如 `opendsecctl sandbox stop <id> -addr x` 和 `opendsecctl sandbox stop -addr x <id>` 等价。
- 除特别说明外，命令的输出是 JSON（protobuf 的 JSON 形式，值为默认值的字段省略）。
- 命令成功时退出码为 0，失败时打印 `error: <reason>: <说明>` 并以非 0 退出。`exec` 以命令自己的退出码退出。

## 连接与环境变量

| 选项 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-addr` | `OPENDSEC_ADDR` | — | apiserver 地址，多个用逗号分隔 |
| `-token` | `OPENDSEC_TOKEN` | — | token。建议用环境变量，避免出现在 shell 历史和进程列表里 |
| `-project` | `OPENDSEC_PROJECT` | `root` | 默认项目 |
| `-ca` | `OPENDSEC_CA` | — | 集群 CA 证书，设置后使用 TLS |
| `-store` | `OPENDSEC_IMAGE_STORE` | — | 镜像库的挂载点（`image import`、`image gc`、`image store-check`） |
| `-deadline` | — | 5m | 整个命令的时限；`image import` 默认不限 |

单机安装后，管理员和调用方的环境分别在：

```sh
. /root/opendsec-ops/env         # 管理员：admin token，项目 root
. /root/opendsec-ops/demo.env    # 调用方：项目 root/demo 的 token，以及 E2B SDK 的变量
```

## sandbox

### `sandbox create`

```
opendsecctl sandbox create -backend <后端> [-image I] [-cpu N] [-mem MB] [-disk MB] [-gpus N]
                           [-task T] [-ttl-idle S] [-ttl-max S] [-net 规则,...] [-count N]
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `-backend` | `sim` | `microvm`、`container`、`fncall`、`fullvm`、`sim`。**默认 `sim` 只模拟，实际使用必须指定** |
| `-image` | — | 镜像，例如 `root/py:3.12` |
| `-cpu` | 1 | CPU 核数 |
| `-mem` | 1024 | 内存 MB |
| `-disk` | 0 | 可写盘 MB，0 为后端默认 |
| `-gpus` | 0 | GPU 个数 |
| `-task` | — | 任务名 |
| `-ttl-idle` | 0 | 空闲超时（秒），0 为集群默认 |
| `-ttl-max` | 0 | 最长寿命（秒），0 为集群默认 |
| `-net` | — | 网络规则，逗号分隔；`!规则` 表示收回集群默认里的一项，例如 `-net 'pypi,github.com:443,!npm'` |
| `-count` | 1 | 批量创建的个数 |

`-count 1` 时输出 sandbox 的 JSON；`-count` 大于 1 时每行输出一个结果（`序号<TAB>id`，失败的是 `序号<TAB>error<TAB>原因: 说明`），最后一行是汇总：

```
$ opendsecctl sandbox create -backend microvm -image root/py:3.12 -count 3 -task job-1
0	node-a1.4k2m…
1	node-b1.9xq1…
2	node-a1.p0zz…
created 3/3 in 412ms; failures: map[]
```

在脚本里取 id：

```sh
ID=$(opendsecctl sandbox create -backend microvm -image root/py:3.12 | grep -m1 '"id"' | cut -d'"' -f4)
```

### `sandbox get | stop | pause | resume | touch <id>`

查看、停止、暂停、恢复、刷新空闲计时。输出更新后的 sandbox。

### `sandbox list [-task T] [-all]`

列出 `-project` 及其子项目里的 sandbox；`-task` 只列这个任务的，`-all` 包括最近结束的。

### `sandbox fork <id> [-count N] [-task T] [-ttl-idle S] [-ttl-max S]`

把运行中的 sandbox 复制成 N 个（1 到 256），输出格式同批量创建。

### `sandbox network <id> <规则>... [-replace]`

修改网络规则：`pypi` 放行，`!pypi` 收回。默认合并进现有规则，`-replace` 整体替换。

```sh
opendsecctl sandbox network $ID pypi github.com:443
opendsecctl sandbox network $ID '!github.com:443'
opendsecctl sandbox network $ID '*' -replace          # 只放行全部公网
```

### `exec <id> [-session S] [-user U] [-timeout S] [--] <命令...>`

在 sandbox 里执行命令，实时输出 stdout 和 stderr，以命令的退出码退出。

- **只有一个参数**时，它是一整条 shell 命令，由 sandbox 里的 shell 解释：`opendsecctl exec $ID 'cd /srv && make test | tail'`。
- **多个参数**时，像 `ssh` 和 `docker exec` 一样，每个参数各自加引号后拼成命令：`opendsecctl exec $ID python3 -c 'print(6*7)'` 在 sandbox 里执行的就是 `python3 -c 'print(6*7)'`。
- 参数里有以 `-` 开头的（例如 `ls -la`），在命令前加 `--`，避免被当成 opendsecctl 的选项：`opendsecctl exec $ID -- ls -la /`。
- `-session`：会话名，默认 `default`；`-user`：会话第一次执行时的用户；`-timeout`：秒，超时后打印 `opendsecctl: command timed out`。

> 0.11 之前的版本把多个参数直接用空格连接，不加引号。当时为了绕开这个问题多加的一层引号（例如 `"'print(6*7)'"`）现在要去掉。

### `cp <id>:<路径> <本地文件>` / `cp <本地文件> <id>:<路径>`

在本机和 sandbox 之间复制单个文件。一次最多复制 64 MB；更大的文件用 SDK 分段读写。

## 任务

```
opendsecctl task pause|resume|stop <任务名>
```

对 `-project` 里这个任务的所有 sandbox 执行操作，输出成功和失败的个数。

## 镜像

### `image import <来源> -as <项目>/<名字>:<标签> -store <镜像库>`

把镜像导入共享镜像库并登记。要在**挂载了镜像库的机器上以 root 运行**，并且需要目标项目上的 `layer.publish`。

来源可以是：

| 来源 | 例子 |
|---|---|
| 公共仓库 | `docker.io/library/python:3.12`、`python:3.12`、`ghcr.io/org/image:tag` |
| 私有仓库 | `harbor.example.com/team/app:1.0` |
| 不带 TLS 的仓库 | 加 `-plain-http` |
| OCI layout 目录或 tar | `./python-3.12.oci.tar` |
| `docker save` 生成的 tar | `./app.tar`；文件里有多个镜像时用 `文件#名字` 选一个 |

本地文件路径要以 `/` 或 `.` 开头，文件不存在时直接报错（不会去仓库下载）。

私有仓库的凭据，按以下顺序查找：

1. `-username U -password-stdin`：密码或访问令牌从标准输入读，例如 `echo "$TOKEN" | opendsecctl image import ... -username 'robot$ci' -password-stdin`；
2. `-registry-auth FILE`：docker 格式的凭据文件；
3. `$REGISTRY_AUTH_FILE`、`$DOCKER_CONFIG/config.json`、`~/.docker/config.json`（`docker login` 保存的凭据）。

导入不设总时限（大镜像可能要很久），进度打印到标准错误。

### `image save <来源> -out <文件>`

把仓库里的镜像保存为 OCI tar，供不能上网的机器用 `image import ./文件` 导入。不需要连接集群。支持 `-plain-http`、`-username`、`-password-stdin`。

### `image compose <新镜像> <part>... [-overwrite]`

把多个镜像从底到顶叠成一个，不复制数据：

```sh
opendsecctl image compose root/rl/swe-4821:v1 root/rl/python:3.12 root/rl/django-ws:a1b2 root/tools/agent-kit:3
```

### `image list [-project P]`、`image get <名字>`、`image delete <名字>`

列出项目及其子项目的镜像；查看一个镜像；删除镜像的登记（层由 `image gc` 回收）。

### `image pack <sandbox-id> <新镜像> [-scrub a,b] [-overwrite]`

即 `pack_diff`：把 container sandbox 相对它启动镜像的改动保存为新镜像，默认清理 `/tmp`、缓存和 shell 历史，`-scrub` 追加路径（相对 `/` 的 glob）。

### `image snapshot <sandbox-id> <新镜像> [-memory] [-overwrite]`

把 sandbox 原样保存为镜像。microVM 必须加 `-memory`（连同内存）。

### `image gc -store <镜像库> [-grace 24h] [-dry-run]`

删除没有任何镜像引用的层和快照。比 `-grace` 新的不删（默认 24 小时），避免删掉正在导入或刚创建的数据。先用 `-dry-run` 看会删什么。需要设置连接参数，但只在镜像库上操作。

### `image store-check -store <目录>`

检查一个文件系统（例如新挂的 NAS）能否用作镜像库：权限、硬链接、重命名、xattr、稀疏文件等。必需项全部为 ok 才能使用。不需要连接集群。

```
$ opendsecctl image store-check -store /mnt/opendsec-images
ok    write, sync and read back a file
ok    files a root process creates are root's (no root squash)
ok    chown to another user (image files keep their owners)
ok    exclusive create (one edge builds a VM disk at a time)
ok    rename a file over another (manifests, records)
ok    rename a directory (layers are published so)
ok    hard links (snapshots link their disks)
ok    symbolic links
ok    finds the holes of sparse files (snapshots move only their data; NFS needs vers=4.2)
ok    0:0 character devices (layer whiteouts)
ok    overlay over layers kept here, whiteouts honored
ok    trusted.* xattrs
ok    user.* xattrs
/mnt/opendsec-images can hold the image store
```

不是必需的项（例如稀疏文件的空洞、`trusted.*` xattr）失败时只给出提示，仍然可以使用；必需项失败时不能用作镜像库。

## 项目、身份、权限与 token

| 命令 | 说明 |
|---|---|
| `project create <上级> <名字> [-quota k=v,...]` | 建子项目，例如 `project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000` |
| `project get <路径>` | 项目详情：配额、当前用量、各身份的权限、子项目 |
| `project delete <路径>` | 删除空项目 |
| `principal create <项目> <id> [-kind agent\|user\|service] [-ttl S]` | 建身份，**输出里的 token 只显示这一次** |
| `principal delete <id>` | 删除身份及其全部 token |
| `grant <项目> <身份> <权限>[,<权限>...]` | 授予权限，例如 `grant root/team-a trainer sandbox.create,sandbox.operate` |
| `revoke <项目> <身份> [<权限>,...]` | 收回权限，不写权限时收回全部 |
| `token create [<身份>] [-ttl S] [-desc D]` | 签发 token，默认给自己 |
| `token list [<身份>]` | 列出 token（不含密钥） |
| `token revoke <身份> <token-id>` | 撤销，约 1 秒内全集群生效。`primary` 指旧格式的主 token |
| `whoami` | 当前 token 对应的身份 |
| `usage [<项目>] [-from YYYY-MM-DD] [-to YYYY-MM-DD] [-daily] [-csv]` | 用量：默认每个项目在这段时间的合计；`-daily` 按天、按项目；`-csv` 输出 CSV |

配额的键：`sandboxes`、`cpu_cores`、`memory_mb`、`gpus`。权限的含义见[项目、身份与权限](IAM.md)。

## 集群

| 命令 | 说明 | 需要 |
|---|---|---|
| `status` | 集群快照：每个 edge 的健康、排空、容量、已分配、sandbox 数、内存和磁盘余量、压力 | — |
| `edge drain <edge-id> [-undo]` | 停止（`-undo` 恢复）往这台 edge 调度新 sandbox，已有的照常运行 | root 上的 `project.admin` |
| `iam backup -out FILE` | 备份 IAM（gzip 的 JSON，权限 0600）：身份、项目、权限、配额、token 哈希 | root 上的 `project.admin` |
| `iam restore FILE` | 用备份替换 IAM 的内容（正在运行的 sandbox 的配额租约保留） | 同上 |
| `iam members` | 列出 IAM 的 Raft 副本 | 同上 |
| `iam member add <id> -raft-addr H:P -iam-addr H:P` | 加入一个以 `opendsec-iam -join` 启动的副本 | 同上 |
| `iam member remove <id>` | 移除一个副本（例如机器已经不在了） | 同上 |
| `version` | 本程序的版本 | — |

## 证书

不需要连接集群。

| 命令 | 说明 |
|---|---|
| `pki init -config opendsec.json -out DIR [-days 365] [-ca-days 3650] [-hosts h1,h2]` | 生成集群 CA 和配置里每个组件的证书。`-hosts` 给每张证书加上额外的主机名或 IP |
| `pki ca -out DIR [-days N]` | 只生成新 CA（用于轮换 CA） |
| `pki issue -ca DIR -role <角色> -id <id> [-hosts ip1,ip2] -out DIR [-days 365]` | 给一个组件签证书。角色：`edge`、`apiserver`、`watcher`、`iam`、`fleet`、`node`、`ops` |

生产集群一般用 `opendsecops certs`，它会调用这些命令，见[多机集群部署](CLUSTER.md)。

## 本地集群与基准

| 命令 | 说明 |
|---|---|
| `cluster up` | 在当前进程里运行一整个集群，用于开发和测试 |
| `bench` | 在进程内的模拟集群上做调度基准；`-compare` 对比随机放置和 power-of-2 |

`cluster up` 的选项：

| 选项 | 默认 | 说明 |
|---|---|---|
| `-config` | 生成的模拟集群 | 集群配置文件 |
| `-sim-edges` | 4 | 没有 `-config` 时模拟的 edge 个数 |
| `-apiservers` | 1 | 没有 `-config` 时 apiserver 的个数 |
| `-runtime` | `sim` | 生成的集群里 container 后端的运行时：`sim` 或 `linux`（真实容器，需要 root） |
| `-microvm-kernel` | — | 同时提供 `microvm` 后端，使用这个 guest 内核 |
| `-image-store` | — | 共享镜像库目录（启用镜像库、`pack_diff`） |
| `-state-dir` | `/var/lib/opendsec` | sandbox 状态目录（linux 运行时） |
| `-host-image` | true | 提供开发用的 `host` 镜像（宿主机的 `/` 作为只读底层，会暴露宿主机文件，只用于开发） |
| `-disk-reserve-mb` | 512 | 状态目录剩余空间低于此值时拒绝创建，-1 关闭 |
| `-tls` | false | 生成 CA 和证书，以 mTLS 运行 |
| `-audit-dir` | — | apiserver 审计日志目录 |
| `-metrics` | — | Prometheus 指标地址，例如 `:9464` |
| `-write-config` | — | 把实际使用的配置（含绑定的地址）写到这个文件 |
| `-log` | `info` | 日志级别 |

```sh
./bin/opendsecctl cluster up -sim-edges 1 -runtime linux -image-store /mnt/opendsec-images \
    -microvm-kernel /opt/opendsec/vm/vmlinux-6.1.167-opendsec
# 按输出设置 OPENDSEC_ADDR、OPENDSEC_TOKEN、OPENDSEC_PROJECT
```

## fleet：集群版本和配置

经 apiserver 访问，需要 root 上的 `fleet.view`（查看）或 `fleet.operate`（操作）；`project.admin` 两者都包括。所有操作都写入审计日志。

| 命令 | 说明 |
|---|---|
| `fleet nodes [-state S] [-role R] [-domain D]` | 列出机器：状态、故障域、角色、期望版本、实际版本、单元就绪数、最后心跳 |
| `fleet node get <名字>` | 一台机器的详情 |
| `fleet node accept <名字> -roles edge=<id>[,...] [-domain D] [-addr-ip IP] [-labels k=v,...]` | 接纳新上报的机器，下发当前版本和配置并启动 |
| `fleet node set <名字> [-roles ...] [-domain D] [-addr-ip IP] [-labels k=v,k=]` | 修改角色、故障域、标签（`k=` 删除标签）。只改记录，不部署 |
| `fleet node sync <名字>` | 把这台机器同步到它应有的版本、配置和角色 |
| `fleet node cordon \| uncordon <名字>` | 暂停、恢复往它调度 |
| `fleet node evacuate <名字> [-deadline 1h]` | cordon，然后等它上面的 sandbox 全部结束 |
| `fleet node retire <名字>` | 下线：停止并禁用它的组件 |
| `fleet node pin <名字> [-reason R]`、`unpin <名字>` | 锁定、解锁：锁定的机器不参与 rollout |
| `fleet import -inventory FILE -release V [-config-gen G] [-domain D]` | 登记已经在运行版本 V 的机器（从 opendsecops 迁移时用） |
| `fleet releases` | 已上传的版本 |
| `fleet release pack -bin DIR -units DIR [-deps DIR] -out DIR` | 打包版本目录（通常用 `opendsecops release`） |
| `fleet release push <版本目录> [-notes N]` | 上传版本到 fleet 的所有副本 |
| `fleet config put <cluster.json> [-note N]` | 上传新的集群配置，生成新的配置代数 |
| `fleet config get [-gen N] [-out FILE]` | 取出某一代配置 |
| `fleet rollout create [-release V] [-config-gen G] [...]` | 发起升级或配置变更，见下表 |
| `fleet rollout status [<id>] [-steps]` | 查看进度，默认最新的一次；`-steps` 列出每台机器 |
| `fleet rollout pause \| resume \| abort \| rollback <id>` | 暂停、继续、中止、回滚 |
| `fleet rollouts` | 历次 rollout |

`fleet rollout create` 的选项：

| 选项 | 说明 |
|---|---|
| `-release V`、`-config-gen G` | 目标版本、目标配置代数（至少一个） |
| `-roles`、`-domains`、`-nodes`、`-labels` | 只对这些角色、故障域、机器、标签的机器做 |
| `-canary N` | 先单独升级的试点台数，默认 1；-1 表示不要试点 |
| `-bake S` | 试点和每批升级后的观察时间（秒），默认 300；-1 表示不观察 |
| `-batch N` | 每批的台数，默认非控制面机器数的 5%（至少 1，最多 100） |
| `-max-per-domain N` | 每批里同一故障域最多几台，默认每批台数的一半（至少 1） |
| `-pause S` | 批与批之间的间隔（秒），默认 60；-1 表示不间隔 |
| `-max-failures N` | 允许失败的台数，超过就暂停；默认 0，即第一台失败就暂停 |
| `-step-timeout S` | 单台机器的超时（秒），默认 600 |
| `-note N` | 备注 |

apiserver 全部不可用时，在运维机上用 ops 证书直连 fleet：

```sh
opendsecctl fleet nodes -direct -fleet 10.0.0.1:7300,10.0.0.2:7300 -pki $OPENDSEC_OPS/pki -ops-id ops
```

完整的发版流程见[运维手册 §6](OPERATIONS.md)。
