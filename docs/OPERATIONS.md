# OpenDsec 生产运维手册

本文是多机生产集群的安装、日常操作和故障处理手册。设计背景见 SPEC §27，组件说明见 `deploy/README.md`。只想在一台机器上试用，见 `deploy/quickstart.sh`（README「单机部署」）。

## 1. 拓扑

下面以示例清单 `deploy/prod/inventory.example` 为例：

| 节点 | 组件 | 说明 |
|---|---|---|
| ctl-1、ctl-2、ctl-3 | iam、watcher、apiserver、fleet 各一个副本；ctl-3 另跑 Prometheus 和 Alertmanager | 管控节点，每个故障域一台，4 核 8G 起步，不跑 sandbox |
| node-a1、node-b1、node-c1 … | edge、节点代理 | 计算节点：裸金属或开了嵌套虚拟化的云主机，跑 sandbox |

- 任意一台管控节点宕机，集群都能继续创建和使用 sandbox。计算节点宕机时，它上面的 sandbox 随之丢失，新的 sandbox 调度到其他节点。
- 小集群可以把管控组件和 edge 放在同一批机器上（inventory 里同一行写多个角色）。
- 共享存储（NAS）挂在所有 apiserver 和 edge 节点的 `/mnt/opendsec-images`，存放镜像和快照。
- 内网负载均衡（下文称 LB）监听 7100 端口（四层 TCP），后端是所有 apiserver。客户端只使用 LB 的地址。

### 端口（安全组只在 VPC 内放行）

| 端口 | 用途 | 谁来访问 |
|---|---|---|
| 7100 | apiserver 公共 API（TLS） | LB、运维机 |
| 7001 / 7011 | IAM gRPC / Raft 复制 | 所有组件 / IAM 副本之间 |
| 7002 | watcher | apiserver、edge |
| 7201 | edge | watcher、apiserver、其他 edge、fleet |
| 7300 | fleet（集群管理，§6） | 节点代理、apiserver、其他 fleet 副本 |
| 7400 | E2B 网关（可选，§4） | 用 E2B SDK 的调用方、LB |
| 9461–9467 | 指标、`/healthz`、`/readyz`（iam、watcher、apiserver、edge、fleet、节点代理、E2B 网关） | Prometheus、LB 健康检查（9463，E2B 网关 9467）、节点代理（本机） |
| 9100 | node_exporter | Prometheus |
| 9090 / 9093 | Prometheus / Alertmanager | 运维人员 |

### 基础设施要求
- **NAS**：使用 NFS 4.1 及以上版本，并且必须关闭 root squash（权限组里设为「不限制 root」）。edge 以 root 身份写快照，apiserver 要删除这些快照。
  - 挂上之后、迁移之前先跑 `opendsecctl image store-check -store /mnt/<新挂载点>`（不需要连集群），必需项全部 ok 才能用。不支持 `trusted.*` xattr 没关系（SPEC §29.5）。
  - 挂载参数：`vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev`。4.1 也能用，但找不到稀疏文件里的空洞：在另一台节点上用内存快照创建 sandbox 时，要把磁盘和内存按全尺寸读一遍（实测慢一倍多，`store-check` 会提示）。`lookupcache=positive` 让客户端不缓存「文件不存在」：不加的话，一台节点在镜像登记之前查过它，之后最长约一分钟内可能仍然找不到（SPEC §30）。
  - fstab 写法：`<nas>:/ /mnt/opendsec-images nfs4 vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev 0 0`。
  - 每个节点的 NFS 客户端标识必须不同。没有设置标识时，NFSv4 客户端用主机名标识自己，主机名相同的节点（比如从同一个镜像克隆出来的）会被服务端当成同一个客户端，互相作废对方的打开文件和锁（SPEC §33.4）。`deploy/node/install.sh` 用 `/etc/machine-id` 设置标识（`/etc/modprobe.d/opendsec-nfs.conf`），新的标识要等重新挂载、且旧挂载没有人在用之后才生效，最简单的是重启节点。检查方法：在 NFS 服务端看 `/proc/fs/nfsd/clients/*/info` 里的 `name`，每个节点应该各不相同；或者看服务端 syslog 里 `rpc.mountd` 的 `client attached/detached` 是否在不停地刷。
- **LB**（云上的四层负载均衡，或自建的 HAProxy / LVS）：配置如下。
  - 监听 TCP 7100，不能用七层 HTTP/gRPC 监听：TLS 由 apiserver 自己终结。
  - 健康检查用 HTTP，端口 9463，路径 `/readyz`，间隔 2 秒，连续 2 次失败即判定不健康。
  - 空闲超时不低于 30 秒：apiserver 每 20 秒给空闲连接发一次 ping，安静的流（批量创建、长命令）因此不会被 LB 断开。
  - 如果 LB 支持，请保留客户端源地址，否则按地址限流的认证失败会集中算到 LB 上（见 `deploy/README.md`「准入与限流」）。
  - apiserver 的证书必须包含 LB 的地址：执行 `opendsecops certs <LB地址>`，再执行 `opendsecops push-config all` 和 `opendsecops restart`。

**不能访问外网的机房**：用离线安装包（`deploy/offline/README.md`，SPEC §38）。步骤和下文相同，只是软件包用 `OPENDSEC_DEBS`、版本用 `opendsecops release-add`、镜像从文件导入。

## 2. 运维机与 opendsecops

运维机可以是任意一台能 ssh 到所有节点的机器（也可以是某台管控节点），目录默认是 `/root/opendsec-ops`，可以用 `OPENDSEC_OPS` 改为其他位置；ssh 私钥默认 `/root/.ssh/opendsec-ops`（`OPENDSEC_SSH_KEY`）。目录内容：

```
inventory      节点与角色（参照 deploy/prod/inventory.example）
opendsec.json      集群配置（参照 deploy/prod/cluster.example.json）
admin.token    管理员 token，权限 0600
pki/           集群 CA（ca.key 只放在这里）
releases/      打包好的版本
backups/       IAM 备份
current ->     releases/<当前版本>
```

`deploy/prod/opendsecops help` 会列出全部命令。常用命令：

| 命令 | 作用 |
|---|---|
| `opendsecops release bin/` | 把 `make build` 的产物打包成一个版本（版本号来自 `opendsecctl version`） |
| `opendsecops certs [LB地址]` | 生成 CA 和证书；指定 LB 地址时，重签 apiserver 的证书 |
| `opendsecops install all` | 首次安装：创建用户和目录，下发版本、配置、证书、systemd unit 和节点准备脚本。不启动任何服务 |
| `opendsecops start all` | 按 IAM → watcher → apiserver → edge 的顺序启动，并等待全部就绪 |
| `opendsecops status` | 检查每个组件的 `/readyz`，并显示当前的 IAM leader |
| `opendsecops versions` | 每个组件正在运行的版本 |
| `opendsecops upgrade <版本>` | 滚动升级 |
| `opendsecops rollback <旧版本>` | 回滚。过程与升级相同，只是换成旧版本 |
| `opendsecops push-config all` + `opendsecops restart` | 修改配置或证书后，下发并滚动重启 |
| `opendsecops backup` | 立即备份一次 IAM 到运维机 |
| `opendsecops rotate-ca 1\|2\|3` | 不停服轮换集群 CA（见 §4「证书」） |
| `opendsecops monitor [webhook]` | 安装 node_exporter、Prometheus 和 Alertmanager，告警发往 webhook |

每个节点只会拿到 `ca.crt` 和本机组件的证书与私钥。`admin.token` 只下发到 IAM 节点，因为 IAM 启动时需要它；集群配置里只写 `admin_token_file`，不写 token 本身。

## 3. 首次安装

```sh
make build && deploy/prod/opendsecops release bin/
# 编辑 $OPENDSEC_OPS/inventory、opendsec.json，写入 admin.token（dsk.admin.<随机 32 位十六进制>）
deploy/prod/opendsecops certs <LB地址>
deploy/prod/opendsecops install all
# 各节点挂载 NAS 到 /mnt/opendsec-images（写入 fstab）
deploy/prod/opendsecops start all
deploy/prod/opendsecops monitor <告警 webhook>
deploy/prod/opendsecops status
```

从单机 IAM（`iam.state` 文件）迁移到 3 副本：
1. 在旧集群上执行 `opendsecctl iam backup -out iam.json.gz`。
2. 停掉旧服务，用新配置执行 `install` 和 `start`。新 IAM 会用同一个 admin token 自举。
3. 执行 `opendsecctl iam restore iam.json.gz`。
4. 配额租约不在备份里。edge 上已有的 sandbox 会在下一轮对账（`reconcile_interval`，默认 30 秒）时被 IAM 重新登记。

## 4. 日常操作

### 升级
```sh
make build && deploy/prod/opendsecops release bin/
deploy/prod/opendsecops upgrade <新版本>
```
- 执行顺序：
  1. 把新版本下发到所有节点并校验 sha256；
  2. 逐个重启组件，每个都等到 `/readyz` 返回 200 才继续下一个；
  3. IAM 先重启 follower，最后重启 leader；
  4. 然后依次是 watcher、apiserver、edge。每台 edge 重启后，还要等它在集群快照中恢复为 healthy。
- 任何一步超时（`OPENDSEC_READY_TIMEOUT`，默认 180 秒）就停下，不再继续。已经升级的组件保持新版本；要回滚就执行 `opendsecops rollback <旧版本>`。
- apiserver 收到 SIGTERM 后先让 `/readyz` 失败，再继续服务 6 秒，等 LB 把它摘掉，然后给进行中的请求最多 30 秒完成。SDK 会对断开的请求做重试和流续传（SPEC §26）。
- edge 重启不会影响 sandbox：前提是配置了 `keep_sandboxes_on_exit` 和 `persist_state`，unit 使用 `KillMode=process`。新 edge 进程启动后会重新接管这些 sandbox。
- 每个节点保留最近 3 个版本，`OPENDSEC_KEEP_RELEASES` 可以调整。已经在运行的 sandbox 继续使用它启动时挂载的那一版 agent。

### 维护一台机器
```sh
opendsecctl edge drain node-a1   # 停止往 node-a1 调度新 sandbox，已有的照常运行
# 等存量 sandbox 结束；暂停中的可以迁走（SPEC §26.2）
systemctl stop opendsec-edge                # 在 node-a1 上；管控节点则停 opendsec-{apiserver,watcher,fleet,iam}@<id>
# 维护……然后启动这些服务并执行：
opendsecctl edge drain node-a1 -undo
```
同一时间只能维护一台 IAM 节点，否则会失去多数派。

需要重启整机时，步骤同上（drain → `systemctl reboot` → 检查 → `drain -undo`）。开机后的检查：`/data`、`/mnt/opendsec-images` 和 swap 都已挂上，`sysctl vm.swappiness` 是 10，四个 `/readyz` 都返回 200，`opendsecctl status` 里这台 edge 恢复 healthy。

注意：
- 整机重启后，这台机器上的 sandbox 全部丢失，暂停中的 microVM 也一样：edge 接管时发现它的网络命名空间已不存在，于是把它连同快照一起清掉，调用方再访问会得到 not_found。
- 重启期间 Prometheus 会触发 `OpenDsecComponentDown`、`OpenDsecEdgeUnhealthy` 等告警；Alertmanager 要配好接收方（`opendsecops monitor <webhook>`），否则告警不会发给任何人。
- 一次实测（裸金属，固件自检约 107 秒）见 SPEC §27。

### 证书
- 组件证书有效期 825 天，但不会超过 CA 的到期时间。CA 有效期 10 年。到期前 30 天会触发 `OpenDsecCertExpiringSoon` 告警。
- **续期组件证书**：在运维机上删除对应的 `.crt` 和 `.key`，执行 `opendsecops certs` 重新签发（LB 地址会保留），然后执行 `opendsecops push-config all` 和 `opendsecops restart`。
- **轮换 CA，不停服**：依次执行下面三步，每一步都包含一次下发配置和滚动重启。
  1. `opendsecops rotate-ca 1`：生成新 CA，所有节点同时信任新旧两个 CA，组件证书暂时不变。
  2. `opendsecops rotate-ca 2`：用新 CA 重签全部组件证书。
  3. `opendsecops rotate-ca 3`：移除旧 CA。

  第 1 步之后，把 `$OPENDSEC_OPS/pki/ca.crt`（同时含新旧两个 CA）发给所有客户端；第 3 步之后，再发一次（只含新 CA）。
  - 为什么要分三步：组件在重启前一直使用旧的证书和信任列表。如果直接用新 CA 重签，已经重启和尚未重启的组件之间会互相校验失败。

### 扩容 edge
启用 fleet（§6）之后，加机器用 `opendsecops add-node` 和 `opendsecctl fleet node accept`，见 §6.3。下面是启用之前的做法：
1. 在 `opendsec.json` 的 `edges` 里加一项，在 inventory 里加一行。
2. 执行 `opendsecops certs`（会补签新 edge 的证书）。
3. 依次执行 `opendsecops install <节点>`、`opendsecops push-config all`、`opendsecops restart`、`opendsecops start <节点>`。

### 接入新租户
```sh
export OPENDSEC_ADDR=<LB地址>:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
opendsecctl project create root <名字> -quota sandboxes=<N>
opendsecctl principal create root/<名字> <调用方> -kind agent          # 输出里的 token 只显示这一次
opendsecctl grant root/<名字> <调用方> sandbox.create,sandbox.operate
opendsecctl grant root <调用方> layer.use                            # 允许使用 root/ 下的镜像
```
- 给调用方的接入包建议包括：`docs/USER_GUIDE.md`（填好地址和项目）、SDK wheel、`ca.crt`、`sdk/python/examples/quickstart.py` 和 token。token 单独通过安全渠道发送。
- token 最长 90 天（`max_token_ttl_s`）。到期前用 `opendsecctl token create <调用方>` 换发，等对方换上新 token 后，用 `opendsecctl token revoke` 撤销旧的。

### 用量（SPEC §41）
```sh
opendsecctl usage root/<名字> -from 2026-10-01 -to 2026-10-31          # 每个项目在这段时间的合计
opendsecctl usage root -from 2026-10-01 -daily -csv > usage.csv        # 按天、按项目，CSV
```
- 列出项目自己和全部子项目：启动的 sandbox 数、sandbox·小时、CPU 核·小时、内存 GB·小时、GPU·小时。按 UTC 日期统计，每行只算这个项目自己的 sandbox，子项目单独成行，最后一行是合计。
- 计的是配额租约：sandbox 占着资源的时间都算，暂停中也算（容量是它的）。还在运行的算到查询时刻。
- 需要在该项目上有 `project.admin`。数据保留 400 天，在 IAM 里随 Raft 复制，不会因为节点重启或故障切换而丢失。
- Python SDK：`await client.get_usage("root/<名字>", start="2026-10-01", end="2026-10-31")`。

### 入口
- **有 LB**：SDK 配置 `OPENDSEC_ADDR=<LB地址>:7100`。
- **没有 LB**：SDK 配置所有 apiserver 的地址，如 `OPENDSEC_ADDR=10.0.0.11:7100,10.0.0.12:7100,10.0.0.13:7100`，SDK 自动轮询并在故障时切换（SPEC §27.8）。
- **对公网开放**：只放行 TCP 7100，并且只对调用方的来源地址放行；apiserver 证书要包含公网地址或域名（`opendsecops certs`）。其他端口一律不对外开放：IAM、watcher、edge、fleet 的端口，9461–9466、9100、9090、9093。
- **从直连切到 LB**：
  1. 执行 `opendsecops certs api.opendsec.internal,<LB地址>,...`；
  2. 执行 `opendsecops push-config all` 和 `opendsecops restart`；
  3. 通知调用方把 `OPENDSEC_ADDR` 改成 LB 地址；
  4. 等旧地址上没有流量后，再收紧安全组。

### E2B 网关（可选，SPEC §37）
让用 E2B SDK 的调用方直接接入。
1. 在集群配置里加 `e2b` 一节，按 §6.2 用 fleet 下发：
   ```json
   "e2b": {
     "gateways": [{"addr": "10.0.0.11:7400"}, {"addr": "10.0.0.12:7400"}],
     "project": "root/e2b",
     "templates": {"base": {"image": "root/py:3.12", "backend": "microvm", "cpu": 2, "memory_mb": 1024}},
     "max_timeout_s": 86400
   }
   ```
2. 给机器加上角色，一台一台来：`opendsecctl fleet node set <名字> -roles <原有角色>,e2b=<序号>`（序号对应 `gateways` 里的位置），再执行 `opendsecctl fleet node sync <名字>`。节点代理会把这台机器同步到它应有的版本和配置，启用并启动 `opendsec-e2b@<序号>`，就绪后再做下一台。
3. 前面放 LB：转发 TCP 7400，健康检查用 HTTP 9467 的 `/readyz`，空闲超时不低于 60 秒（SDK 的流每 50 秒保活一次）。对外要用 HTTPS 时，在 LB 上终止 TLS，或者在 `gateways` 里配 `tls_cert` 和 `tls_key`。
4. 调用方的设置：`E2B_API_URL` 和 `E2B_SANDBOX_URL` 都指向网关，`E2B_API_KEY` 用他的 OpenDsec token。这个 token 需要在 `project` 上有 `sandbox.create`、`sandbox.operate`，在镜像所在项目上有 `layer.use`。要用快照（`create_snapshot()`）的，还要在 `project` 上有 `layer.publish`：快照存成这个项目里的镜像。

网关不保存状态，每个请求都用调用方自己的 token 调 apiserver，所以权限、配额、审计和直接用 OpenDsec SDK 完全一样。

**E2B code interpreter**（`e2b_code_interpreter` 包）要一个专门的 template：
1. 下载 E2B 的 code-interpreter 仓库，用 `deploy/e2b/build-code-interpreter.py` 构建镜像。它会建一个 microVM，装好 Jupyter 和 E2B 的服务，拍成带内存的快照 `root/code-interpreter:v1`。需要能访问外网（pip、apt），以及在 `root` 上的 `layer.publish` 权限。
2. 在 `e2b.templates` 里加上 `"code-interpreter-v1": {"image": "root/code-interpreter:v1", "backend": "microvm", "cpu": 2, "memory_mb": 2048}`。`cpu` 和 `memory_mb` 必须和快照一致。
3. 按 §6.2 下发配置。用 `test/e2e/testdata/e2b_code_interpreter_check.py` 验收。

## 5. 故障处理

### 一台 IAM 节点宕机
- 剩下的两个副本继续服务。会触发 `OpenDsecIAMQuorumAtRisk` 告警，这时**不能再有第二台宕机**。
- 机器能恢复：启动 `opendsec-iam@<id>`，它会自动追上进度。
- 机器无法恢复（换一台新机器、新地址），以替换副本 2 为例，新副本 id 用 3：
  ```sh
  opendsecctl iam member remove 2
  # opendsec.json：把 replicas 里 id 2 的那项改成 id 3 的新地址；inventory 也相应修改
  opendsecops certs && opendsecops install <新节点>
  echo 'OPENDSEC_IAM_FLAGS=-join' > /etc/opendsec/iam.env      # 在新节点上
  opendsecops start <新节点>      # 不会自举，等待被加入；/readyz 在加入前返回失败，所以这一步会超时，属于正常现象
  opendsecctl iam member add 3 -raft-addr <新IP>:7011 -iam-addr <新IP>:7001
  rm /etc/opendsec/iam.env       # 加入之后数据目录里已有 Raft 状态，-join 不再起作用
  opendsecops push-config all && opendsecops restart     # 让其他组件使用新的地址列表
  ```
- 原机器保留原地址、只是换了盘：在它上面用 `-join` 启动即可。它仍在成员列表里，leader 会用快照把状态补给它。

### IAM 全部丢失（灾难恢复）
1. 清空每个副本的 `/var/lib/opendsec/iam`，然后启动。新集群会用 admin token 自举。
2. 执行 `opendsecctl iam restore <最近的备份>`。备份位置：每台 IAM 节点的 `/var/backups/opendsec`，以及运维机的 `backups/`。
3. 等一轮对账，edge 上存活的 sandbox 会被重新登记到配额里。
4. 备份之后才创建的 principal、token 和项目会丢失，需要重建。

### 一台计算节点宕机
- 其他节点继续服务。
- 宕机机器上的 sandbox 随之丢失。超过 `lost_edge_grace`（120 秒）后，watcher 会释放它们占用的配额。
- 机器恢复后，edge 会接管仍在运行的 sandbox（只要整机没有重启）。整机重启后什么都接管不了，暂停中的 microVM 也会被清掉（见「维护一台机器」）。

### NAS 不可用
- 已经在运行的 microVM 不受影响：它们从本地的镜像副本和快照缓存运行。
- 已经在运行的容器也不受影响：它们挂的是镜像层在节点本地的副本（`layer_cache`，默认开启）。关闭了 `layer_cache` 的话，容器的只读层直接挂在镜像库上，读取不在页缓存里的文件会卡住，直到 NAS 恢复（SPEC §33 实测：NFS 中断 60 秒时，一条命令卡了 88 秒）。
- 依赖镜像库的操作会卡住，直到 NAS 恢复或者调用超时，包括：新建 sandbox（实测创建在中断期间最长等了 94 秒，恢复后全部成功）、pack、snapshot、跨节点 fork。
- 告警 `NodeImageStoreMissing`。NFS 用 `hard` 挂载，所以 NAS 恢复后卡住的 IO 会继续完成。

### 系统盘
- 审计日志在 `audit_dir`（默认 `/var/log/opendsec/audit`），每个 apiserver 最多保留 `audit_keep` 个文件（默认 8 个、每个 256 MB）。需要长期保存的，要定期转存到别处。
- 每个 sandbox 都会产生一些内核消息和 networkd 消息。`deploy/node/install.sh` 让它们只留在 journal 里（journal 默认最多占用文件系统的 10%），并关掉没有配置脚本的 networkd-dispatcher。不这样做的话，负载下 `/var/log/syslog` 每天增长 1 GB 以上（SPEC §33.2）。

### 告警与处理

| 告警 | 首先检查 |
|---|---|
| OpenDsecComponentDown / NotReady | `opendsecops status`；在节点上执行 `journalctl -u <unit>`。`curl <ip>:<端口>/readyz` 会返回不就绪的原因 |
| OpenDsecIAMNoLeader | 在线副本是否少于 2 个；副本之间 7011 端口是否通 |
| OpenDsecEdgeUnhealthy | 那台机器是否在线，`opendsec-edge` 是否在运行 |
| OpenDsecCreateErrors / CreateSlow | `opendsec_apiserver_create_seconds` 按 `reason` 看错误分布；查看 edge 的 `opendsec_edge_create_phase_seconds` |
| OpenDsecCapacityLow / EdgeUnderPressure | 扩容 edge，或者调低项目配额 |
| OpenDsecCertExpiringSoon | 按 §4「证书」续期 |
| OpenDsecIAMBackupStale | `systemctl status opendsec-iam-backup`；查看 `/var/backups/opendsec` |
| OpenDsecSLOCreateBurnFast / BurnSlow、SLORuntimeBurnFast / BurnSlow | 错误预算消耗过快（docs/SLO.md）：同 CreateErrors，按 `reason` 和 `method` 看是哪类错误、从什么时候开始；同一时间有没有发版、改配置或节点故障 |

## 6. 集群管理服务 fleet（SPEC §28）

机器多了以后，升级和改配置不再由运维机逐台 SSH，而是由 fleet 服务分批推进，每台机器上的节点代理在本机执行。`opendsecops` 保留，用于首次安装、签发证书、加机器和应急。

### 6.1 组成
- **`opendsec-fleet@<id>`**：与 IAM 一起放在控制面节点上，3 个副本，端口 7300（指标 9465）。持有 IAM 锁 `fleet-controller` 的副本是 leader，其他副本把请求转给它。期望状态存在 IAM 的键值区里，随 IAM 一起备份。
- **`opendsec-nodeagent`**：每台机器一个，以 root 运行（指标 9466）。每 10 秒向 fleet 上报一次，并执行 fleet 下发的操作：下载版本、切换版本、写 `/etc/opendsec/{opendsec.json,edge.env}`、重启 `opendsec-*` 服务。它只接受这几种操作。
  - 节点代理运行的是 `/opt/opendsec/agent/opendsec-nodeagent`，不随版本切换；新版本里的节点代理先通过 `-check` 自检，才会替换它。
  - fleet 全挂时，节点代理不做任何改动，组件和 sandbox 照常运行。
- **命令行**：`opendsecctl fleet ...`，经 apiserver 访问，需要 root 项目上的 `fleet.view`（查看）或 `fleet.operate`（操作）权限，`project.admin` 同时具备两者。所有操作都写入审计日志。apiserver 全挂时，在运维机上用 `-direct -fleet <副本地址> -pki $OPENDSEC_OPS/pki -ops-id ops` 直连 fleet。

### 6.2 发布和升级
```sh
make build && deploy/prod/opendsecops release bin/      # 打包，带上 deploy/deps.lock 锁定的 firecracker、jailer、内核
opendsecctl fleet release push $OPENDSEC_OPS/releases/<版本>
opendsecctl fleet rollout create -release <版本>        # 默认：试点 1 台、观察 5 分钟、每批 5%、批间 60 秒
opendsecctl fleet rollout status [-steps]
```
- 顺序：先让全部目标机器下载新版本；控制面节点逐台升级，IAM leader 所在的节点最后；然后 edge 先升 1 台试点，观察结束后按批升级，每批里同一故障域最多占一半。
- 每台 edge 升级前先暂停调度（drain），升级后等本机 `/readyz` 和 watcher 快照都正常，再恢复调度。edge 重启不影响已有的 sandbox。
- 每批开始前检查：本次已升级的机器仍然正常，所有控制面组件就绪。配置了 `fleet.prometheus_url` 和 `fleet.gates` 时，观察期内和每批开始前还会检查这些 PromQL：超过阈值或者读不出来（Prometheus 不可达）都会暂停升级；查询没有样本按 0 处理，但前提是 Prometheus 确实在抓取 OpenDsec（`fleet.gates_up`，默认 `up{job=~"opendsec-.*"}` 至少有一个为 1），否则暂停，消息是 `gate data unavailable`。被闸门暂停后执行 `resume`，闸门放行到下一批开始为止。回滚不检查闸门。
- **出问题时**：失败的机器自动回到原版本并被锁定（pinned），升级暂停。之后可以：
  - `opendsecctl fleet rollout resume <id>`：接受这些失败，继续升级其余机器；
  - `opendsecctl fleet rollout rollback <id>`：把已升级的机器按相反顺序分批退回原版本；
  - `opendsecctl fleet rollout abort <id>`：停在当前位置。

  查明原因后，用 `opendsecctl fleet node unpin <名字>` 解除锁定。
- **只改配置**：`opendsecctl fleet config put opendsec.json -note ...` 生成新的配置代数，再执行 `opendsecctl fleet rollout create -config-gen <代数>`。配置里不能有 `service_token` 或 `iam.admin_token`。
- 有 fleet 副本时，`opendsecops upgrade` 和 `restart` 会拒绝执行；应急时可以加 `OPENDSEC_FORCE=1`。

### 6.3 加机器、维护、下线
```sh
deploy/prod/opendsecops add-node n17 <ssh地址> <私网地址> edge=n17   # 签证书、安装、启动节点代理
opendsecctl fleet nodes -state pending                               # 节点代理上报后出现在这里
opendsecctl fleet node accept n17 -roles edge=n17 -domain az2        # 下发当前版本和配置并启动
```
- 新的 edge 不用写进 `edges`：集群配置里的 `edge_template` 适用于所有未列出的 edge。
- 给已有机器加角色（例如 `e2b`）：`node set <名字> -roles ...` 之后执行 `node sync <名字>`，一台一台来。只改角色不会启动任何东西，要等这台机器下一次被 rollout 或 sync 才部署。0.11.0-202610230504 及之前的 fleet，在多台机器同时加了角色时，rollout 会互相等待对方的新单元就绪而卡住（SPEC §37.7），这种情况要用 sync。
- 维护：`opendsecctl fleet node cordon <名字>` 暂停调度（fleet 会一直保持），维护完执行 `node uncordon`；`node evacuate <名字>` 在 cordon 之后等这台机器上的 sandbox 全部结束。
- 下线：先 `node evacuate <名字>`，等 sandbox 全部结束后再 `opendsecctl fleet node retire <名字>`，节点代理会停掉并禁用这台机器上的组件。没有 evacuate 完（没 cordon、还有 sandbox）时 fleet 拒绝下线；已经不上报心跳的机器可以直接下线。带控制面角色的机器要先把这些角色迁走。

### 6.4 从 opendsecops 迁到 fleet（一次性，不停机）
1. inventory 里给控制面节点加上 `fleet=<id>`，`opendsec.json` 里加上 `fleet` 段（参照 `deploy/prod/cluster.example.json`），并把 microvm 的 `firecracker`、`jailer`、`kernel` 指向 `/opt/opendsec/current/...`。
2. `opendsecops certs`：补签 fleet、节点代理和 ops 证书。
3. 用 opendsecops 做最后一次滚动升级（带 fleet 和节点代理的版本）：`opendsecops release bin/`、`opendsecops push-config all`、`OPENDSEC_FORCE=1 opendsecops upgrade <版本>`，再 `opendsecops start all` 启动 fleet 副本。
4. `opendsecops install-agent all`：每台机器启动节点代理。
5. 导入：`opendsecctl fleet release push $OPENDSEC_OPS/releases/<版本>`；`opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json`；`opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release <版本> -config-gen 1 -domain <故障域>`。
6. `opendsecctl fleet nodes`：确认每台机器都在上报，`RUNNING` 与 `RELEASE` 一致，`UNITS` 全部就绪。

