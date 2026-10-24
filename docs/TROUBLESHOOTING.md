# 故障排查

按现象查找原因和处理方法。每一条都来自实际遇到过的问题。还没找到的，按 §1 收集信息后[提 issue](https://github.com/Kernflux/opendsec/issues)。

## 1. 先收集这些信息

```sh
opendsecctl version                                   # 客户端版本
deploy/prod/opendsecops status                        # 每个组件是否就绪（运维机）
deploy/prod/opendsecops versions                      # 每个组件运行的版本
opendsecctl status                                    # 集群快照：每个 edge 的健康、容量、压力
opendsecctl fleet nodes                               # 由 fleet 管理时：每台机器的状态
journalctl -u 'opendsec-*' -p warning --since -1h     # 各节点上：最近一小时的警告和错误
curl -s <节点>:9463/readyz                            # 未就绪时返回原因（各角色端口见监控与告警）
```

调用失败时，记下错误的 `reason` 和完整的说明、时间、sandbox id。sandbox id 的前半部分是它所在的节点，到那台节点上看 `journalctl -u opendsec-edge`。

## 2. 安装

| 现象 | 原因 | 处理 |
|---|---|---|
| quickstart 报 `[x] command make`、`[x] Go 1.27+` | 新机器没有装编译工具 | 见[单机安装详解 §2](INSTALL.md) |
| `apt install` 报 `has no installation candidate` | 全新的云镜像没有软件包索引 | 先 `apt update` |
| `python3 -m venv` 报 ensurepip 不可用 | 缺 `python3-venv` | `apt install -y python3-venv` |
| `pip install` 报 externally-managed-environment | Ubuntu 24.04 不允许往系统 Python 装包 | 用虚拟环境：`python3 -m venv .venv && .venv/bin/pip install ...` |
| `could not fetch the guest kernel pinned in deploy/deps.lock` | 访问不了 GitHub Release | `--kernel FILE`、`--build-kernel`，或 `--no-microvm`；集群用 `OPENDSEC_KERNEL=<文件>` |
| `[x] port 7100 is in use`、`already holds a cluster` | 之前装过 | `deploy/quickstart.sh --uninstall` 后重装 |
| IAM 启动失败，日志说 admin token 是占位值 | 配置里还是示例的 `change-me` | 生成真正的 token（`dsk.admin.$(openssl rand -hex 16)`） |
| 配置校验报 `zone ... must be "onprem" or "cloud"` | `edges` 或 `edge_template` 的 `zone` 写了别的值 | 只能是这两个值 |
| edge 启动失败：`erofs_images needs mkfs.erofs` | 节点缺 erofs-utils | `apt install erofs-utils`；新版 `opendsecops install` 会自动装 |
| `opendsecops release` 下载内核失败 | 同上，访问不了 GitHub | 设置 `OPENDSEC_KERNEL`，或把文件放进 `~/.cache/opendsec-deps/` |
| ssh 一直不返回（运维机执行远程命令时） | 远程后台进程没有和会话脱离 | 用 `ssh -f host 'setsid nohup cmd > log 2>&1 < /dev/null &'` |

## 3. 创建 sandbox

| 错误 | 原因 | 处理 |
|---|---|---|
| `quota_exceeded: root/team-a: sandboxes 100+1 > 100` | 项目（或某个祖先）的配额用完了 | 停掉不用的 sandbox（`list_sandboxes` 找出来）；或者申请调高配额。错误信息指出了是哪一级、哪个键 |
| `no_capacity` | 所有候选节点都满了，或处于内存、磁盘、CPU 压力下，或在排空 | `opendsecctl status` 看各节点的 `alloc`、`under_pressure`、`draining`；扩容或稍后重试 |
| 全部创建都 `no_capacity`，但 edge 是健康的 | edge 的 `zone` 不是 `onprem`（旧版本不校验） | 改成 `onprem` |
| `invalid: ... ttl_max ... exceeds` | 请求的寿命超过 `max_ttl_max_s` | 调小，或请管理员调高上限 |
| `invalid: backend "microvm" ...` / 后端不存在 | 集群没有这个后端（例如节点没有 KVM） | 用 `opendsecctl status` 看各节点的 `backends` |
| `not_found: image ...` | 镜像名写错，或镜像没导入 | `opendsecctl image list -project root` |
| 镜像刚登记，某台 edge 约 1 分钟内报 `image ... not found` | NFS 客户端缓存了「文件不存在」 | NFS 挂载参数加 `lookupcache=positive` |
| `forbidden: ... lacks sandbox.create on ...` | 没有项目的创建权限 | 项目管理员 `grant` |
| `forbidden: ... lacks layer.use on root` | 没有镜像所属项目的使用权限 | `grant root <身份> layer.use` |
| `invalid: memory ... snapshot` / 从快照创建失败 | `memory_limit_mb` 和快照时不同 | 用快照时的内存大小 |
| 从快照创建一直等待 | 快照还在发布到镜像库（刚制作，在其他节点上用） | 等发布完成；镜像库慢时会久一些 |
| 只有部分节点能用某个快照 | 快照只放到 Firecracker 版本相同的节点 | 升级 Firecracker 后重新制作快照 |
| 批量创建经过负载均衡时报 `Stream removed`，负载均衡日志里是 `cD` | 负载均衡的空闲超时断开了安静的流 | 空闲超时设为 30 秒以上；新版服务端每 20 秒 ping 一次 |
| `rate_limited` | 超过每个身份的限流 | 退避重试；批量请用 `run_sandboxes`（服务端排队，不会因限流失败） |

## 4. 执行命令和文件

| 现象 | 原因 | 处理 |
|---|---|---|
| `invalid: sandbox ... is STOPPED` | sandbox 已经停止：被调用方停止，或者空闲超时、最长寿命到了 | `get_sandbox` 看 `message`（例如 `idle timeout (ttl_running_stop) reached`）；需要更长时间就调大超时 |
| `not_found` | sandbox 已清理（结束 10 分钟后），或所在节点宕机/重启 | 节点重启后上面的 sandbox 全部丢失，重新创建 |
| `ShellResult.timed_out` 为 True | 命令超过了 `timeout` | 调大 `timeout`，或改用后台命令 + `get_output` |
| 输出不完整，`truncated` 为 True | 单次调用最多返回每个流 16 MB | 用 `get_output(cmd_id, stdout_offset=...)` 继续取 |
| `dropped_bytes` 大于 0 | 输出超过每个流 64 MB 的记录上限 | 把输出写到文件，再分段读 |
| 写或读 4 MB 以上的文件失败，报 `quota_exceeded: grpc: received message larger than max` | 较早的代码里单个消息上限是 4 MB（CHANGELOG 0.11.0「Fixed」第一条修复了它） | 升级；临时办法：分块读写（每块 3 MB 以下） |
| 命令输出 4 MB 以上时整个调用失败 | 同上 | 同上；临时办法：输出重定向到文件，再分段读 |
| `opendsecctl exec $ID python3 -c "'print(1)'"` 什么都不输出 | 0.11 改了 `exec` 的参数处理，旧的绕过写法多了一层引号 | 写成 `opendsecctl exec $ID python3 -c 'print(1)'` |
| `exec` 的参数被当成 opendsecctl 的选项 | 命令里有 `-` 开头的参数 | 在命令前加 `--`：`opendsecctl exec $ID -- ls -la` |
| 普通用户会话里写不了系统目录 | 会话以 `user` 指定的用户运行 | 预期行为；需要 root 的操作放在另一个会话 |
| 同一会话传了不同的 `user`，没有生效 | 会话第一次执行时就确定了用户 | 换一个会话名 |

## 5. 网络

见[网络策略 §6](NETWORK.md)。最常见的两个：

- 域名解析失败：域名没有放行（规则不匹配时 DNS 代理返回「域名不存在」）。
- 访问内网服务超时：内网地址必须用地址或网段规则明确放行，域名解析到的内网地址一律拦截。

## 6. microVM

| 现象 | 原因 | 处理 |
|---|---|---|
| 节点不提供 microvm 后端 | 没有 `/dev/kvm` | 裸金属，或开启嵌套虚拟化 |
| 暂停后恢复全部失败（Ubuntu 24.04、内核 6.8.0-1xx） | 这个内核在用过 `cgroup.kill` 的 cgroup 里会杀掉之后放进来的进程。2026-10-24 的代码修复（CHANGELOG 0.11.0「Fixed」） | 升级 OpenDsec |
| VM 一直启动不起来，日志里有 `connect: invalid argument` | 状态目录路径太长，vsock 的 unix socket 路径超过 108 字节 | 用短一些的 `state_dir` |
| 节点内存紧张 | VM 内存没有还给宿主机 | 开启 `free_page_reporting`、`cold_age_s`、`image_pmem`（需要 OpenDsec 的 guest 内核）；调低 `paused_mem_charge` 让暂停的 VM 少占配额 |
| 跨节点从内存快照创建很慢 | NFS 4.1 不支持找稀疏文件的空洞，要读完整的内存文件 | NFS 改用 `vers=4.2`（`umount -l` 再 `mount`） |

## 7. 镜像

| 现象 | 原因 | 处理 |
|---|---|---|
| `image import` 中途报 `context deadline exceeded` | 旧版命令行有 5 分钟的总时限 | 升级；新版导入不设总时限 |
| `image import ./x.tar` 报去 `registry-1.docker.io` 下载 | 旧版把不存在的本地文件当成镜像名 | 检查路径；新版会直接报文件不存在 |
| `image import` 报权限错误 | 不是 root，或者镜像库开了 root squash | 以 root 在挂载了镜像库的节点上执行；NAS 关闭 root squash |
| `store-check` 有必需项失败 | 文件系统不满足要求 | 按失败的那一项调整 NAS 设置（root squash、硬链接、xattr 等） |
| 镜像库占用越来越大 | 删除镜像只删登记，层还在 | 定期 `opendsecctl image gc` |
| NFS 服务端日志不停地刷 `client attached/detached` | 节点的 NFS 客户端标识相同（主机名相同） | `deploy/node/install.sh` 用 machine-id 设置标识，重启节点后生效 |

## 8. 集群与升级

| 现象 | 原因 | 处理 |
|---|---|---|
| `too many colons in address` | 0.11 之前的 opendsecctl 不支持逗号分隔的多个地址 | 升级，或临时只写一个地址 |
| 连多个地址时 TLS 报 `not api.opendsec.internal` | 旧证书里没有这个名字 | `opendsecops certs <名字>` 重签 → `push-config all` → 滚动重启 |
| 升级期间少量调用报 `unknown edge` | 管控节点重启时，新启动的 watcher 还不知道部分 edge。2026-10-24 的代码修复；从更早的版本升级上来的过程中仍可能出现几次 | 重试即可；升级完成后不再出现 |
| `opendsecops upgrade` 报 `this cluster has fleet replicas` | 集群已经交给 fleet | 用 `opendsecctl fleet rollout create` |
| rollout 暂停，有机器被锁定（pinned） | 那台机器升级后没能就绪，已自动回到原版本 | `fleet rollout status -steps` 和那台机器的日志找原因；处理后 `fleet node unpin`，再 resume 或 rollback |
| 给两台机器同时加了角色后 rollout 卡住 | 2026-10-23 之前的 fleet 会互相等待 | 一台一台加：`fleet node set` 之后 `fleet node sync` |
| 改了配置但 E2B 网关没生效 | 旧版 `opendsecops restart` 不重启 E2B 网关 | 升级；或在那台机器上 `systemctl restart opendsec-e2b@<序号>` |
| 磁盘告警在小磁盘的机器上一直响 | 旧版告警用的是固定阈值 | 用新的 `alerts.yml`（剩余低于 10% 才告警），`opendsecops monitor` 重新加载 |
| `OpenDsecEdgeUnhealthy` | edge 停了、机器宕了，或网络不通 | 恢复后 edge 会重新接管仍在运行的 sandbox（整机没重启的话） |
| 整机重启后 sandbox 都没了 | sandbox（包括暂停的）不跨整机重启保留 | 预期行为；需要保留的状态请做快照 |

## 9. E2B SDK

| 现象 | 原因 | 处理 |
|---|---|---|
| `401: ... API key is malformed: expected the "e2b_" prefix` | 没有设置 `E2B_API_URL`，SDK 在连 E2B 官方服务 | 设置 `E2B_API_URL` 和 `E2B_SANDBOX_URL` 指向网关 |
| JS SDK 报语法错误或启动失败 | Node 版本太低 | E2B 的 JS SDK 需要 Node 22.19 以上 |
| `pause(mode="filesystem")` 没有报错，而是做了完整暂停 | E2B Python SDK 2.46 不认 `mode` 参数，悄悄忽略 | 升级 E2B SDK 到 2.59 以上；OpenDsec 会拒绝只暂停文件系统的请求 |
| E2B sandbox 连不了外网 | 0.11 之前的网关沿用集群的默认网络规则 | 升级；新版与 E2B 一致，默认放行公网 |
| code interpreter 模板构建失败 | 构建需要访问外网和 `layer.publish` 权限 | 新版构建脚本会为构建用的 sandbox 放行外网；检查权限 |
| `Sandbox.create(snapshot_id)` 超时 | 跨节点使用刚做好的快照时，要等它发布到镜像库 | 加大 `timeout`；镜像库慢时尤其如此 |
