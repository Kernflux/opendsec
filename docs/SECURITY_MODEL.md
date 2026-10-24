# 安全模型

OpenDsec 运行的是不可信的代码：强化学习里模型生成的命令、agent 执行的脚本。这一页说明 sandbox 之间、sandbox 与宿主机之间、调用方之间分别靠什么隔离，集群内部的通信和密钥怎么保护，以及生产环境的加固清单。

报告安全漏洞请看仓库根目录的 `SECURITY.md`，不要公开提 issue。

## 1. 威胁模型

| 假设 | 说明 |
|---|---|
| sandbox 里的代码完全不可信 | 它可能以 root 运行、尝试逃逸、扫描网络、耗尽资源 |
| 调用方之间互不信任 | 不同项目的调用方不能看到或操作彼此的 sandbox 和镜像 |
| 集群节点和私网可信 | 组件间仍然使用 mTLS，但前提是节点本身没有被攻破 |
| 运维机最敏感 | 它保存 CA 私钥和管理员 token |

## 2. sandbox 的隔离

### microVM（推荐用于不可信代码）

- 每个 sandbox 是一个 Firecracker 虚拟机，**有自己的内核**：sandbox 里的 root 只是 guest 内核的 root，攻击面是 Firecracker 的少量虚拟设备，而不是宿主机内核的全部系统调用。
- Firecracker 进程由 jailer 启动：chroot 到它自己的目录，以**每个 VM 独立的 uid** 运行（从 `uid_base`，默认 10 亿开始），即使 VMM 被攻破，也碰不到其他 VM 的文件。
- 每个 VM 在自己的 cgroup 里，内存上限是 guest 内存加上 `vm_overhead_mb`。
- 默认开启核心调度（`core_sched`）：两个 sandbox 不会同时运行在同一个物理核的两个超线程上，关闭超线程侧信道。

### container

- Linux namespace（mount、pid、net、uts、ipc、cgroup）+ overlayfs + cgroup v2，共享宿主机内核。
- **能力**：只保留 Docker 默认能力集，并去掉 `CAP_MKNOD`（没有设备 cgroup 时设备节点可能访问到宿主机磁盘）。
- **seccomp**：以下系统调用返回 EPERM：挂载与命名空间切换（`mount`、`umount2`、`pivot_root`、`setns`、新挂载 API）、内核模块和 kexec、`bpf`、keyring、文件句柄（`open_by_handle_at`，即「shocker」逃逸）、`userfaultfd`、`perf_event_open`、端口 IO、swap、quota、重启；带 `CLONE_NEWUSER` 的 `clone` 和 `unshare` 被拒绝（用户命名空间会拿回被去掉的能力）；`clone3` 返回 ENOSYS，libc 退回到 `clone`。
- 进程数上限 `pids_max`（默认 4096），CPU、内存、磁盘 IO 由 cgroup 限制。
- 默认开启核心调度。

**容器与宿主机共享内核**，内核漏洞可能导致逃逸。运行不可信代码请优先用 microVM。

### 两种后端都有的

- **代理只读**：sandbox 里的代理程序（aether、chronus）以只读方式挂载，sandbox 里的代码改不了它们。
- **会话用户**：命令可以在普通用户的会话里执行（`user="1000"`）。普通用户的会话连不上其他会话的通道，看不到它们的输出记录，也改不了系统文件。把 agent 的命令和评测放在不同的会话里，agent 就无法篡改评测。
- **路径限制**（API 字段 `readonly_paths`、`masked_paths`）：把 sandbox 里的路径设为只读，或隐藏（换成空目录或空文件）。在容器里 root 也撤销不了；在 microVM 里 guest 的 root 可以撤销，所以要配合非 root 的 `init_user` 使用。
- **资源上限**：CPU、内存、磁盘大小、磁盘 IO（`disk_io`）都有上限；节点内存或磁盘紧张时拒绝新建，保护已有的 sandbox。
- **输出上限**：每条命令的输出最多记录 64 MB，每个会话最多保留 512 MB，避免撑爆节点磁盘。

## 3. 网络隔离

见[网络策略](NETWORK.md)。要点：

- 出站默认拒绝，按规则放行；规则在宿主机的 nftables 里执行，sandbox 里的 root 改不了。
- 入站一律拒绝：sandbox 之间互相连不上，也连不到宿主机上的服务（DNS 代理除外）。
- 伪造源地址的包被丢弃。
- 内网、链路本地（含云元数据地址 `169.254.169.254`）、组播地址只有用网段规则明确写出才能访问；通过域名解析到的内网地址一律拦截，防止 DNS 绕过。
- 收回放行会立即切断已有连接。

## 4. 调用方之间的隔离

- 每个调用都带 token；token 只在 IAM 里保存哈希。
- 权限按项目授予并向下继承；有界委托保证管理员只能分出自己拥有的权限和配额（[项目、身份与权限](IAM.md)）。
- 操作 sandbox 要求 sandbox 所在项目上的 `sandbox.operate`：同一项目里的调用方可以操作彼此的 sandbox，**需要互相隔离的调用方请放在不同的项目里**。
- 镜像按所属项目授权：可以让运行任务的身份只有 `layer.use`，不能修改训练用的镜像。
- token 可以设置有效期（集群可以用 `max_token_ttl_s` 强制上限），撤销在约 1 秒内全集群生效。
- 同一来源地址的认证失败超过限额后，暂时不再为它认证，防止暴力猜测。

## 5. 集群内部

- **mTLS**：所有组件之间的通信都是双向 TLS。每个组件的证书带有它的角色和 id（例如 `edge-node-a1`），每个内部服务只接受特定角色的调用：例如 edge 上的 sandbox 操作只接受 apiserver，状态查询只接受 watcher、apiserver 和 fleet，快照拉取只接受其他 edge；IAM 的管理接口只接受 apiserver。
- **公共 API**：apiserver 提供 TLS，客户端用集群 CA 校验。apiserver 的证书带有负载均衡的地址和 `api.opendsec.internal`。
- **密钥的位置**：

| 密钥 | 在哪里 | 不在哪里 |
|---|---|---|
| CA 私钥 | 只在运维机的 `$OPENDSEC_OPS/pki` | 任何节点 |
| 管理员 token | 运维机；IAM 节点的 `/etc/opendsec/admin.token`（IAM 自举时需要） | 集群配置文件里只写 `admin_token_file`；其他节点没有 |
| 组件证书和私钥 | 只下发到运行该组件的节点 | 其他节点 |
| 调用方 token | 调用方自己 | 服务端只存哈希 |

- **审计日志**：每个 apiserver 记录所有变更类调用（创建、停止、暂停、fork、改网络、镜像发布、项目、身份、权限、token、集群操作）：时间、身份、方法、项目、对象、结果、来源地址。执行命令只记录命令的长度和 SHA-256，不记录内容。设置 `audit_runtime` 后也记录运行时调用和只读查询。
- **fleet 的节点代理**以 root 运行。它主动连接 fleet（用自己的节点证书，并校验 fleet 的证书），只执行固定的几种操作：下载并校验版本、切换版本、写配置、重启 OpenDsec 的服务。新版本的节点代理要先通过自检才会替换旧的。

## 6. 加固清单

部署生产集群时逐项确认：

- [ ] 对调用方只开放负载均衡的 7100（和 7400，如果用 E2B SDK），其余端口只在私网内可达。
- [ ] 不可信代码用 `microvm` 后端。
- [ ] 默认网络规则（`network.default_rules`）按需最小化；需要访问内网服务时，只放行具体的地址和端口。
- [ ] 设置 `iam.max_token_ttl_s`（例如 90 天），定期换发 token。
- [ ] 调用方按团队或用途分到不同项目，只授予需要的权限；运行任务的身份不给 `layer.publish`。
- [ ] 开启审计日志（`audit_dir`），并定期转存到别处。
- [ ] `$OPENDSEC_OPS` 只有运维人员能访问，并且有离线备份（里面有 CA 私钥）。
- [ ] `opendsecops monitor <webhook>` 配好告警接收方，关注 `OpenDsecCertExpiringSoon`、`OpenDsecIAMBackupStale`。
- [ ] 不在生产集群使用开发用的 `host` 镜像（它把宿主机的 `/` 暴露给 sandbox），也不要设置 `service_token`。
- [ ] agent 的命令在普通用户的会话里执行，评测在另一个会话里执行。
- [ ] 镜像库的 NAS 只对集群节点开放。
