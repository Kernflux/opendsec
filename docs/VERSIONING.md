# 版本与兼容

这一页说明 OpenDsec 各版本之间哪些保持兼容，以及升级和回滚需要注意什么。各版本的变更见 [CHANGELOG.md](../CHANGELOG.md)。

## 版本号

- 正式版本是 `MAJOR.MINOR.PATCH`，取自 `VERSION` 文件，打 tag `v<版本>`。
- 正式版本以外的构建带时间戳：`make build` 得到 `0.11.0-202610180528`。`opendsecctl version` 和指标 `opendsec_build_info` 会显示它。
- **1.0 之前**（现在）：次版本（0.11 → 0.12）可能破坏兼容。这时变更日志会在「Breaking」下列出每一处不兼容，并说明怎么处理。修订版本（0.11.0 → 0.11.1）从不破坏兼容。
- **1.0 之后**：不兼容的改动要升主版本号。次版本以兼容的方式加功能，修订版本只修 bug。
- 安全修复只进最新的次版本（见 [SECURITY.md](../SECURITY.md)）。

## 覆盖范围

| 对象 | 兼容承诺 |
|---|---|
| 公开的 gRPC API（`opendsec.v1.DSec`，`proto/opendsec/v1/opendsec.proto`）和 Python SDK | 只做增加：新的 RPC、新字段、新的枚举值。字段不会重新编号或挪作他用。错误原因（`no_capacity`、`quota_exceeded` 等）是稳定的字符串。SDK 能用于同一个次版本和下一个次版本的集群。例如 0.10 的 SDK 可以连 0.11 的集群，在生产环境从 0.10 升级到 0.11 时带着压测验证过。 |
| 内部 gRPC API：IAM、watcher 和 edge（`cluster.proto`）、sandbox 内的 agent（`runtime.proto`）、fleet | 相邻的次版本之间兼容，这样滚动升级时新旧组件可以同时运行（见下文）。它们不是给其他程序用的 API。 |
| 集群配置（`opendsec.json`） | 新字段都是可选的，并且有默认值。要删除或改名的字段，会先标记弃用并保留一个次版本。校验可能变得更严格（例如 0.11 会拒绝调度用不上的 `edge_template` zone）；这类变化会写进变更日志。 |
| 命令行（`opendsecctl`） | 命令和参数保持不变；参数解析方式的变化会写进变更日志。JSON 输出遵循 API 的 protobuf JSON 映射。 |
| 指标和告警名 | 1.0 之前的次版本中可能改变；改名会写进变更日志。 |
| Go 包（`pkg/client`、`internal/...`） | 不在承诺范围内。`internal/` 本来也无法从模块外部导入。 |

## 升级

**支持的升级路径**：从一个次版本升到下一个（0.10 → 0.11），以及同一个次版本内的各修订版本之间。要跨多个版本，请一次升一个次版本。

**滚动升级不影响运行中的 sandbox。** 用 fleet 服务（`opendsecctl fleet rollout create`）和用 `opendsecops upgrade` 的顺序相同：

1. 先升 IAM 的 follower，最后升 IAM 的 leader。follower 能执行旧 leader 提出的任何命令；新类型的命令只有在 leader 运行新版本之后才会提出，而那时所有副本都已经是新版本。
2. 然后是 watcher，再是 apiserver，再是 fleet 副本。
3. 最后是 edge，一次一台（用 fleet 时按批次），每台先排空。

升级后能延续的：

- **edge**：新版本的 edge 会接管上一个版本留下的运行中的 sandbox。这需要 `persist_state`、`keep_sandboxes_on_exit` 和 `KillMode=process`（默认的 unit 文件就是这样）。SDK 会续上被打断的调用和输出流。
- **sandbox 内的 agent**：每个版本都在自己的 `agents/` 目录下带上 aether 和 chronus。运行中的 sandbox 一直用它启动时的 agent，直到结束；edge 能和上一个次版本的 agent 通信。
- **IAM 状态**：Raft 日志和快照会向前延续。备份可以跨版本恢复：0.11 能读取 `opendsec-iam-backup/2` 和 `/1` 格式，以及改名前的 `dsec-iam-backup/1`。
- **guest 内核**：新版本里的新内核只用于新创建的 microVM。运行中和暂停中的 VM 继续用原来的内核。

**运行时的版本绑定：**

- **Firecracker 版本**：内存快照（暂停快照、fork、用 `memory=true` 创建的镜像）只能在生成它的那个 Firecracker 版本下恢复。调度会根据各 edge 上报的运行时版本保证这一点。所以如果一个版本更换了 Firecracker，旧的快照只能在仍是旧版本的 edge 上运行。每当 `deploy/deps.lock` 更换 Firecracker 版本，变更日志都会写明。
- **镜像库格式**：层、清单和快照都能被之后的版本读取。派生文件的格式在文件名里带版本号（例如 `vmdisks/` 下的 EROFS 盘）；新格式会和旧格式并存构建，镜像垃圾回收再删掉旧的。

## 回滚

- **回到上一个版本**：按同样的滚动流程进行。用 fleet 时执行 `opendsecctl fleet rollout rollback <id>`，或者滚动发布旧版本；否则用 `opendsecops rollback <版本>`。
- **新版本写入的状态**，旧版本可能读不懂。特别是新格式的备份不能恢复到旧版本的 IAM。每次升级前都要备份 IAM（`opendsecops backup`），并保留上一个版本的安装包（fleet 会保留，每台节点也会保留最近 3 个，见 `OPENDSEC_KEEP_RELEASES`）。
- **变更日志里标注「no rollback」的条目**，表示这个版本改变了已存储的状态，上一个版本无法读取。这类改动只会出现在 1.0 之前的次版本里，修订版本中不会有。

## 弃用

要删除的东西（RPC、字段、配置项、命令行参数）会先在变更日志、proto 注释或配置参考里标记为弃用，并至少再保留一个次版本照常可用。
