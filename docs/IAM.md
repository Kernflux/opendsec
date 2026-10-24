# 项目、身份与权限

OpenDsec 用一棵**项目树**组织资源，用**身份**和 **token** 认证调用方，用授予在项目上的**权限**控制谁能做什么，用**配额**限制每个项目能用多少资源。这一页说明这些规则，以及几种常见的配置方式。

## 1. 项目

- 项目组成一棵树，根是 `root`，路径用 `/` 分隔，例如 `root/team-a/rl`。
- 项目名不能含 `/` 和空格。
- sandbox 和镜像都属于某个项目：sandbox 属于创建时指定的项目，镜像属于它名字里的项目（`root/team-a/py:3.12` 属于 `root/team-a`）。
- 列出 sandbox 和镜像时，会包括项目的全部子项目。

```sh
opendsecctl project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000
opendsecctl project create root/team-a rl
opendsecctl project get root/team-a
```

`project get` 显示配额（`quota`）、当前用量（`usage`）、每个身份在这个项目上直接拥有的权限（`policies`）和子项目（`children`）。查看需要在项目上有任意一项权限。

删除项目：`opendsecctl project delete root/team-a/rl`。只能删除空项目：没有子项目，没有用量（没有运行中的 sandbox），也没有属于它的身份。root 不能删除。

## 2. 身份与 token

**身份**（principal）是调用 API 的主体，一个人、一个服务或一个 agent。

```sh
opendsecctl principal create root/team-a trainer -kind agent
```

- 身份 id 全局唯一，不能含 `.`、`/` 和空格。
- 身份属于创建它的项目：这个项目的管理员可以管理它（签发、撤销 token，删除）。
- `kind` 是 `user`、`service` 或 `agent`，默认 `agent`。只用于区分，不影响权限。
- 创建时会签发第一个 token，**只在输出里显示这一次**。
- 新建的身份没有任何权限，需要单独授予（见 §3）。

**token** 是身份的凭证，调用时放在 `authorization: Bearer <token>` 里（SDK 和 opendsecctl 会自动处理）：

- 格式 `dsk.<身份>.<token id>.<密钥>`。旧格式 `dsk.<身份>.<密钥>` 是身份的主 token，id 为 `primary`，管理员的自举 token 就是这种格式。
- 服务端只保存密钥的哈希，丢了无法找回，只能重新签发。
- 一个身份可以有多个 token，例如每台训练机一个，泄露时只撤销一个。

```sh
opendsecctl token create trainer -ttl 2592000 -desc "gpu-node-07"     # 30 天
opendsecctl token list trainer
opendsecctl token revoke trainer <token-id>
```

| 规则 | 说明 |
|---|---|
| 谁能管理 | 每个身份可以管理自己的 token；身份所属项目的 `project.admin` 可以管理它的 token |
| 有效期 | `-ttl` 秒。集群设置了 `max_token_ttl_s` 时：不写取上限，超过上限报 `invalid`；没设置时：不写表示永不过期 |
| 撤销 | 约 1 秒内在所有 apiserver 上失效：每次撤销都会让各 apiserver 清空认证缓存 |
| 过期后 | 调用返回 `unauthenticated` |

**换发 token 的步骤**：签发新 token → 交给调用方 → 调用方换上新 token → 确认旧 token 不再被使用 → 撤销旧 token。

**认证失败限流**：同一客户端地址的认证失败超过 `auth_fail_rate`（默认每秒 5 次）后，暂时不再为它认证新 token，防止暴力猜测。

## 3. 权限

权限授予在项目上，对这个项目和它的**全部子项目**生效：

```sh
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl revoke root/team-a trainer sandbox.operate
opendsecctl revoke root/team-a trainer              # 收回全部
```

| 权限 | 允许的操作 |
|---|---|
| `sandbox.create` | 创建 sandbox、批量创建、fork（副本建在这个项目里） |
| `sandbox.operate` | 查看、列出 sandbox；执行命令、读写文件、HTTP、进程、端口；暂停、恢复、停止、刷新；修改网络规则；任务操作 |
| `layer.use` | 用这个项目的镜像创建 sandbox；查看、列出镜像；作为 `compose` 的组成部分 |
| `layer.publish` | 发布这个项目的镜像：导入、组合、`pack_diff`、快照、删除 |
| `project.admin` | 建子项目，设子项目的配额，删子项目；建身份、删身份；授予和收回权限；管理所属身份的 token；查看用量 |
| `fleet.view` | 在 root 上：查看集群管理服务的状态（机器、版本、rollout） |
| `fleet.operate` | 在 root 上：发版、改配置、发起和控制 rollout、管理机器 |

几点说明：

- 权限之间**互不包含**：有 `project.admin` 不代表能创建 sandbox，需要的权限要逐个授予。例外是集群管理：root 上的 `project.admin` 同时具有 `fleet.view` 和 `fleet.operate` 的能力。
- **集群级操作**需要 root 上的 `project.admin`：排空 edge（`edge drain`）、IAM 备份和恢复、IAM 副本管理。
- 操作 sandbox 时检查的是**sandbox 所在项目**上的 `sandbox.operate`，不论 sandbox 是谁创建的。同一个项目里有 `sandbox.operate` 的身份可以操作彼此的 sandbox；需要隔离的调用方请放在不同的项目里。
- 创建 sandbox 需要两处权限：目标项目上的 `sandbox.create`，以及镜像所属项目上的 `layer.use`。
- 自举的管理员（配置里的 `admin_id`，默认 `admin`）在 root 上拥有全部权限，不能被删除。

### 有界委托

项目管理员可以把管理权交给下级，但交出去的不能超过自己有的：

- **授予权限**：要在项目上有 `project.admin`，并且自己在这个项目上也拥有要授予的每一项权限。没有 `layer.publish` 的管理员不能把 `layer.publish` 授予别人。
- **配额**：子项目的配额不能超过任何一个祖先的配额。设置子项目配额需要的是**上级项目**的 `project.admin`，项目自己的管理员不能给自己加配额。
- 这使得可以放心地把一个子项目整个交给一个团队或一个 agent 管理：他们能在里面建项目、建身份、分配配额和权限，但突破不了上级给的边界。

## 4. 配额

| 配额键 | 含义 |
|---|---|
| `sandboxes` | 同时存在的 sandbox 数（运行中和暂停中都算） |
| `cpu_cores` | CPU 核数之和 |
| `memory_mb` | 内存之和（MB） |
| `gpus` | GPU 数之和 |

- 创建时，sandbox 的资源要同时满足**它的项目和所有祖先**的配额：子项目的用量也计入每一个祖先。任何一级超出都返回 `quota_exceeded`，错误信息里指出是哪一级、哪个键。
- 建项目或设置配额时没写的键，取当时祖先中最严的那个限制，存进这个项目；root 的配额由运维设置（`iam.root_quota`），不设置则不限。
- 之后调低祖先的配额也会立即生效：创建时每一级祖先都会重新检查，实际的上限总是这条路径上最小的那个。
- 设置配额是整体替换：`set_quota` 里没写的键，重新取当时祖先中最严的限制。
- 暂停的 sandbox 仍然占用配额：它的资源（暂停后恢复所需的容量）还是它的。
- 停止 sandbox 后配额立即归还。节点宕机时，它上面的 sandbox 的配额在 `lost_edge_grace`（默认 120 秒）后由 watcher 释放。
- 配额是「同时占用」的上限，不是累计用量；累计用量见 §5。

```sh
opendsecctl project create root/team-a eval -quota sandboxes=200,cpu_cores=400
# SDK：
await client.set_quota("root/team-a/eval", {"sandboxes": 300, "cpu_cores": 600})
```

## 5. 用量统计

```sh
opendsecctl usage root/team-a -from 2026-10-01 -to 2026-10-31          # 每个项目这段时间的合计
opendsecctl usage root -from 2026-10-01 -daily -csv > usage.csv        # 按天、按项目
```

```python
report = await client.get_usage("root/team-a", start="2026-10-01", end="2026-10-31")
for row in report.rows:
    print(row.day, row.project, row.sandboxes_started, row.sandbox_hours, row.cpu_core_hours, row.memory_gb_hours, row.gpu_hours)
```

- 统计项目和全部子项目：启动的 sandbox 数、sandbox·小时、CPU 核·小时、内存 GB·小时、GPU·小时。
- 按 UTC 日期统计。每行只算这个项目自己的 sandbox，子项目各自成行；不加 `-daily` 时最后一行是合计。
- 计的是配额占用的时间：运行中和暂停中都算。还在运行的 sandbox 算到查询的时刻。
- 需要项目上的 `project.admin`。
- 数据保留 400 天，保存在 IAM 里，随 Raft 复制，不会因为节点重启或故障切换而丢失。

## 6. 常见配置

### 给一个团队开通

```sh
export OPENDSEC_ADDR=<LB>:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
opendsecctl project create root team-a -quota sandboxes=1000,cpu_cores=4000,memory_mb=4096000
opendsecctl principal create root/team-a team-a-admin -kind user        # 团队管理员
opendsecctl grant root/team-a team-a-admin project.admin,sandbox.create,sandbox.operate,layer.use,layer.publish
opendsecctl grant root team-a-admin layer.use                          # 可以使用 root/ 下的公共镜像
```

团队管理员之后可以自己建子项目和身份，把不超过自己的权限分下去。

### 训练任务的调用方

```sh
opendsecctl principal create root/team-a trainer -kind agent
opendsecctl grant root/team-a trainer sandbox.create,sandbox.operate
opendsecctl grant root trainer layer.use
```

### 构建镜像的账号与运行任务的账号分开

```sh
# 构建账号：能发布 root/team-a 下的镜像
opendsecctl principal create root/team-a builder -kind service
opendsecctl grant root/team-a builder sandbox.create,sandbox.operate,layer.use,layer.publish
# 运行账号：只能使用，不能修改镜像
opendsecctl grant root/team-a trainer layer.use
```

运行任务的代码即使被攻破，也无法篡改训练要用的镜像。

### 让 agent 自己管理子项目

agent 用同一套 API（SDK 的 `create_project`、`create_principal`、`grant`、`create_token`）在自己的子项目里给子任务分配身份和配额：

```python
async with DSecClient(token=agent_admin_token, project="root/team-a/agent-7") as c:
    await c.create_project("root/team-a/agent-7", "sub-1", quota={"sandboxes": 10})
    tok = await c.create_principal("root/team-a/agent-7/sub-1", "agent-7-sub-1", ttl=3600)
    await c.grant("root/team-a/agent-7/sub-1", "agent-7-sub-1", ["sandbox.create", "sandbox.operate"])
```

有界委托保证子任务拿到的配额和权限不超过 agent 自己的。

### E2B 网关的调用方

E2B 网关用调用方自己的 token 访问 OpenDsec，需要在 `e2b.project` 上有 `sandbox.create`、`sandbox.operate`，在模板镜像所在的项目上有 `layer.use`；用快照（`create_snapshot()`）还要在 `e2b.project` 上有 `layer.publish`。

## 7. 备份与恢复

IAM 的全部内容（身份、项目、权限、配额、token 的哈希、用量）可以备份：

```sh
opendsecctl iam backup -out iam-$(date +%F).json.gz     # gzip 的 JSON，权限 0600
opendsecctl iam restore iam-2026-10-24.json.gz
```

- 需要 root 上的 `project.admin`。
- 集群部署后，每台 IAM 节点每天 03:00 自动备份到 `/var/backups/opendsec`（`opendsec-iam-backup.timer`），`opendsecops backup` 立即备份一份到运维机。
- 恢复会替换 IAM 的内容。运行中 sandbox 的配额租约不在备份里，恢复后由下一轮对账（默认 30 秒）从各 edge 重新登记。
- 备份之后才创建的身份、token 和项目在恢复后不存在，需要重建。

灾难恢复的完整步骤见[运维手册 §5](OPERATIONS.md)。
