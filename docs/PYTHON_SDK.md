# Python SDK 参考

`opendsec` 是 OpenDsec 的异步 Python SDK，基于 gRPC 和 `asyncio`。这一页列出它的全部类和方法。概念（后端、状态、超时、会话、权限）见[核心概念](CONCEPTS.md)。

- 要求 Python 3.10 或以上，依赖 `grpcio>=1.73.1`、`protobuf>=6.31,<8`、`googleapis-common-protos>=1.60`。
- 许可证 Apache-2.0：调用 OpenDsec 的程序不受服务端 AGPL 约束。
- 所有方法都是协程，要在 `async` 函数里 `await`。

## 安装

```sh
# 从源码仓库
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
# 从管理员给的 wheel
pip install opendsec-0.11.0-py3-none-any.whl
```

离线环境：离线安装包的 `wheels/` 目录里有 SDK 和它的全部依赖，用 `pip install --no-index --find-links wheels opendsec`。

## 快速示例

```python
import asyncio
from opendsec import DSecClient, DSecRunArgs, DSecError

async def main():
    async with DSecClient() as client:            # 读取 OPENDSEC_* 环境变量
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm", image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            ttl_running_stop=600,                   # 空闲 10 分钟自动停止
            network_rules={"pypi": True}))          # 只放行 PyPI
        try:
            r = await sb.run_shell("pip install requests && python3 -c 'import requests; print(requests.__version__)'")
            print(r.exit_code, r.stdout, r.stderr)
        finally:
            await sb.stop()

asyncio.run(main())
```

## 连接：`DSecClient`

```python
DSecClient(endpoint=None, token=None, project=None, ca_file=None,
           server_name=None, retry_timeout=60)
```

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `endpoint` | `OPENDSEC_ADDR` | `127.0.0.1:7100` | apiserver 地址 `host:port`。多个地址用逗号分隔（`10.0.0.11:7100,10.0.0.12:7100`）：请求分散到所有在线的 apiserver，一台宕机后自动避开 |
| `token` | `OPENDSEC_TOKEN` | 空 | 身份凭证 `dsk.<id>.<secret>`，每个请求都带上 |
| `project` | `OPENDSEC_PROJECT` | `root` | 默认项目，创建、列出、任务操作、镜像列表都用它 |
| `ca_file` | `OPENDSEC_CA` | 无 | 集群 CA 证书。设置后使用 TLS；不设置则是明文，只用于开发集群 |
| `server_name` | — | 无；多地址时为 `api.opendsec.internal` | 校验服务端证书时使用的名字。apiserver 证书都带有 `api.opendsec.internal` |
| `retry_timeout` | — | 60 | 服务端不可达（`unavailable`，例如重启、切换）时自动重试的时长，秒。0 表示不重试 |

使用方式：

```python
async with DSecClient() as client:      # 推荐：进入时连接，退出时关闭
    ...

client = DSecClient(endpoint="10.0.0.10:7100", token=tok, project="root/team-a", ca_file="ca.crt")
await client.open()                      # 也可以手动打开和关闭
...
await client.close()
```

连接参数（自动处理，通常不用关心）：断线后 100 ms 起重连，最长退避 2 秒；每 10 秒发送一次 keepalive，静默断开的连接约 15 秒内被发现；单个响应最大 64 MB。

## 创建参数：`DSecRunArgs`

```python
@dataclass
class DSecRunArgs:
    backend: str = "sim"
    image: str = ""
    cpu_cores_limit: float = 1.0
    memory_limit_mb: int = 2048
    gpus: int = 0
    gpu_mode: str = ""
    disk_mb: int = 0
    ttl_running_stop: int = 0
    ttl_max: int = 0
    network_rules: dict[str, bool] = {}
    init_user: str = "root"
    task_id: str = ""
    qos: str = "LS"
    labels: dict[str, str] = {}
    project: str | None = None
```

| 字段 | 说明 |
|---|---|
| `backend` | `microvm`、`container`、`fncall`、`fullvm` 或 `sim`。**默认是 `sim`（只模拟，不运行任何东西），实际使用时一定要指定** |
| `image` | 镜像名 `<项目>/<名字>:<标签>`，例如 `root/py:3.12`。需要在镜像所属项目上有 `layer.use` |
| `cpu_cores_limit` | CPU 核数，可以是小数 |
| `memory_limit_mb` | 内存（MB）。用带内存的快照创建时，必须和快照时的值一致 |
| `gpus`、`gpu_mode` | GPU 个数；`gpu_mode` 为 `exclusive`（独占）或 `shared`（共享），默认由节点决定 |
| `disk_mb` | 可写盘大小（MB）。0 表示用后端默认值 |
| `ttl_running_stop` | 空闲超时（秒）。0 表示集群默认（通常 1 小时） |
| `ttl_max` | 最长寿命（秒），从创建时算，暂停时间也计入。0 表示集群默认（通常 1 天），上限通常 7 天 |
| `network_rules` | 网络规则，例如 `{"pypi": True}`、`{"*": True}`、`{"github.com:443": True}`。见[网络策略](NETWORK.md) |
| `init_user` | sandbox 里默认的用户，也是会话的默认用户 |
| `task_id` | 任务名，用于 `pause_task` 等批量操作 |
| `qos` | `LS`（延迟敏感，默认）或 `BE`（尽力而为） |
| `labels` | 任意键值标签，原样保存在 sandbox 的规格里 |
| `project` | 创建到哪个项目，默认用客户端的 `project` |

`DSecContainerRunArgs` 是它的子类，默认 `backend="container"`，并多一个 `container_image` 字段（与论文里的写法一致），设置了就代替 `image`：

```python
DSecContainerRunArgs(container_image="root/py:3.12", memory_limit_mb=4096, cpu_cores_limit=4)
```

## 创建与查询

### `run_sandbox(args, timeout=120) -> Sandbox`

创建一个 sandbox，等它进入 `RUNNING` 后返回。

- `timeout`：整个创建过程的时限（秒），`None` 表示不限。
- 服务端不可达时在 `retry_timeout` 内自动重试。每次创建带一个随机的幂等键：即使第一次的应答丢了，重试拿到的也是第一次创建的那个 sandbox，不会多建一个。
- 需要：项目上的 `sandbox.create`；镜像所属项目上的 `layer.use`。
- 常见错误：`quota_exceeded`、`no_capacity`、`invalid`（例如镜像不存在、后端不存在、超时超过上限）、`forbidden`。

### `run_container(args, timeout=120) -> Sandbox`

与 `run_sandbox` 相同，参数通常是 `DSecContainerRunArgs`。

### `run_sandboxes(args, count, timeout=600) -> list[Sandbox | DSecError]`

批量创建 `count` 个相同规格的 sandbox，一次最多 32768 个。

- 返回列表按序号排列；成功的是 `Sandbox`，失败的是 `DSecError`（不会抛出）。
- 服务端按限流速率排队，大批量不会因限流部分失败。
- 断线后自动重试，只补齐还没有创建的部分。
- 批量请求本身失败（例如没有权限）时直接抛出 `DSecError`。

```python
res = await client.run_sandboxes(DSecRunArgs(backend="microvm", image="root/py:3.12", task_id="job-7"), 500)
ok = [x for x in res if not isinstance(x, DSecError)]
failed = [x for x in res if isinstance(x, DSecError)]
```

### `run_containers(args, count, timeout=600)`

与 `run_sandboxes` 相同。

### `get_sandbox(sandbox_id) -> Sandbox`

按 id 取 sandbox。需要它所在项目上的 `sandbox.operate`。已结束的 sandbox 在节点上保留 10 分钟，之后返回 `not_found`。

### `list_sandboxes(task_id="", include_ended=False, project=None) -> list[Sandbox]`

列出项目（含全部子项目）里的 sandbox。`task_id` 只列出这个任务的；`include_ended=True` 包括最近结束的。需要 `sandbox.operate`。

### `cluster_status() -> Snapshot`

集群快照：每个 edge 的地址、健康、是否排空、后端、容量、已分配资源、各后端的 sandbox 数、内存和磁盘余量、压力原因等（protobuf `Snapshot`，字段见 `proto/opendsec/v1/cluster.proto` 和 `types.proto` 的 `EdgeState`）。

## sandbox 句柄：`Sandbox`

`run_sandbox`、`get_sandbox` 等返回 `Sandbox` 对象。

| 属性 | 说明 |
|---|---|
| `id` | sandbox id |
| `state` | 状态名字符串，例如 `"RUNNING"`。这是**最后一次看到的**状态，调用 `refresh()` 更新 |
| `edge_id` | 所在节点 |
| `info` | 完整记录（protobuf `Sandbox`）：`project`、`principal`、`spec`、`created_at`、`last_active_at`、`ended_at`、`message` |

### 生命周期

所有生命周期方法都返回 `Sandbox` 本身（`info` 已更新），并在服务端不可达时自动重试。需要 `sandbox.operate`。

| 方法 | 说明 |
|---|---|
| `refresh()` | 重新获取记录 |
| `stop()` | 停止并清理。配额立即归还 |
| `pause()` | 暂停。microVM 拍快照后结束进程，内存全部释放；container 冻结进程 |
| `resume()` | 恢复。不调用也可以：对暂停的 sandbox 发起运行时调用会自动恢复 |
| `touch()` | 刷新空闲计时；对暂停的 sandbox 会恢复它 |
| `update_network(rules, replace=False)` | 修改网络规则：默认合并进现有规则，`replace=True` 整体替换。收回的放行对新连接立即生效，已有连接也会被切断 |

### 执行命令

```python
run_shell(cmd, timeout=None, session="default", env=None, cwd=None, user=None) -> ShellResult
```

在会话里执行一条 shell 命令，等它结束后返回结果。

| 参数 | 说明 |
|---|---|
| `cmd` | 整条 shell 命令，由会话的 shell 解释，可以用管道、`&&` 等 |
| `timeout` | 秒。到期后杀掉这条命令启动的进程，会话保留，`ShellResult.timed_out` 为 `True` |
| `session` | 会话名。同一会话里 `cd`、`export` 在命令之间保留；不同会话互不影响 |
| `env`、`cwd` | 只对这一条命令生效的环境变量和工作目录 |
| `user` | 会话**第一次**执行命令时确定的用户：名字，或 `uid[:gid]`（例如 `"1000"`）。之后对同一会话传不同的值不起作用 |

断线（edge 或 apiserver 重启）时自动重试，不会把命令执行两次。

```python
r = await sb.run_shell("cd /srv && export X=1")
r = await sb.run_shell("pwd; echo $X")          # /srv 1
r = await sb.run_shell("pytest -q", timeout=600, cwd="/srv/repo")
if not r.ok:
    print(r.exit_code, r.stderr)
```

`ShellResult` 的字段：

| 字段 | 说明 |
|---|---|
| `cmd_id` | 命令在会话里的编号 |
| `exit_code` | 退出码 |
| `stdout`、`stderr` | 输出（UTF-8 解码，无法解码的字节替换为 `�`）；原始字节在 `stdout_bytes`、`stderr_bytes` |
| `done` | 是否已结束（后台命令可能为 `False`） |
| `timed_out` | 是否因超时被杀 |
| `duration` | 执行时长（秒） |
| `truncated` | 输出超过了单次调用能返回的上限（每个流 16 MB），没有全部返回；完整的输出（每个流最多 64 MB）仍在记录里，用 `get_output(cmd_id, stdout_offset=...)` 按偏移量继续取 |
| `dropped_bytes` | 超过每个流 64 MB 记录上限后丢弃的字节数 |
| `ok` | `done and exit_code == 0 and not timed_out` |

### 后台命令

```python
cmd_id = await sb.run_shell_background("python3 train.py", session="train")
...
r = await sb.get_output(cmd_id, session="train", wait=30)   # 最多等 30 秒
print(r.done, r.stdout)
```

- `run_shell_background(cmd, timeout=None, session="default", env=None, cwd=None, user=None) -> int`：启动后立即返回命令编号。
- `get_output(cmd_id, session="default", wait=0, stdout_offset=0, stderr_offset=0) -> ShellResult`：取已记录的输出。`wait` 秒内等命令结束；`stdout_offset`、`stderr_offset` 从指定字节位置开始取，用于增量读取。

### 流式输出

```python
async for kind, data in sb.stream_shell("make test", timeout=1800):
    if kind == "stdout":
        sys.stdout.buffer.write(data)
    elif kind == "stderr":
        sys.stderr.buffer.write(data)
    elif kind == "exit":
        print("exit code", data.exit_code)     # data 是不含输出的 ShellResult
```

`stream_shell(cmd, timeout=None, session="default", env=None, cwd=None, user=None)` 依次产出 `("stdout", bytes)`、`("stderr", bytes)`，最后是 `("exit", ShellResult)`。连接中断时从断开的位置继续，命令在 sandbox 里一直在运行，输出不重复也不丢失。

### 会话

- `list_sessions() -> list[str]`：sandbox 里现有的会话名。
- `close_session(session)`：结束会话，杀掉它启动的所有进程。

### 文件

所有路径都是 sandbox 里的绝对路径；文件操作以会话的用户身份执行（`session` 参数，默认 `default`）。

| 方法 | 说明 |
|---|---|
| `read_file(path, offset=0, length=0) -> bytes` | 读文件。`length=0` 读到末尾 |
| `write_file(path, data, mode=0, append=False) -> FileInfo` | 写文件，`data` 是 `bytes` 或 `str`（按 UTF-8 编码）。`mode` 为文件权限（例如 `0o755`），0 表示默认；`append=True` 追加 |
| `list_dir(path) -> list[FileInfo]` | 列目录 |
| `stat(path) -> FileInfo` | 文件信息 |
| `remove(path, recursive=False)` | 删除文件；`recursive=True` 删除目录及其内容 |

`FileInfo` 的字段：`name`、`type`（`file`、`dir`、`symlink`、`other`）、`size`、`mode`、`mtime`。

大小限制：

- 一次 `read_file` 最多返回 64 MB，更大的文件用 `offset` 和 `length` 分段读；
- 一次 `write_file` 的数据建议不超过 64 MB（单个消息上限 80 MB），更大的文件用 `append=True` 分段写；
- 较早的代码里，经过 apiserver 的单个消息上限是 4 MB，超过时报 `quota_exceeded`（实际是消息过大）。CHANGELOG 0.11.0「Fixed」第一条修复了它：把服务端、Go 客户端和 Python SDK 都放宽到 80 MB，这类错误报 `invalid`。

```python
# 分段读一个大文件
chunks, off = [], 0
while True:
    part = await sb.read_file("/data/big.bin", offset=off, length=32 << 20)
    if not part:
        break
    chunks.append(part)
    off += len(part)
```

### sandbox 里的 HTTP 服务

```python
r = await sb.http("http://127.0.0.1:8000/health", method="GET", headers=None, body=b"", timeout=30)
print(r.status, r.headers, r.body)
```

在 sandbox 的网络命名空间里发起 HTTP 请求，用来访问 sandbox 里运行的服务。返回 `HttpResult(status, headers, body)`。需要直接的 TCP 连接（例如 WebSocket），用 API 的 `ConnectPort`，或通过 E2B 网关访问端口。

### fork、快照与制作镜像

```python
fork(count=1, ttl_running_stop=0, ttl_max=0, labels=None, task_id="", timeout=600) -> list[Sandbox | DSecError]
```

把运行中的 sandbox 复制成 `count` 个（1 到 256）运行中的 sandbox。

- 源 sandbox 短暂暂停后继续运行，`id` 和超时都不变。
- 副本继承源的规格；`labels` 追加到副本的标签上，`task_id` 替换任务名（默认沿用源的）；`ttl_running_stop`、`ttl_max` 是副本的超时（0 为集群默认）。
- microVM 的副本连同内存复制，进程从 fork 时的状态继续；container 只复制文件。
- 结果按序号返回，失败的是 `DSecError`。每个副本单独计入配额。断线后重试只补齐未完成的部分。
- 需要：项目上的 `sandbox.create`；源镜像所属项目上的 `layer.use`。

```python
create_snapshot(image, memory=False, overwrite=False) -> ImageInfo
```

把 sandbox 原样保存为镜像 `image`（`<项目>/<名字>:<标签>`），不清理任何文件。

- `memory=True`（只有 microVM）：连内存一起保存，用这个镜像创建的 sandbox 直接从快照恢复，进程从保存时的状态继续运行。创建时 `memory_limit_mb` 要和快照时一致。
- microVM 必须 `memory=True`。需要只含文件的镜像时，用 container 构建，再 `pack_diff`。
- `overwrite=True` 覆盖同名镜像。
- 需要镜像所属项目上的 `layer.publish`。

```python
pack_diff(image, scrub=(), overwrite=False) -> ImageInfo
```

把 sandbox 相对它启动镜像的改动保存为新镜像 `image`，叠在原镜像之上（只有 container 类后端）。

- 默认清理的路径：`/tmp/*`、`/var/tmp/*`、`/root/.cache`、`/root/.bash_history`、`/home/*/.bash_history`、`/root/.python_history`。`scrub` 追加更多（相对于 `/` 的 glob，例如 `["srv/repo/.git"]`）。
- 得到的镜像 container 和 microVM 都能用。
- 需要镜像所属项目上的 `layer.publish`。

```python
sb = await client.run_container(DSecContainerRunArgs(container_image="root/rl/python:3.12",
                                                     network_rules={"pypi": True, "github": True}))
await sb.run_shell("git clone https://github.com/org/repo /srv/repo && pip install -e /srv/repo")
img = await sb.pack_diff("root/rl/repo-env:v1")
await sb.stop()
# 之后直接用 root/rl/repo-env:v1 创建，不必重复安装
```

`ImageInfo` 的字段：`name`、`layers`（从底到顶）、`env`、`workdir`、`user`、`parent`、`source`、`created_at`、`created_by`、`snapshot`、`memory`。

## 任务操作

| 方法 | 说明 |
|---|---|
| `pause_task(task_id, project=None)` | 暂停任务的所有 sandbox |
| `resume_task(task_id, project=None)` | 恢复任务的所有 sandbox |
| `stop_task(task_id, project=None)` | 停止任务的所有 sandbox |

返回 `TaskActionResult`：`affected`（成功个数）、`failed`（失败个数）、`errors`（失败原因）。需要 `sandbox.operate`。

## 镜像管理

| 方法 | 说明 | 权限 |
|---|---|---|
| `list_images(project=None) -> list[ImageInfo]` | 列出项目及其子项目的镜像 | `layer.use` |
| `get_image(name) -> ImageInfo` | 镜像详情 | `layer.use` |
| `compose_image(name, parts, env=None, workdir="", user="", overwrite=False) -> ImageInfo` | 把 `parts` 里的镜像从底到顶叠成新镜像，不复制数据。`env` 追加环境变量，`workdir`、`user` 设置默认工作目录和用户 | 新镜像所属项目上 `layer.publish`，每个 part 上 `layer.use` |
| `delete_image(name)` | 删除镜像的登记。它的层由 `opendsecctl image gc` 回收 | `layer.publish` |

```python
await client.compose_image("root/rl/swe-4821:v1",
                           ["root/rl/python:3.12", "root/rl/django-ws:a1b2", "root/tools/agent-kit:3"])
```

从镜像仓库导入只能用命令行（`opendsecctl image import`），因为要在挂载了镜像库的机器上写入数据。

## 项目、身份与 token

这些方法和 `opendsecctl` 用的是同一套 API，人和 agent 都可以调用，权限规则相同（[项目、身份与权限](IAM.md)）。

| 方法 | 说明 | 需要 |
|---|---|---|
| `whoami() -> str` | 当前 token 对应的身份 id | — |
| `create_project(parent, name, quota=None) -> Project` | 在 `parent` 下建子项目。`quota` 例如 `{"sandboxes": 100, "cpu_cores": 400}`，不写的键继承上级 | `parent` 上的 `project.admin` |
| `get_project(project=None) -> Project` | 项目详情：`path`、`quota`、`usage`（当前用量）、`policies`（每个身份的权限）、`children` | 项目上的任意权限 |
| `set_quota(project, quota) -> Project` | 设置配额（整体替换），不能超过任何祖先 | 上级项目的 `project.admin` |
| `delete_project(project)` | 删除空项目（没有子项目、没有用量、没有属于它的身份） | 上级项目的 `project.admin` |
| `create_principal(project, principal_id, kind="agent", ttl=0) -> str` | 在项目里建身份，返回它的第一个 token（**只返回这一次**）。`ttl` 是 token 有效期（秒），0 为服务端默认 | `project.admin` |
| `delete_principal(principal)` | 删除身份和它的全部 token | 身份所属项目的 `project.admin` |
| `grant(project, principal, perms) -> Project` | 授予权限，例如 `["sandbox.create", "sandbox.operate"]`。只能授予自己拥有的权限 | `project.admin` 及要授予的每个权限 |
| `revoke(project, principal, perms=()) -> Project` | 收回权限；`perms` 为空时收回全部 | `project.admin` |
| `create_token(principal=None, ttl=0, description="") -> (str, TokenInfo)` | 签发新 token，默认给自己 | 给自己：无；给别人：其所属项目的 `project.admin` |
| `list_tokens(principal=None) -> list[TokenInfo]` | 列出 token（不含密钥）：`id`、`created_at`、`expires_at`（0 为永不过期）、`description`、`created_by` | 同上 |
| `revoke_token(principal, token_id)` | 撤销 token，约 1 秒内在所有 apiserver 上失效 | 同上 |
| `get_usage(project=None, start="", end="") -> UsageReport` | 项目及其子项目按 UTC 日期的用量，`start`、`end` 为 `YYYY-MM-DD`（含） | `project.admin` |

`UsageReport.rows` 的每一行：`project`、`day`、`sandboxes_started`、`sandbox_hours`、`cpu_core_hours`、`memory_gb_hours`、`gpu_hours`。

## 错误：`DSecError`

所有失败都抛出 `DSecError`（批量创建和 fork 的单个失败项除外，它们放在结果列表里）。

```python
from opendsec import DSecError, QUOTA_EXCEEDED, NO_CAPACITY

try:
    sb = await client.run_sandbox(args)
except DSecError as e:
    if e.reason in (QUOTA_EXCEEDED, NO_CAPACITY):
        await asyncio.sleep(5)        # 稍后重试
    else:
        raise
```

- `e.reason`：稳定的原因字符串，模块里有同名常量：`UNAUTHENTICATED`、`FORBIDDEN`、`NOT_FOUND`、`QUOTA_EXCEEDED`、`RATE_LIMITED`、`NO_CAPACITY`、`INVALID`、`UNAVAILABLE`、`TIMEOUT`、`INTERNAL`。各自的含义和处理方法见[核心概念 §9](CONCEPTS.md#_9-错误)。
- `e.message`：服务端给出的说明。

**自动重试的范围**：只有 `unavailable`（服务端不可达）会在 `retry_timeout` 内自动重试，适用于创建、批量创建、fork、生命周期操作、执行命令、读文件、列目录、会话和流式输出。`write_file`、`remove`、`http`、`update_network`、`pack_diff`、`create_snapshot` 和管理类方法不自动重试，失败时由调用方决定。

## 常见用法

### 强化学习 rollout

```python
async def rollout(client, step_image, episode):
    sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image=step_image,
                                              cpu_cores_limit=2, memory_limit_mb=2048,
                                              task_id="ppo-run-42", ttl_max=3600))
    try:
        for action in episode:
            r = await sb.run_shell(action, session="agent", user="1000", timeout=120)
            ...
        score = await sb.run_shell("python3 /grader/grade.py", session="grader")   # root 会话
        return float(score.stdout)
    finally:
        await sb.stop()

# 训练被抢占
await client.pause_task("ppo-run-42")
# 恢复后，对每个 sandbox 的下一次调用会自动恢复它；也可以：
await client.resume_task("ppo-run-42")
```

### 从同一个状态分支探索

```python
base = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/swe-4821:v1"))
await base.run_shell("cd /srv/repo && git apply /tmp/partial.patch")
branches = await base.fork(count=8, task_id="search-17")
results = await asyncio.gather(*(b.run_shell(f"python3 try.py --variant {i}")
                                 for i, b in enumerate(branches) if not isinstance(b, DSecError)))
```

### 预热好的环境

```python
sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12", memory_limit_mb=2048))
await sb.run_shell("python3 -c 'import torch, transformers'")         # 加载慢的初始化
await sb.create_snapshot("root/rl/warm-torch:v1", memory=True)
await sb.stop()
# 之后从这个快照创建，进程和已加载的模块都在，约 55 ms
fast = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/warm-torch:v1",
                                            memory_limit_mb=2048))
```

更多示例在仓库的 `sdk/python/examples/`：`quickstart.py`、`test_features.py`（逐项检查各功能）、`load_test.py`（压测）、`decoupled_rollout.py`（解耦 rollout）。
