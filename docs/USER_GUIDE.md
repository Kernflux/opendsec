# OpenDsec 接入指南（调用方）

> 给管理员：这份指南写给使用集群的人，可以改好下面带「管理员填写」的几处后交给他们。

OpenDsec 提供隔离的代码执行环境，叫做 sandbox。你可以通过 Python SDK 创建 sandbox，在里面执行命令、读写文件，用完后停止。

## 1. 你会拿到

| 文件 / 信息 | 说明 |
|---|---|
| `opendsec-<版本>-py3-none-any.whl` | Python SDK，要求 Python 3.10 或以上 |
| `ca.crt` | 集群 CA，用于校验服务端证书 |
| token | 你的身份凭证，格式为 `dsk.<id>.<secret>`。**请当作密码保管**，不要写进代码仓库 |
| 项目 | 例如 `root/prod`。你创建的 sandbox 都计入这个项目的配额 |
| 地址 | 见下文 |

**地址**（多个地址用逗号分隔，SDK 会把请求分散到所有在线的 apiserver 上，并自动避开宕机的那台）：
- 有负载均衡时只有一个地址，例如 `api.opendsec.internal:7100`；
- 没有时是所有 apiserver 的地址，例如 `10.0.0.11:7100,10.0.0.12:7100,10.0.0.13:7100`。
- 具体地址由集群管理员提供。

## 2. 安装与第一个 sandbox

```sh
pip install opendsec-<版本>-py3-none-any.whl
export OPENDSEC_ADDR=10.0.0.11:7100,10.0.0.12:7100,10.0.0.13:7100
export OPENDSEC_TOKEN=dsk.prod-caller.xxxxxxxx
export OPENDSEC_PROJECT=root/prod
export OPENDSEC_CA=/path/to/ca.crt
python quickstart.py
```

```python
import asyncio
from opendsec import DSecClient, DSecRunArgs

async def main():
    async with DSecClient() as client:                     # 读取上面的环境变量
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm", image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            ttl_running_stop=600))                         # 空闲 10 分钟后自动停止
        try:
            r = await sb.run_shell("python3 -c 'print(6*7)'")
            print(r.stdout)                                # 42
        finally:
            await sb.stop()

asyncio.run(main())
```

## 3. 常用操作

| 操作 | SDK |
|---|---|
| 创建 | `client.run_sandbox(DSecRunArgs(...))`；批量创建用 `client.run_sandboxes(args, count)`，一次最多 32768 个 |
| 执行命令 | `sb.run_shell(cmd, timeout=...)`，返回 stdout、stderr 和退出码；同一个 `session` 里的环境变量和当前目录会保留 |
| 后台命令 / 流式输出 | `sb.run_shell_background(...)` + `sb.get_output(...)`；`sb.stream_shell(...)` |
| 文件 | `sb.write_file(path, data)`、`sb.read_file(path)`、`sb.list_dir(path)`、`sb.remove(path)` |
| sandbox 内的 HTTP 服务 | `sb.http(url)` |
| 暂停 / 恢复 | `sb.pause()` / `sb.resume()`：暂停后保留内存状态，恢复后从原处继续 |
| 复制 | `sb.fork(count=N)`：从一个运行中的 sandbox 复制出 N 个，内存和文件都相同（microvm） |
| 网络规则 | `sb.update_network({...})` |
| 制作镜像 | container：`sb.pack_diff("root/prod/<repo>:<tag>")`，只保存文件，清掉 /tmp、缓存等构建残留；得到的镜像 container、microvm 都能用。microvm：`sb.create_snapshot(image, memory=True)`，连内存一起保存，用它创建的 sandbox 从保存时的状态继续运行；microvm 不支持只保存文件，需要纯文件镜像时用 container 构建 |
| 停止 | `sb.stop()`。**用完请务必停止**，sandbox 会一直占用配额，直到超时 |
| agent 和评测分开 | `run_shell(cmd, session="agent", user="1000")` 让 agent 的命令以普通用户运行，评测放在另一个会话（默认 root）里。会话第一次执行时确定用户，之后不能换。普通用户的会话连不上别的会话、看不到它们的输出记录、改不了系统文件；评测要瞒着 agent 的文件请用严格权限写（如 `umask 077`） |

## 4. 规格与限制
- **backend**：
  - `microvm`：Firecracker 虚拟机，隔离最强，约 0.2 秒启动，支持暂停、恢复和 fork，**推荐**。
  - `container`：容器，启动约 0.1 秒。
- **镜像**：管理员导入的镜像，比如 quickstart 导入的 `root/py:3.12`（python:3.12）；`client.list_images()` 可以查看。需要其他镜像请联系管理员。
- **网络**：
  - 默认能否访问公网由集群配置决定（`network.default_rules`，管理员填写）。quickstart 装的集群默认不能访问，需要时在 `network_rules` 里放行，例如 `{"*": True}` 或规则集 `{"pypi": True}`。
  - 内网地址（VPC、集群节点）和云元数据地址默认不可访问：`*` 不包括它们，域名解析到的内网地址也一律拦截。确实需要访问内网的某个服务时，用地址或网段规则明确写出，例如 `{"10.30.0.10:5432/tcp": True}`（[网络策略](NETWORK.md)）。
  - 收紧规则：`network_rules` 的键可以是规则集名、域名（含子域名）、IPv4 地址或网段、`"*"`（所有公网地址），后面可以加 `:端口[/协议]` 只放行这些端口，例如 `{"*": False, "pypi.org:443": True, "files.pythonhosted.org:443/tcp": True}`；端口可以是范围 `8000-8080`，协议是 `tcp` 或 `udp`，不写时两个都放行。
  - 只支持 IPv4。
- **生命周期**：
  - 空闲超时 `ttl_running_stop` 默认 1 小时。没有命令在运行、也没有其他调用时算作空闲；超时后自动停止。
  - 最长寿命 `ttl_max` 默认 1 天，最多可以设为 7 天。
- **配额**：每个项目同时存在的 sandbox 数和资源有上限（管理员填写）。超出时创建返回 `quota_exceeded`。
- **磁盘**：可写盘默认 microvm 2 GB、container 1 GB，用 `disk_mb` 调整。
- **命令输出**：每条命令的 stdout、stderr 各记录前 64 MB，超出部分丢弃（`ShellResult.dropped_bytes`），命令照常运行；每个会话保留最近 512 MB 的输出记录，更早的会被删除，`get_output` 取不到。
- **限流**：每个身份在每个 apiserver 上每秒最多发起的创建数和调用数由集群配置决定（管理员填写；默认 2000 次创建、10000 次调用，示例生产配置是 2 万和 10 万）。批量创建在服务端排队，不会因为限流失败。

## 5. 错误与重试

| `DSecError.reason` | 含义 | 怎么办 |
|---|---|---|
| `unavailable` | 服务端正在重启或切换 | SDK 已经自动重试，默认最长 60 秒（`retry_timeout`）。只有在超过这个时间后才会抛给你 |
| `no_capacity` | 集群暂时放不下 | 稍后重试，或者减少并发 |
| `quota_exceeded` | 超出项目配额 | 停掉不再使用的 sandbox，或者申请调高配额 |
| `rate_limited` | 请求过快 | 退避后重试 |
| `unauthenticated` / `forbidden` | token 无效、过期，或者没有权限 | 检查 token 和项目 |
| `not_found` | sandbox 不存在或已经清理 | — |
| `invalid` | 参数错误 | 看错误信息 |

- 创建请求可以放心重试：SDK 会给每次创建带上幂等键，所以即使服务端重启时丢了应答，重试也只会得到同一个 sandbox。
- sandbox 所在的物理机宕机时，上面的 sandbox 会丢失，调用会返回 `not_found` 或 `unavailable`。需要长期保存的结果请及时取出。

## 6. token
- token 有一个有效期（集群的 `max_token_ttl_s`，quickstart 设为 90 天；你的 token 什么时候到期，管理员填写，`opendsecctl token list` 可以查到）。到期前请找管理员换发（`opendsecctl token create <身份>`）。旧 token 在新 token 生效后撤销。
- token 泄露时，立即通知管理员撤销（`opendsecctl token revoke`），撤销在 1 秒内对所有 apiserver 生效。

## 7. 更多文档

- [核心概念](CONCEPTS.md)：后端、状态、超时、会话、任务、镜像、网络、权限、错误
- [Python SDK 参考](PYTHON_SDK.md)：全部类和方法
- [命令行参考](CLI.md)：`opendsecctl` 的全部命令
- [镜像与快照](IMAGES.md)、[网络策略](NETWORK.md)、[项目、身份与权限](IAM.md)
- [故障排查](TROUBLESHOOTING.md)
