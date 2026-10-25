# 从 E2B 迁移到 OpenDsec

OpenDsec 的 E2B 网关（`opendsec-e2b`）提供 E2B SDK 调用的那套 API。按 E2B 写的代码，以及基于 E2B SDK 的智能体框架，不用改代码就能跑在你自己的 OpenDsec 集群上：把 SDK 指向网关，用 OpenDsec 的 token 作为 API key 即可。设计和测试见 SPEC §37。

## 调用方：设置三个环境变量

```sh
export E2B_API_URL=http://<网关>:7400            # 开了 TLS 时用 https://...
export E2B_SANDBOX_URL=http://<网关>:7400
export E2B_API_KEY=<你的 OpenDsec token>          # dsk.<id>.<secret>
```

```python
from e2b import Sandbox

sbx = Sandbox.create()                          # 模板 "base"
print(sbx.commands.run("python3 -V").stdout)
sbx.files.write("/tmp/a.txt", "hello")
sbx.kill()
```

E2B 的 JS SDK 需要 Node.js 22.19 以上（Ubuntu 24.04 自带的 `nodejs` 是 18，请从 nodejs.org 安装）：

```js
import { Sandbox } from 'e2b'

const sbx = await Sandbox.create()
console.log((await sbx.commands.run('python3 -V')).stdout)
await sbx.kill()
```

code interpreter 的用法相同，使用管理员为它构建的模板（见下文）：

```python
from e2b_code_interpreter import Sandbox

sbx = Sandbox.create("code-interpreter-v1")
print(sbx.run_code("6 * 7").text)               # 42
```

和其他 OpenDsec 调用一样，你的 token 的权限、配额和审计记录照常生效：网关自己不保存任何状态，每次调用都用你的 token 发出。

## 支持的功能

用 E2B 的 Python SDK（同步和异步）、JS/TS SDK 和 code interpreter SDK 验证过（`test/e2e/testdata/e2b_*`）：

| 方面 | 支持 |
|---|---|
| sandbox | `create`、`connect`、`get_info`、`list`、`kill`、`set_timeout`、`is_running`、metadata、环境变量 |
| 命令 | 输出和流式输出、退出码、`envs`、`cwd`、后台进程、stdin、`kill`、`list`、重新连接 |
| 终端 | `pty.create`、输入、调整窗口大小 |
| 文件 | `read`、`write`（任意大小，按 2 MB 分块）、`list`、`make_dir`、`rename`、`remove`、`exists`、`get_info` |
| 端口 | `get_host(port)`：HTTP、流式响应、到 sandbox 内服务的 WebSocket |
| code interpreter | `run_code` 的结果、日志、错误、图表、pandas 表格、上下文、`envs` |
| fork 和快照 | `fork(count)`、`create_snapshot(name)`、`list_snapshots`、`delete_snapshot`、`Sandbox.create(snapshot_id)`；microVM 会保留内存，运行中的进程会延续下去 |
| 生命周期 | `pause`、通过 `connect` 恢复、`lifecycle={"on_timeout": "pause"}`（autoPause）、refresh 保活 |
| 网络 | `allow_internet_access`、`network={"allow_out": [...], "deny_out": ["0.0.0.0/0"]}`、`update_network` |

## 和 E2B 的差别

| | E2B | OpenDsec 网关 |
|---|---|---|
| API key | E2B 的 key | OpenDsec 的 token |
| 模板 | 用 E2B 的模板构建生成 | 管理员在集群配置里把模板名对应到 OpenDsec 的镜像、后端和规格；也可以直接写 OpenDsec 的镜像名（`root/py:3.12`）。没有模板构建 API |
| sandbox 端口 | 可以开放公开访问 | 必须带 token（SDK 会自动带上）；不能直接用浏览器访问 |
| 暂停的 sandbox | 只有开了 autoResume 时，有流量才会恢复 | 任何调用都会让它恢复 |
| 自动恢复之后 | 重新开始计原来的超时 | 按空闲超时计 |
| 只保存文件系统的暂停 | 支持 | 拒绝（400）：暂停总是保留内存 |
| 只保存文件系统的快照 | 支持 | microVM 上拒绝（400）；容器的快照本来就只有文件系统（没有内存可保留） |
| 禁止出站 | 任意网段 | 只能禁止全部流量（`0.0.0.0/0`）；其余都按规则放行 |
| 域名规则 | `*.example.com` 覆盖子域名 | 也覆盖 `example.com` 本身 |
| 创建时给的 `envVars` 在 `run_code` 里 | 生效 | 不生效（请给 `run_code` 传 `envs`） |
| code interpreter 的内核 | Python、JavaScript、R、Java、Bash | Python |
| 不支持 | | 监听目录、签名文件地址、MCP、volume、metrics（返回空列表）、请求改写规则、出站代理 |

网关做不到的选项会以 400 拒绝，而不是悄悄忽略，所以程序不会在没拿到所要设置的情况下运行。

## 速度

2026-10-23 在项目的裸金属测试机（AMD EPYC 9Y24）上经网关在 microVM（Firecracker）上测得：

| | 耗时 |
|---|---|
| `Sandbox.create()`，模板 `base`（2 vCPU、1 GB、冷启动） | p50 166 ms |
| 创建后的第一条命令 | p50 12 ms |
| `Sandbox.create("code-interpreter-v1")`（2 GB 内存快照） | 约 250 ms |
| 第一次 `run_code` | 约 40 ms |
| `fork(count=2)` | 约 100–150 ms |
| `create_snapshot()` | 约 40–70 ms |
| `Sandbox.create(snapshot_id)` | 约 65–85 ms；拍完快照马上创建的第一个约 0.6 s（要等快照在后台发布到镜像库） |

## 管理员

1. 在集群配置里加上 `e2b` 一节并下发（docs/OPERATIONS.md §4「E2B 网关」）：
   ```json
   "e2b": {
     "gateways": [{"addr": "10.0.0.11:7400"}, {"addr": "10.0.0.12:7400"}],
     "project": "root/e2b",
     "templates": {"base": {"image": "root/py:3.12", "backend": "microvm", "cpu": 2, "memory_mb": 1024}},
     "max_timeout_s": 86400
   }
   ```
2. 一台一台地给节点加上 fleet 角色 `e2b=<序号>`（`opendsecctl fleet node set`，然后 `fleet node sync`）。
3. 前面放一个负载均衡：TCP 7400，健康检查用 HTTP 9467 `/readyz`，空闲超时不低于 60 秒。TLS 可以在负载均衡上终止，也可以给网关配置 `tls_cert` 和 `tls_key`。
4. 给调用方的 token 授予项目上的 `sandbox.create` 和 `sandbox.operate`，以及镜像所在项目上的 `layer.use`。用快照还需要项目上的 `layer.publish`，因为快照就是这个项目里的一个镜像。
5. code interpreter 需要它的模板：`deploy/e2b/build-code-interpreter.py` 会构建 `root/code-interpreter:v1`，即一个运行着 E2B code-interpreter 服务的 microVM 的内存快照，再在模板配置里把一个名字对应到它。
6. 和 E2B 一样，经网关创建的 sandbox 默认可以访问公网，除非调用方关闭（`allow_internet_access=False`，或者 `deny_out` 全部流量），不受集群 `network.default_rules` 的影响。
