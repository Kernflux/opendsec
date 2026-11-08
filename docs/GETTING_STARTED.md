# 使用已有集群

给集群已经在运行的开发者看。搭建集群见 [INSTALL.md](INSTALL.md) 和 README 的“Deploy a cluster”，这里用不到。

## 1. 需要什么

向集群管理员要：

| 项目 | 例子 |
|---|---|
| 地址 | `10.0.0.11:7100,10.0.0.12:7100`（内网），或 `api.example.com:443`（有公共证书的入口） |
| CA 证书 | `ca.crt`，只有内网方式需要 |
| token | `dsk.<id>.<secret>`，当密码保管 |
| 项目 | `root/team`，你的 sandbox 计入它的配额 |
| 镜像 | `root/py:3.12`，或者自己做（第 5 节） |

## 2. 安装

需要 Python 3.10 或以上：

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install "git+https://github.com/Kernflux/opendsec#subdirectory=sdk/python"
# 或者管理员给的 wheel：pip install opendsec_sdk-<版本>-py3-none-any.whl
```

包名是 `opendsec-sdk`（`import opendsec`）。**不要** `pip install opendsec`：PyPI 上这个名字属于一个无关的项目。

## 3. 连接

```sh
export OPENDSEC_TOKEN='dsk....' OPENDSEC_PROJECT=root/team
# 内网：
export OPENDSEC_ADDR=10.0.0.11:7100,10.0.0.12:7100 OPENDSEC_CA=$PWD/ca.crt
# 或者有公共证书的入口：
export OPENDSEC_ADDR=api.example.com:443 OPENDSEC_TLS=1
```

## 4. 运行代码

[`sdk/python/examples/execute_code.py`](../sdk/python/examples/execute_code.py) 创建一个 sandbox，在里面运行一段 Python，然后停掉它：

```python
from opendsec import DSecClient, DSecRunArgs

async with DSecClient() as client:
    async with client.sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12")) as sb:
        r = await sb.exec(["python3", "-c", "print(6*7)"])
        print(r.exit_code, r.stdout)        # 0 42
```

```sh
python execute_code.py
```

- `client.sandbox(...)` 在代码块结束时停掉 sandbox，出错时也一样。程序被强制结束的话，sandbox 最多一小时后自己停（默认的 `ttl_max`）。
- `sb.exec([...])` 用列表传命令：每个参数原样交给程序，不可信的输入没法注入 shell 命令。`timeout=` 到时杀掉（`r.timed_out`）。
- 文件：`sb.write_file(path, data)`、`sb.read_file(path)`。

出错时，错误会告诉你该检查什么：

```python
from opendsec import DSecError
try:
    ...
except DSecError as e:
    print(e.code, e.message)   # 例如 quota_exceeded
    print(e.next_steps)        # 该怎么办
    print(e.retryable)         # 同样的调用能否直接重试
```

## 5. 自己的镜像

```python
from opendsec import Template

t = (Template()
     .from_registry("python:3.12-slim")      # 任意公开仓库的镜像
     .pip_install(["pandas"])
     .copy("./app", "/app")
     .workdir("/app"))
await t.build(client, "root/team/myenv:v1")
```

集群负责拉取和构建；之后用 `image="root/team/myenv:v1"`。项目可能限制镜像的数量和保留时间。

## 6. fork 和暂停

| 示例 | 演示什么 | 需要 |
|---|---|---|
| [`memory_fork.py`](../sdk/python/examples/memory_fork.py) | fork 一个运行中的 microVM：副本从它的内存继续运行，然后各走各的 | microvm 后端 |
| [`task_pause.py`](../sdk/python/examples/task_pause.py) | 一次调用暂停、恢复整批 sandbox（`task_id`） | microvm 或 container |
| [`decoupled_rollout.py`](../sdk/python/examples/decoupled_rollout.py) | 等推理时暂停的 RL rollout | container |

## 7. 更多

- [USER_GUIDE.md](USER_GUIDE.md)：限制、错误与重试、token。
- [PYTHON_SDK.md](PYTHON_SDK.md)：所有调用。
- [E2B.md](E2B.md)：为 E2B SDK 写的程序。
