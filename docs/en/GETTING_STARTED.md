# Use an existing cluster

For developers whose cluster is already running. Setting a cluster up is
in [INSTALL.md](INSTALL.md) and the README's "Deploy a cluster"; you do not
need either here.

## 1. What you need

From your cluster's administrator:

| Item | Example |
|---|---|
| address | `10.0.0.11:7100,10.0.0.12:7100` (inside the network), or `api.example.com:443` (behind a public certificate) |
| CA certificate | `ca.crt`, inside the network only |
| token | `dsk.<id>.<secret>`: treat it like a password |
| project | `root/team`: your sandboxes count against its quota |
| an image | `root/py:3.12`, or make your own (section 5) |

## 2. Install

Python 3.10 or newer:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install "git+https://github.com/Kernflux/opendsec#subdirectory=sdk/python"
# or a wheel your administrator gave you: pip install opendsec_sdk-<version>-py3-none-any.whl
```

The package is `opendsec-sdk` (`import opendsec`). **Not** `pip install
opendsec`: that name on PyPI belongs to an unrelated project.

## 3. Connect

```sh
export OPENDSEC_TOKEN='dsk....' OPENDSEC_PROJECT=root/team
# inside the network:
export OPENDSEC_ADDR=10.0.0.11:7100,10.0.0.12:7100 OPENDSEC_CA=$PWD/ca.crt
# or behind a public certificate:
export OPENDSEC_ADDR=api.example.com:443 OPENDSEC_TLS=1
```

## 4. Run code

[`sdk/python/examples/execute_code.py`](../../sdk/python/examples/execute_code.py)
makes a sandbox, runs a Python program in it and stops it:

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

- `client.sandbox(...)` stops the sandbox when the block ends, also on
  errors. If your program is killed, the sandbox stops by itself after an
  hour (its default `ttl_max`).
- `sb.exec([...])` takes the command as a list: each argument reaches the
  program as it is, so untrusted input cannot inject shell commands.
  `timeout=` kills it (`r.timed_out`).
- Files: `sb.write_file(path, data)`, `sb.read_file(path)`.

When something fails, the error says what to check:

```python
from opendsec import DSecError
try:
    ...
except DSecError as e:
    print(e.code, e.message)   # e.g. quota_exceeded
    print(e.next_steps)        # what to do about it
    print(e.retryable)         # whether the same call may simply be repeated
```

## 5. Your own image

```python
from opendsec import Template

t = (Template()
     .from_registry("python:3.12-slim")      # any public registry image
     .pip_install(["pandas"])
     .copy("./app", "/app")
     .workdir("/app"))
await t.build(client, "root/team/myenv:v1")
```

The cluster pulls and builds it; then use `image="root/team/myenv:v1"`.
Your project may limit how many images it keeps and for how long.

## 6. Fork and pause

| Example | What it shows | Needs |
|---|---|---|
| [`memory_fork.py`](../../sdk/python/examples/memory_fork.py) | fork a running microVM: the copies continue from its memory, then diverge | microvm backend |
| [`task_pause.py`](../../sdk/python/examples/task_pause.py) | pause and resume a whole batch (`task_id`) in one call each | microvm or container |
| [`decoupled_rollout.py`](../../sdk/python/examples/decoupled_rollout.py) | RL rollouts that pause while waiting for inference | container |

## 7. More

- [USER_GUIDE.md](USER_GUIDE.md): limits, errors and retries, tokens.
- [PYTHON_SDK.md](PYTHON_SDK.md): every call.
- [E2B.md](E2B.md): programs written for E2B's SDKs.
