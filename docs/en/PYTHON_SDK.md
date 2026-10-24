# Python SDK reference

`opendsec` is OpenDsec's asynchronous Python SDK, built on gRPC and `asyncio`. This page lists all of its classes and methods. The concepts behind them (backends, states, timeouts, sessions, permissions) are in [Concepts](CONCEPTS.md).

- Python 3.10 or newer; depends on `grpcio>=1.73.1`, `protobuf>=6.31,<8` and `googleapis-common-protos>=1.60`.
- Licensed Apache-2.0: programs that call OpenDsec are not bound by the server's AGPL.
- Every method is a coroutine: `await` it inside an `async` function.

## Install

```sh
# from the source repository
python3 -m venv .venv && .venv/bin/pip install ./sdk/python
# from a wheel your administrator gave you
pip install opendsec-0.11.0-py3-none-any.whl
```

Offline: the offline bundle's `wheels/` directory holds the SDK and all its dependencies; install with `pip install --no-index --find-links wheels opendsec`.

## Quick example

```python
import asyncio
from opendsec import DSecClient, DSecRunArgs, DSecError

async def main():
    async with DSecClient() as client:            # reads the OPENDSEC_* variables
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm", image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            ttl_running_stop=600,                   # stop after 10 idle minutes
            network_rules={"pypi": True}))          # PyPI only
        try:
            r = await sb.run_shell("pip install requests && python3 -c 'import requests; print(requests.__version__)'")
            print(r.exit_code, r.stdout, r.stderr)
        finally:
            await sb.stop()

asyncio.run(main())
```

## Connecting: `DSecClient`

```python
DSecClient(endpoint=None, token=None, project=None, ca_file=None,
           server_name=None, retry_timeout=60)
```

| Parameter | Environment variable | Default | Meaning |
|---|---|---|---|
| `endpoint` | `OPENDSEC_ADDR` | `127.0.0.1:7100` | Apiserver address `host:port`. Several addresses, comma separated (`10.0.0.11:7100,10.0.0.12:7100`), spread calls over every reachable apiserver and move off one that goes down |
| `token` | `OPENDSEC_TOKEN` | empty | The caller's credential `dsk.<id>.<secret>`, sent with every call |
| `project` | `OPENDSEC_PROJECT` | `root` | Default project for creations, listings, task actions and image listings |
| `ca_file` | `OPENDSEC_CA` | none | The cluster's CA certificate. Set, the client uses TLS; unset, plaintext, for development clusters only |
| `server_name` | — | none; `api.opendsec.internal` with several addresses | The name the server certificate is checked against. Every apiserver certificate carries `api.opendsec.internal` |
| `retry_timeout` | — | 60 | How long (seconds) calls keep retrying while a server is unreachable (`unavailable`: a restart, a failover). 0 disables retries |

```python
async with DSecClient() as client:      # recommended: connects on entry, closes on exit
    ...

client = DSecClient(endpoint="10.0.0.10:7100", token=tok, project="root/team-a", ca_file="ca.crt")
await client.open()                      # or open and close it yourself
...
await client.close()
```

Connection settings (automatic): reconnects start after 100 ms and back off to at most 2 s; a keepalive every 10 s detects a silently lost connection within about 15 s; messages may be up to 80 MB.

## Creation arguments: `DSecRunArgs`

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

| Field | Meaning |
|---|---|
| `backend` | `microvm`, `container`, `fncall`, `fullvm` or `sim`. **The default, `sim`, only simulates and runs nothing: always set it** |
| `image` | Image name `<project>/<name>:<tag>`, e.g. `root/py:3.12`. Needs `layer.use` on the image's project |
| `cpu_cores_limit` | CPU cores; may be fractional |
| `memory_limit_mb` | Memory (MB). Creating from a snapshot with memory, it must equal the snapshot's |
| `gpus`, `gpu_mode` | Number of GPUs; `gpu_mode` is `exclusive` or `shared` (default: the node decides) |
| `disk_mb` | Writable disk size (MB); 0 means the backend's default |
| `ttl_running_stop` | Idle timeout (seconds); 0 means the cluster default (usually 1 hour) |
| `ttl_max` | Lifetime (seconds) from creation, paused time included; 0 means the cluster default (usually 1 day); usually at most 7 days |
| `network_rules` | Network rules, e.g. `{"pypi": True}`, `{"*": True}`, `{"github.com:443": True}`. See [Network policy](NETWORK.md) |
| `init_user` | The sandbox's default user, also the sessions' default user |
| `task_id` | Task name, for task actions such as `pause_task` |
| `qos` | `LS` (latency-sensitive, default) or `BE` (best effort) |
| `labels` | Arbitrary key-value labels, kept in the sandbox's spec |
| `project` | The project to create in; default: the client's `project` |

`DSecContainerRunArgs` is a subclass with `backend="container"` by default and a `container_image` field (as the paper writes it) that replaces `image` when set:

```python
DSecContainerRunArgs(container_image="root/py:3.12", memory_limit_mb=4096, cpu_cores_limit=4)
```

## Creating and querying

### `run_sandbox(args, timeout=120) -> Sandbox`

Creates a sandbox and returns once it is `RUNNING`.

- `timeout`: limit for the whole creation (seconds); `None` for none.
- While the server is unreachable, the call retries within `retry_timeout`. Each creation carries a random idempotency key: even if the first answer was lost, a retry returns the sandbox the first attempt created, never a second one.
- Needs `sandbox.create` on the project and `layer.use` on the image's project.
- Common errors: `quota_exceeded`, `no_capacity`, `invalid` (no such image or backend, a timeout over the limit), `forbidden`.

### `run_container(args, timeout=120) -> Sandbox`

The same as `run_sandbox`, usually with `DSecContainerRunArgs`.

### `run_sandboxes(args, count, timeout=600) -> list[Sandbox | DSecError]`

Creates `count` sandboxes of one spec, up to 32768 per call.

- The list is in index order: `Sandbox` for each success, `DSecError` for each failure (not raised).
- The server queues creations at the rate limit, so rate limiting never fails part of a large batch.
- A lost connection is retried; only what is still missing gets created.
- If the batch request itself fails (no permission, say), `DSecError` is raised.

```python
res = await client.run_sandboxes(DSecRunArgs(backend="microvm", image="root/py:3.12", task_id="job-7"), 500)
ok = [x for x in res if not isinstance(x, DSecError)]
failed = [x for x in res if isinstance(x, DSecError)]
```

### `run_containers(args, count, timeout=600)`

The same as `run_sandboxes`.

### `get_sandbox(sandbox_id) -> Sandbox`

Looks a sandbox up by id. Needs `sandbox.operate` on its project. Ended sandboxes stay on their node for 10 minutes; after that, `not_found`.

### `list_sandboxes(task_id="", include_ended=False, project=None) -> list[Sandbox]`

Lists the sandboxes of a project and all its subprojects. `task_id` narrows to one task; `include_ended=True` includes recently ended ones. Needs `sandbox.operate`.

### `cluster_status() -> Snapshot`

The cluster snapshot: each edge's address, health, draining state, backends, capacity, allocated resources, sandboxes per backend, free memory and disk, and pressure (protobuf `Snapshot`; fields in `proto/opendsec/v1/cluster.proto` and `EdgeState` in `types.proto`).

## Sandbox handle: `Sandbox`

`run_sandbox`, `get_sandbox` and the others return `Sandbox` objects.

| Attribute | Meaning |
|---|---|
| `id` | Sandbox id |
| `state` | State name, e.g. `"RUNNING"`. The **last seen** state; `refresh()` updates it |
| `edge_id` | The node it runs on |
| `info` | The full record (protobuf `Sandbox`): `project`, `principal`, `spec`, `created_at`, `last_active_at`, `ended_at`, `message` |

### Lifecycle

Every lifecycle method returns the `Sandbox` itself (`info` updated) and retries while the server is unreachable. They need `sandbox.operate`.

| Method | Meaning |
|---|---|
| `refresh()` | Fetch the record again |
| `stop()` | Stop and clean up. The quota comes back at once |
| `pause()` | Pause. A microVM is snapshotted and its process ends, freeing all its memory; a container's processes are frozen |
| `resume()` | Resume. Optional: a runtime call to a paused sandbox resumes it |
| `touch()` | Reset the idle timer; resumes a paused sandbox |
| `update_network(rules, replace=False)` | Change network rules: merged into the current ones by default, replaced with `replace=True`. Taking an allowance back applies to new connections at once and cuts existing ones too |

### Running commands

```python
run_shell(cmd, timeout=None, session="default", env=None, cwd=None, user=None) -> ShellResult
```

Runs a shell command in a session and returns its result when it ends.

| Parameter | Meaning |
|---|---|
| `cmd` | A whole shell command, interpreted by the session's shell: pipes, `&&` and so on work |
| `timeout` | Seconds. When it expires, the processes the command started are killed, the session stays, and `ShellResult.timed_out` is `True` |
| `session` | Session name. Within a session, `cd` and `export` carry over between commands; sessions are independent of each other |
| `env`, `cwd` | Environment variables and working directory for this command only |
| `user` | The session's user, fixed by its **first** command: a name or `uid[:gid]` (e.g. `"1000"`). Later values for the same session have no effect |

A lost connection (edge or apiserver restart) is retried without running the command twice.

```python
r = await sb.run_shell("cd /srv && export X=1")
r = await sb.run_shell("pwd; echo $X")          # /srv 1
r = await sb.run_shell("pytest -q", timeout=600, cwd="/srv/repo")
if not r.ok:
    print(r.exit_code, r.stderr)
```

`ShellResult` fields:

| Field | Meaning |
|---|---|
| `cmd_id` | The command's number in its session |
| `exit_code` | Exit code |
| `stdout`, `stderr` | Output decoded as UTF-8 (undecodable bytes become `�`); the raw bytes are `stdout_bytes`, `stderr_bytes` |
| `done` | Whether the command has ended (background commands may not have) |
| `timed_out` | Whether it was killed by its timeout |
| `duration` | Run time (seconds) |
| `truncated` | The output exceeds what one call returns (16 MB per stream) and was not all returned; the full output (up to 64 MB per stream) is still recorded: fetch the rest with `get_output(cmd_id, stdout_offset=...)` |
| `dropped_bytes` | Bytes dropped past the 64 MB per-stream record limit |
| `ok` | `done and exit_code == 0 and not timed_out` |

### Background commands

```python
cmd_id = await sb.run_shell_background("python3 train.py", session="train")
...
r = await sb.get_output(cmd_id, session="train", wait=30)   # wait up to 30 s
print(r.done, r.stdout)
```

- `run_shell_background(cmd, timeout=None, session="default", env=None, cwd=None, user=None) -> int` starts the command and returns its number at once.
- `get_output(cmd_id, session="default", wait=0, stdout_offset=0, stderr_offset=0) -> ShellResult` returns the recorded output, waiting up to `wait` seconds for the command to end; `stdout_offset` and `stderr_offset` start from a byte position, for reading incrementally.

### Streaming output

```python
async for kind, data in sb.stream_shell("make test", timeout=1800):
    if kind == "stdout":
        sys.stdout.buffer.write(data)
    elif kind == "stderr":
        sys.stderr.buffer.write(data)
    elif kind == "exit":
        print("exit code", data.exit_code)     # data is a ShellResult without output
```

`stream_shell(cmd, timeout=None, session="default", env=None, cwd=None, user=None)` yields `("stdout", bytes)` and `("stderr", bytes)` chunks as they come, then `("exit", ShellResult)`. A broken connection resumes where it broke: the command keeps running in the sandbox and nothing is repeated or lost.

### Sessions

- `list_sessions() -> list[str]`: the sandbox's sessions.
- `close_session(session)`: end a session, killing every process it started.

### Files

Paths are absolute paths in the sandbox; file calls run as the session's user (`session` parameter, default `default`).

| Method | Meaning |
|---|---|
| `read_file(path, offset=0, length=0) -> bytes` | Read a file; `length=0` reads to the end |
| `write_file(path, data, mode=0, append=False) -> FileInfo` | Write a file; `data` is `bytes` or `str` (encoded as UTF-8). `mode` sets the permissions (e.g. `0o755`; 0 for the default); `append=True` appends |
| `list_dir(path) -> list[FileInfo]` | List a directory |
| `stat(path) -> FileInfo` | File information |
| `remove(path, recursive=False)` | Remove a file; `recursive=True` removes a directory and its contents |

`FileInfo` fields: `name`, `type` (`file`, `dir`, `symlink`, `other`), `size`, `mode`, `mtime`.

Size limits:

- one `read_file` returns at most 64 MB; read larger files in pieces with `offset` and `length`;
- keep one `write_file` under 64 MB (a message may be up to 80 MB); write larger files in pieces with `append=True`;
- in older code, a message through the apiserver was limited to 4 MB, and going over it reported `quota_exceeded` (really a message that was too large). The first entry under "Fixed" in CHANGELOG 0.11.0 raised the limit to 80 MB on the servers, the Go client and the Python SDK; such errors now report `invalid`.

```python
# Read a large file in pieces. Past the end, read_file returns b"".
chunks, off = [], 0
while True:
    part = await sb.read_file("/data/big.bin", offset=off, length=32 << 20)
    if not part:
        break
    chunks.append(part)
    off += len(part)
```

### HTTP services in the sandbox

```python
r = await sb.http("http://127.0.0.1:8000/health", method="GET", headers=None, body=b"", timeout=30)
print(r.status, r.headers, r.body)
```

Makes an HTTP request from inside the sandbox's network namespace, to reach services running in it. Returns `HttpResult(status, headers, body)`. For a direct TCP connection (WebSocket, say), use the API's `ConnectPort`, or reach the port through the E2B gateway.

### Fork, snapshots and images

```python
fork(count=1, ttl_running_stop=0, ttl_max=0, labels=None, task_id="", timeout=600) -> list[Sandbox | DSecError]
```

Copies a running sandbox into `count` (1 to 256) running sandboxes.

- The source pauses briefly and carries on, its `id` and timeouts unchanged.
- Copies inherit the source's spec; `labels` are added to theirs, `task_id` replaces the task (default: the source's), and `ttl_running_stop` and `ttl_max` are the copies' timeouts (0 for the cluster default).
- microVM copies include memory, so processes continue from the fork; container copies get the files only.
- Results are in index order, failures as `DSecError`. Each copy counts against quota. A retry after a lost connection creates only the copies still missing.
- Needs `sandbox.create` on the project and `layer.use` on the source image's project.

```python
create_snapshot(image, memory=False, overwrite=False) -> ImageInfo
```

Saves the sandbox as image `image` (`<project>/<name>:<tag>`) exactly as it is; nothing is cleaned up.

- `memory=True` (microVM only) includes memory: sandboxes created from the image resume from the snapshot, with its processes running. Their `memory_limit_mb` must equal the snapshot's.
- microVMs require `memory=True`. For a files-only image, build on container and use `pack_diff`.
- `overwrite=True` replaces an existing image of that name.
- Needs `layer.publish` on the image's project.

```python
pack_diff(image, scrub=(), overwrite=False) -> ImageInfo
```

Saves the sandbox's changes against the image it started from as a new image `image`, stacked on that image (container-type backends only).

- Removed by default: `/tmp/*`, `/var/tmp/*`, `/root/.cache`, `/root/.bash_history`, `/home/*/.bash_history`, `/root/.python_history`. `scrub` adds more (globs relative to `/`, e.g. `["srv/repo/.git"]`).
- The image works for both container and microVM.
- Needs `layer.publish` on the image's project.

```python
sb = await client.run_container(DSecContainerRunArgs(container_image="root/rl/python:3.12",
                                                     network_rules={"pypi": True, "github": True}))
await sb.run_shell("git clone https://github.com/org/repo /srv/repo && pip install -e /srv/repo")
img = await sb.pack_diff("root/rl/repo-env:v1")
await sb.stop()
# from now on, create from root/rl/repo-env:v1 instead of installing again
```

`ImageInfo` fields: `name`, `layers` (bottom first), `env`, `workdir`, `user`, `parent`, `source`, `created_at`, `created_by`, `snapshot`, `memory`.

## Task actions

| Method | Meaning |
|---|---|
| `pause_task(task_id, project=None)` | Pause every sandbox of the task |
| `resume_task(task_id, project=None)` | Resume every sandbox of the task |
| `stop_task(task_id, project=None)` | Stop every sandbox of the task |

They return a `TaskActionResult`: `affected` (succeeded), `failed`, `errors` (the failures' reasons). They need `sandbox.operate`.

## Images

| Method | Meaning | Permission |
|---|---|---|
| `list_images(project=None) -> list[ImageInfo]` | Images of the project and its subprojects | `layer.use` |
| `get_image(name) -> ImageInfo` | One image | `layer.use` |
| `compose_image(name, parts, env=None, workdir="", user="", overwrite=False) -> ImageInfo` | Stack the `parts` bottom first into a new image without copying data. `env` adds environment variables; `workdir` and `user` set the defaults | `layer.publish` on the new image's project, `layer.use` on each part's |
| `delete_image(name)` | Delete the image's registration. `opendsecctl image gc` reclaims its layers | `layer.publish` |

```python
await client.compose_image("root/rl/swe-4821:v1",
                           ["root/rl/python:3.12", "root/rl/django-ws:a1b2", "root/tools/agent-kit:3"])
```

Importing from a registry is CLI-only (`opendsecctl image import`): it writes into the store on a machine that mounts it.

## Projects, principals and tokens

These methods use the same API as `opendsecctl`, for people and agents alike, under the same permission rules ([Projects, principals and permissions](IAM.md)).

| Method | Meaning | Needs |
|---|---|---|
| `whoami() -> str` | The principal of the current token | — |
| `create_project(parent, name, quota=None) -> Project` | Create a subproject of `parent`. `quota` e.g. `{"sandboxes": 100, "cpu_cores": 400}`; keys left out take the parent's limit | `project.admin` on `parent` |
| `get_project(project=None) -> Project` | `path`, `quota`, `usage` (current), `policies` (each principal's permissions), `children` | any permission on the project |
| `set_quota(project, quota) -> Project` | Set the quota (replaced as a whole); may not exceed any ancestor's | `project.admin` on the parent project |
| `delete_project(project)` | Delete an empty project (no subprojects, no usage, no principals of its own) | `project.admin` on the parent project |
| `create_principal(project, principal_id, kind="agent", ttl=0) -> str` | Create a principal in the project and return its first token (**returned only this once**). `ttl`: the token's lifetime in seconds, 0 for the server default | `project.admin` |
| `delete_principal(principal)` | Delete a principal and all its tokens | `project.admin` on the principal's project |
| `grant(project, principal, perms) -> Project` | Grant permissions, e.g. `["sandbox.create", "sandbox.operate"]`. Only permissions you hold yourself | `project.admin` and each permission granted |
| `revoke(project, principal, perms=()) -> Project` | Revoke permissions; all of them when `perms` is empty | `project.admin` |
| `create_token(principal=None, ttl=0, description="") -> (str, TokenInfo)` | Issue a token, by default for yourself | yourself: nothing; others: `project.admin` on their project |
| `list_tokens(principal=None) -> list[TokenInfo]` | Tokens without secrets: `id`, `created_at`, `expires_at` (0: never), `description`, `created_by` | as above |
| `revoke_token(principal, token_id)` | Revoke a token; it stops working on every apiserver within about 1 s | as above |
| `get_usage(project=None, start="", end="") -> UsageReport` | Usage of the project and its subprojects per UTC day; `start` and `end` are `YYYY-MM-DD`, inclusive | `project.admin` |

Each row of `UsageReport.rows`: `project`, `day`, `sandboxes_started`, `sandbox_hours`, `cpu_core_hours`, `memory_gb_hours`, `gpu_hours`.

## Errors: `DSecError`

Every failure raises `DSecError`, except single items of a batch creation or fork, which go in the result list.

```python
from opendsec import DSecError, QUOTA_EXCEEDED, NO_CAPACITY

try:
    sb = await client.run_sandbox(args)
except DSecError as e:
    if e.reason in (QUOTA_EXCEEDED, NO_CAPACITY):
        await asyncio.sleep(5)        # try again later
    else:
        raise
```

- `e.reason`: a stable reason string, with a constant of the same name in the module: `UNAUTHENTICATED`, `FORBIDDEN`, `NOT_FOUND`, `QUOTA_EXCEEDED`, `RATE_LIMITED`, `NO_CAPACITY`, `INVALID`, `UNAVAILABLE`, `TIMEOUT`, `INTERNAL`. What each means and what to do: [Concepts §9](CONCEPTS.md#_9-errors).
- `e.message`: the server's explanation.

**What is retried automatically**: only `unavailable` (server unreachable), within `retry_timeout`, for creation, batch creation, fork, lifecycle calls, commands, file reads, directory listings, sessions and streams. `write_file`, `remove`, `http`, `update_network`, `pack_diff`, `create_snapshot` and the management methods are not retried; on failure the caller decides.

## Patterns

### RL rollouts

```python
async def rollout(client, step_image, episode):
    sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image=step_image,
                                              cpu_cores_limit=2, memory_limit_mb=2048,
                                              task_id="ppo-run-42", ttl_max=3600))
    try:
        for action in episode:
            r = await sb.run_shell(action, session="agent", user="1000", timeout=120)
            ...
        score = await sb.run_shell("python3 /grader/grade.py", session="grader")   # a root session
        return float(score.stdout)
    finally:
        await sb.stop()

# training is preempted
await client.pause_task("ppo-run-42")
# afterwards, the next call to each sandbox resumes it; or explicitly:
await client.resume_task("ppo-run-42")
```

### Branching from one state

```python
base = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/swe-4821:v1"))
await base.run_shell("cd /srv/repo && git apply /tmp/partial.patch")
branches = await base.fork(count=8, task_id="search-17")
results = await asyncio.gather(*(b.run_shell(f"python3 try.py --variant {i}")
                                 for i, b in enumerate(branches) if not isinstance(b, DSecError)))
```

### A warmed-up environment

```python
sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/model-server:v1",
                                          memory_limit_mb=4096))
# start a long-running service that loads a model (slow), then waits for requests on port 8000
await sb.run_shell("(nohup python3 /srv/serve.py > /tmp/serve.log 2>&1 &)")
await sb.run_shell("until curl -sf http://127.0.0.1:8000/ready; do sleep 1; done", timeout=600)
await sb.create_snapshot("root/rl/model-server:warm", memory=True)
await sb.stop()
# created from the snapshot, the service is already running with the model loaded: ready in about 55 ms
fast = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/model-server:warm",
                                            memory_limit_mb=4096))
```

More examples in the repository's `sdk/python/examples/`: `quickstart.py`, `test_features.py` (checks each feature in turn), `load_test.py` (load test), `decoupled_rollout.py` (decoupled rollouts).
