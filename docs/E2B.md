# Moving from E2B to OpenDsec

OpenDsec's E2B gateway (`opendsec-e2b`) serves the API that E2B's SDKs talk to. Code written for E2B, and agent frameworks built on its SDKs, run on your own OpenDsec cluster without changes: you point the SDK at the gateway and use an OpenDsec token as the API key. The design and its tests are in SPEC §37.

## For callers: three environment variables

```sh
export E2B_API_URL=http://<gateway>:7400       # https://... when TLS is on
export E2B_SANDBOX_URL=http://<gateway>:7400
export E2B_API_KEY=<your OpenDsec token>         # dsk.<id>.<secret>
```

```python
from e2b import Sandbox

sbx = Sandbox.create()                          # template "base"
print(sbx.commands.run("python3 -V").stdout)
sbx.files.write("/tmp/a.txt", "hello")
sbx.kill()
```

E2B's JS SDK needs Node.js 22.19 or newer (Ubuntu 24.04's own `nodejs` is 18: take Node from nodejs.org):

```js
import { Sandbox } from 'e2b'

const sbx = await Sandbox.create()
console.log((await sbx.commands.run('python3 -V')).stdout)
await sbx.kill()
```

The code interpreter works the same way, on a template your administrator built for it (see below):

```python
from e2b_code_interpreter import Sandbox

sbx = Sandbox.create("code-interpreter-v1")
print(sbx.run_code("6 * 7").text)               # 42
```

Your token's permissions, quota and audit trail apply as for any OpenDsec call: the gateway keeps no state of its own and makes every call with your token.

## What works

Checked with E2B's Python SDK (sync and async), JS/TS SDK and code interpreter SDKs (`test/e2e/testdata/e2b_*`):

| Area | Supported |
|---|---|
| Sandboxes | `create`, `connect`, `get_info`, `list`, `kill`, `set_timeout`, `is_running`, metadata, environment variables |
| Commands | output and streaming, exit codes, `envs`, `cwd`, background processes, stdin, `kill`, `list`, reconnecting |
| Terminals | `pty.create`, input, resize |
| Files | `read`, `write` (any size, 2 MB chunks), `list`, `make_dir`, `rename`, `remove`, `exists`, `get_info` |
| Ports | `get_host(port)`: HTTP, streamed responses, WebSocket to a server in the sandbox |
| Code interpreter | `run_code` with results, logs, errors, charts, pandas tables, contexts, `envs` |
| Fork and snapshots | `fork(count)`, `create_snapshot(name)`, `list_snapshots`, `delete_snapshot`, `Sandbox.create(snapshot_id)`; on microVMs memory is kept, so running processes carry over |
| Lifecycle | `pause`, resume through `connect`, `lifecycle={"on_timeout": "pause"}` (autoPause), the refresh keepalive |
| Network | `allow_internet_access`, `network={"allow_out": [...], "deny_out": ["0.0.0.0/0"]}`, `update_network` |

## What differs

| | E2B | OpenDsec gateway |
|---|---|---|
| API key | E2B key | an OpenDsec token |
| Templates | built by E2B's template build | names an administrator maps to an OpenDsec image, backend and size in the cluster config; an OpenDsec image name (`root/py:3.12`) also works. No template build API |
| Sandbox ports | public access can be enabled | always need the token (the SDKs send it); no plain browser access |
| Paused sandboxes | resumed by traffic only with autoResume | any call resumes them |
| After an auto-resume | the original timeout restarts | the idle timeout applies |
| Filesystem-only pauses | supported | refused (400): pauses keep memory |
| Filesystem-only snapshots | supported | refused (400) on microVMs; container snapshots are filesystem-only (no memory to keep) |
| Egress denials | any CIDR | only all traffic (`0.0.0.0/0`); everything else is allowed by rule |
| Domain rules | `*.example.com` covers subdomains | also covers `example.com` itself |
| `envVars` given at creation, in `run_code` | applied | not applied (pass `envs` to `run_code`) |
| Code interpreter kernels | Python, JavaScript, R, Java, Bash | Python |
| Not available | | watching directories, signed file URLs, MCP, volumes, metrics (an empty list), request transform rules, egress proxy |

An option the gateway cannot honour is refused with 400 rather than ignored, so a program never runs with settings it did not get.

## Speed

Measured through the gateway on microVMs (Firecracker), on the project's bare-metal test hosts (AMD EPYC 9Y24), 2026-10-23:

| | Time |
|---|---|
| `Sandbox.create()`, template `base` (2 vCPU, 1 GB, cold boot) | p50 166 ms |
| First command after creation | p50 12 ms |
| `Sandbox.create("code-interpreter-v1")` (2 GB memory snapshot) | about 250 ms |
| First `run_code` | about 40 ms |
| `fork(count=2)` | about 100–150 ms |
| `create_snapshot()` | about 40–70 ms |
| `Sandbox.create(snapshot_id)` | about 65–85 ms |

## For administrators

1. Add an `e2b` section to the cluster config and roll it out (docs/OPERATIONS.md §4, "E2B 网关"):
   ```json
   "e2b": {
     "gateways": [{"addr": "10.0.0.11:7400"}, {"addr": "10.0.0.12:7400"}],
     "project": "root/e2b",
     "templates": {"base": {"image": "root/py:3.12", "backend": "microvm", "cpu": 2, "memory_mb": 1024}},
     "max_timeout_s": 86400
   }
   ```
2. Give nodes the fleet role `e2b=<index>`, one at a time (`opendsecctl fleet node set` then `fleet node sync`).
3. Put a load balancer in front: TCP 7400, health check HTTP 9467 `/readyz`, idle timeout at least 60 s. Terminate TLS there, or set `tls_cert` and `tls_key` on the gateways.
4. Give callers tokens with `sandbox.create` and `sandbox.operate` on the project and `layer.use` on the images' projects. Snapshots also need `layer.publish` on the project, since a snapshot is an image there.
5. The code interpreter needs its template: `deploy/e2b/build-code-interpreter.py` builds `root/code-interpreter:v1`, a memory snapshot of a microVM running E2B's code-interpreter server, and the template entry maps a name to it.
6. As on E2B, sandboxes made through the gateway can reach the internet unless the caller turns it off (`allow_internet_access=False`, or `deny_out` of all traffic), whatever the cluster's `network.default_rules`.
