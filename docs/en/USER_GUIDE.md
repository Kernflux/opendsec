# OpenDsec caller guide

> For administrators: this guide is written for the people who use the cluster. Fill in the items marked "administrator fills in" and hand it to them.

OpenDsec provides isolated environments for running code, called sandboxes. You create sandboxes with the Python SDK, run commands and read and write files in them, and stop them when you are done.

## 1. What you get

| File or item | Meaning |
|---|---|
| `opendsec-<version>-py3-none-any.whl` | The Python SDK; needs Python 3.10 or newer |
| `ca.crt` | The cluster CA, to verify the server's certificate |
| token | Your credential, `dsk.<id>.<secret>`. **Treat it like a password** and keep it out of code repositories |
| project | E.g. `root/prod`. Every sandbox you create counts against this project's quota |
| address | See below |

**Address** (several addresses, comma separated, spread calls over every reachable apiserver and avoid one that is down):
- with a load balancer, a single address, e.g. `api.opendsec.internal:7100`;
- without one, every apiserver's address, e.g. `10.0.0.11:7100,10.0.0.12:7100,10.0.0.13:7100`.
- Your cluster administrator gives you the address.

## 2. Install and a first sandbox

```sh
pip install opendsec-<version>-py3-none-any.whl
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
    async with DSecClient() as client:                     # reads the variables above
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm", image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            ttl_running_stop=600))                         # stops after 10 idle minutes
        try:
            r = await sb.run_shell("python3 -c 'print(6*7)'")
            print(r.stdout)                                # 42
        finally:
            await sb.stop()

asyncio.run(main())
```

## 3. Common operations

| Operation | SDK |
|---|---|
| Create | `client.run_sandbox(DSecRunArgs(...))`; batches with `client.run_sandboxes(args, count)`, up to 32768 per call |
| Run a command | `sb.run_shell(cmd, timeout=...)` returns stdout, stderr and the exit code; environment variables and the current directory carry over within one `session` |
| Background commands / streaming | `sb.run_shell_background(...)` + `sb.get_output(...)`; `sb.stream_shell(...)` |
| Files | `sb.write_file(path, data)`, `sb.read_file(path)`, `sb.list_dir(path)`, `sb.remove(path)` |
| HTTP services in the sandbox | `sb.http(url)` |
| Pause / resume | `sb.pause()` / `sb.resume()`: a paused sandbox keeps its memory state and continues where it left off |
| Copy | `sb.fork(count=N)`: N copies of a running sandbox, same memory and files (microvm) |
| Network rules | `sb.update_network({...})` |
| Make an image | container: `sb.pack_diff("root/prod/<repo>:<tag>")` saves files only, without build residue in /tmp, caches and so on; the image works on container and microvm. microvm: `sb.create_snapshot(image, memory=True)` saves memory too, and sandboxes created from it continue from the moment it was saved; microvm cannot save files only, so build files-only images on container |
| Stop | `sb.stop()`. **Always stop sandboxes when you are done**: they hold quota until they time out |
| Separate the agent from grading | `run_shell(cmd, session="agent", user="1000")` runs the agent's commands as an unprivileged user, with grading in another session (root by default). A session's user is fixed by its first command. An unprivileged session cannot reach other sessions, read their output records or change system files; write files the agent must not see with strict permissions (e.g. `umask 077`) |

## 4. Specs and limits

- **backend**:
  - `microvm`: Firecracker virtual machines, the strongest isolation, starting in about 0.2 s, with pause, resume and fork. **Recommended.**
  - `container`: containers, starting in about 0.1 s.
- **Images**: images the administrator imported, such as `root/py:3.12` (python:3.12) from the quickstart; `client.list_images()` lists them. Ask your administrator for other images.
- **Network**:
  - Whether sandboxes reach the internet by default depends on the cluster config (`network.default_rules`; administrator fills in). Clusters installed with the quickstart reach nothing by default; allow what you need in `network_rules`, e.g. `{"*": True}` or a rule set `{"pypi": True}`.
  - Private addresses (the VPC, cluster nodes) and cloud metadata are unreachable by default: `*` excludes them, and private addresses a domain resolves to are always blocked. To reach one internal service, name its address or network explicitly, e.g. `{"10.30.0.10:5432/tcp": True}` ([Network policy](NETWORK.md)).
  - Narrowing rules: keys of `network_rules` can be rule set names, domains (with subdomains), IPv4 addresses or networks, or `"*"` (every public address), optionally followed by `:port[/protocol]` to allow only those ports, e.g. `{"*": False, "pypi.org:443": True, "files.pythonhosted.org:443/tcp": True}`. Ports may be ranges such as `8000-8080`; the protocol is `tcp` or `udp`, both when left out.
  - IPv4 only.
- **Lifecycle**:
  - The idle timeout `ttl_running_stop` defaults to 1 hour. A sandbox is idle while no command runs and no other call arrives; it stops when the timeout is reached.
  - The lifetime `ttl_max` defaults to 1 day and can be at most 7 days.
- **Quota**: each project's number of sandboxes and resources at a time are limited (administrator fills in). Creations beyond it get `quota_exceeded`.
- **Disk**: the writable disk defaults to 2 GB for microvm and 1 GB for container; set `disk_mb` to change it.
- **Command output**: the first 64 MB of each command's stdout and stderr are recorded and the rest is dropped (`ShellResult.dropped_bytes`) while the command keeps running; each session keeps its last 512 MB of output records, and older output can no longer be fetched with `get_output`.
- **Rate limits**: the creations and calls per second each principal may make on each apiserver are set in the cluster config (administrator fills in; the defaults are 2000 creations and 10000 calls, the example production config 20000 and 100000). Batch creations are queued by the server and never fail on the rate.

## 5. Errors and retries

| `DSecError.reason` | Meaning | What to do |
|---|---|---|
| `unavailable` | A server is restarting or failing over | The SDK already retried, for up to 60 s by default (`retry_timeout`); you only see this after that |
| `no_capacity` | The cluster cannot place it right now | Retry later, or lower concurrency |
| `quota_exceeded` | Over the project's quota | Stop sandboxes you no longer use, or ask for more quota |
| `rate_limited` | Too many requests | Back off and retry |
| `unauthenticated` / `forbidden` | Token invalid or expired, or a permission missing | Check the token and the project |
| `not_found` | The sandbox does not exist or was cleaned up | — |
| `invalid` | Bad arguments | Read the message |

- Creations are safe to retry: the SDK gives each creation an idempotency key, so even if an answer is lost in a server restart, a retry returns the same sandbox.
- When the machine a sandbox runs on fails, the sandbox is lost and calls return `not_found` or `unavailable`. Take out results you need to keep in time.

## 6. Tokens

- Tokens have a lifetime (the cluster's `max_token_ttl_s`, 90 days with the quickstart; when yours expires: administrator fills in; `opendsecctl token list` shows it). Ask your administrator for a new token before then (`opendsecctl token create <principal>`). The old token is revoked once the new one works.
- If a token leaks, tell your administrator at once to revoke it (`opendsecctl token revoke`); revocation takes effect on every apiserver within 1 s.

## 7. More

- [Concepts](CONCEPTS.md): backends, states, timeouts, sessions, tasks, images, network, permissions, errors
- [Python SDK reference](PYTHON_SDK.md): every class and method
- [CLI reference](CLI.md): every `opendsecctl` command
- [Images and snapshots](IMAGES.md), [Network policy](NETWORK.md), [Projects, principals and permissions](IAM.md)
- [Troubleshooting](TROUBLESHOOTING.md)
