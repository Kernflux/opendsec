"""Build the image of the E2B gateway's code-interpreter template (SPEC §37.8).

The image is a memory snapshot of a microVM already running E2B's
code-interpreter server (port 49999) and a Python Jupyter kernel, so a
sandbox made from it serves run_code at once (no start command).

E2B's server and configuration come from its code-interpreter repository
(Apache-2.0): download it first and pass its template/ directory:

    curl -fsSL https://codeload.github.com/e2b-dev/code-interpreter/tar.gz/refs/heads/main | tar -xz
    OPENDSEC_ADDR=... OPENDSEC_TOKEN=<token with layer.publish> OPENDSEC_CA=... \\
        python build-code-interpreter.py code-interpreter-main/template [image] [base image]

Then add the template to the cluster config's e2b section, with the
snapshot's VM size:

    "code-interpreter-v1": {"image": "root/code-interpreter:v1", "backend": "microvm", "cpu": 2, "memory_mb": 2048}

Only the Python kernel is installed: the server is patched to start
without its default JavaScript context. Sandbox-level envVars do not reach
run_code (the server asks envd for them, which OpenDsec sandboxes lack; a
stub answers {}); run_code(envs=...) works.
"""
import asyncio
import sys
import time
from pathlib import Path

from opendsec.client import DSecClient, DSecRunArgs

SRC = Path(sys.argv[1])
IMAGE = sys.argv[2] if len(sys.argv) > 2 else "root/code-interpreter:v1"
BASE = sys.argv[3] if len(sys.argv) > 3 else "root/py:3.12"
VCPUS, MEMORY_MB = 2, 2048  # the template's cpu and memory_mb must match

FILES = {**{f"/root/.server/{p.relative_to(SRC / 'server')}": p for p in (SRC / "server").rglob("*") if p.is_file()},
         "/root/.config/matplotlib/.matplotlibrc": SRC / "matplotlibrc",
         "/root/.jupyter/jupyter_server_config.py": SRC / "jupyter_server_config.py",
         "/root/.jupyter/jupyter-healthcheck.sh": SRC / "jupyter-healthcheck.sh",
         "/root/.jupyter/start-up.sh": SRC / "start-up.sh",
         "/root/.ipython/profile_default/ipython_kernel_config.py": SRC / "ipython_kernel_config.py",
         **{f"/root/.ipython/profile_default/startup/{p.name}": p for p in (SRC / "startup_scripts").iterdir()}}

# The server asks envd (port 49983) for the sandbox's env vars; OpenDsec
# sandboxes have no envd.
ENVD_STUB = b"""import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 49983), H).serve_forever()
"""

# Python kernel only: the server must start without its default JavaScript
# context.
OLD = """        javascript_context = await create_context(
            client, websockets, "javascript", "/home/user"
        )
        default_websockets["javascript"] = javascript_context.id
"""
NEW = """        try:  # OpenDsec: Python kernel only
            javascript_context = await create_context(
                client, websockets, "javascript", "/home/user"
            )
            default_websockets["javascript"] = javascript_context.id
        except Exception as e:
            logger.warning(f"no JavaScript context: {e}")
"""

PACKAGES = "jupyter-server==2.20.0 ipykernel==6.31.0 ipython orjson pandas matplotlib numpy e2b_charts requests"


async def sh(sb, cmd, timeout=1800):
    t = time.time()
    r = await sb.run_shell(cmd, timeout=timeout)
    print(f"[{time.time() - t:6.1f}s] exit {r.exit_code}: {cmd[:90]}", flush=True)
    if r.exit_code != 0:
        print(r.stdout[-2000:], r.stderr[-3000:])
        raise SystemExit(1)
    return r


async def main():
    async with DSecClient() as c:
        sb = await c.run_sandbox(DSecRunArgs(backend="microvm", image=BASE, cpu_cores_limit=VCPUS,
                                             memory_limit_mb=MEMORY_MB, disk_mb=8192, ttl_max=7200,
                                             network_rules={"*": True}),  # apt and pip, whatever the cluster's default
                                 timeout=300)
        print("building in sandbox", sb.id, flush=True)
        try:
            await sh(sb, "mkdir -p /root/.server /root/.jupyter /root/.config/matplotlib "
                         "/root/.ipython/profile_default/startup /home/user /run/e2b-jupyter")
            for dst, src in FILES.items():
                data = src.read_bytes()
                if dst == "/root/.server/main.py":
                    s = data.decode()
                    assert s.count(OLD) == 1, "main.py changed upstream: update the patch"
                    data = s.replace(OLD, NEW).encode()
                await sb.write_file(dst, data)
            await sb.write_file("/root/.jupyter/envd-stub.py", ENVD_STUB)
            await sh(sb, "chmod +x /root/.jupyter/*.sh")
            await sh(sb, "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                         "--no-install-recommends curl >/dev/null && rm -rf /var/lib/apt/lists/*")
            await sh(sb, f"pip install -q --no-cache-dir --root-user-action=ignore {PACKAGES}")
            await sh(sb, "ipython kernel install --name python3 --user")
            await sh(sb, "python3 -m venv /root/.server/.venv && "
                         "/root/.server/.venv/bin/pip install -q --no-cache-dir -r /root/.server/requirements.txt")
            await sb.run_shell_background("python3 /root/.jupyter/envd-stub.py", session="envd-stub")
            await sb.run_shell_background("cd /root && /root/.jupyter/start-up.sh > /tmp/code-interpreter.log 2>&1",
                                          session="code-interpreter")
            for _ in range(120):
                r = await sb.run_shell("curl -s -o /dev/null -w %{http_code} http://localhost:49999/health")
                if r.stdout.strip() == "200":
                    break
                await asyncio.sleep(1)
            else:
                print((await sb.run_shell("tail -30 /tmp/code-interpreter.log")).stdout)
                raise SystemExit("the code interpreter server did not become healthy")
            r = await sh(sb, """curl -s -X POST localhost:49999/execute -H content-type:application/json -d '{"code":"6*7"}'""")
            assert '"42"' in r.stdout, r.stdout
            img = await sb.create_snapshot(IMAGE, memory=True, overwrite=True)
            print(f"image {img.name}: {len(img.layers)} layers, memory snapshot {img.snapshot}")
        finally:
            await sb.stop()


asyncio.run(main())
