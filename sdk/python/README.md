# opendsec: Python SDK for OpenDsec

Async client for [OpenDsec](https://github.com/kernflux/opendsec) sandboxes: create microVM or container sandboxes, run commands, read and write files, pause, fork and snapshot them.

```sh
pip install ./sdk/python      # from a clone; Python 3.10+
export OPENDSEC_ADDR=10.0.0.11:7100 OPENDSEC_TOKEN=dsk.... OPENDSEC_PROJECT=root/demo OPENDSEC_CA=ca.crt
```

```python
import asyncio
from opendsec import DSecClient, DSecRunArgs

async def main():
    async with DSecClient() as client:
        sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12"))
        try:
            print((await sb.run_shell("python3 -c 'print(6*7)'")).stdout)
        finally:
            await sb.stop()

asyncio.run(main())
```

## Images

```python
from opendsec import Template

t = (Template()
     .from_registry("python:3.12-slim")      # or .from_image("root/py:3.12")
     .apt_install(["git"])
     .pip_install(["pandas"])
     .copy("./app", "/app")
     .env({"MODE": "prod"})
     .workdir("/app"))
info = await t.build(client, "root/me/myenv:v1")
```

The cluster builds it: a sandbox from the base runs the steps and is saved
(files with pack_diff; with `start_cmd(...)`, its running processes too, as a
microVM memory snapshot). Also `client.import_image(name, ref)` (a registry's
image as it is), `sandbox.pack_diff(name)` and
`sandbox.create_snapshot(name, memory=True)`.

See `examples/` and the project's `docs/USER_GUIDE.md`.
