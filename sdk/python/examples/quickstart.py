"""OpenDsec quickstart: create a sandbox, run code in it, stop it.

    pip install opendsec            # or the wheel your cluster admin gave you
    export OPENDSEC_ADDR=<apiserver addresses>  OPENDSEC_TOKEN=<your token>
    export OPENDSEC_PROJECT=<your project>  OPENDSEC_CA=./ca.crt
    python quickstart.py

On a single-node cluster made by deploy/quickstart.sh: . /root/opendsec-ops/demo.env
"""
import asyncio

from opendsec import DSecClient, DSecError, DSecRunArgs


async def main():
    async with DSecClient() as client:
        sb = await client.run_sandbox(DSecRunArgs(
            backend="microvm",            # or "container"
            image="root/py:3.12",
            cpu_cores_limit=1, memory_limit_mb=1024,
            ttl_running_stop=600,         # stop after 10 min idle
            network_rules={"pypi": True}, # outbound traffic is denied unless a rule allows it
        ))
        print("sandbox", sb.id, sb.state)
        try:
            r = await sb.run_shell("python3 -c 'import sys; print(sys.version)'")
            print(r.stdout.strip())
            await sb.write_file("/tmp/hello.py", "print('hello from', __import__('platform').node())\n")
            print((await sb.run_shell("python3 /tmp/hello.py")).stdout.strip())
            r = await sb.run_shell("pip install -q requests && python3 -c 'import requests; print(requests.get(\"https://pypi.org/simple/\").status_code)'",
                                   timeout=120)
            print("internet:", r.stdout.strip() or r.stderr.strip()[-200:])
        finally:
            await sb.stop()
        print("stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except DSecError as e:
        raise SystemExit(f"OpenDsec error {e.reason}: {e}")
