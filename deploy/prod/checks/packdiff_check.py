"""Release check, as a principal with layer.publish on the project: a container
pack_diff, a sandbox from the image, and a fork of it; the image is deleted after."""
import asyncio
import os
from opendsec import DSecClient, DSecContainerRunArgs

IMAGE = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")

async def main():
    c = await DSecClient(retry_timeout=60).open()
    a = DSecContainerRunArgs(container_image=IMAGE, cpu_cores_limit=1, memory_limit_mb=512, ttl_running_stop=300)
    sb = await c.run_container(a)
    try:
        await sb.run_shell("echo packed > /root/packed && ln -s /etc /root/link")
        await sb.pack_diff(f"{c.project}/relcheck:1", overwrite=True)
        a2 = DSecContainerRunArgs(container_image=f"{c.project}/relcheck:1", cpu_cores_limit=1, memory_limit_mb=512, ttl_running_stop=300)
        sb2 = await c.run_container(a2)
        r = await sb2.run_shell("cat /root/packed; readlink /root/link")
        assert r.stdout.split() == ["packed", "/etc"], r
        forks = await sb2.fork(1)
        r = await forks[0].run_shell("cat /root/packed")
        assert r.stdout.strip() == "packed", r
        for s in [sb2, *forks]:
            await s.stop()
    finally:
        await sb.stop()
        try:
            await c.delete_image(f"{c.project}/relcheck:1")
        except Exception as e:
            print("delete image:", e)
    print("PACKDIFF ok")

asyncio.run(main())
