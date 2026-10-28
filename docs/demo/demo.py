import asyncio, time
from opendsec import DSecClient, DSecRunArgs

async def main():
    async with DSecClient() as client:
        t = time.perf_counter()
        sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12"))
        print(f"ready in {time.perf_counter() - t:.2f}s (whole API call: placement + boot)")
        print((await sb.run_shell("python3 -c 'print(6*7)'")).stdout.strip())
        t = time.perf_counter()
        forks = await sb.fork(count=4)    # copies with memory
        print(f"forked 4 in {time.perf_counter() - t:.2f}s")
        await asyncio.gather(*(s.stop() for s in [sb, *forks]))

asyncio.run(main())
