"""OpenDsec 压测：WORKERS 个并发不停地 创建 -> 执行 -> 停止，统计成功数、失败和延迟。

    export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=root/prod OPENDSEC_CA=./ca.crt
    python load_test.py 300 16                 # 跑 300 秒，16 个并发，container 和 microvm 各一半
    python load_test.py 300 16 microvm         # 只测 microvm
每 10 秒打印一次进度，结束时打印 p50 / p99 和前 30 条失败。
"""
import asyncio
import collections
import sys
import time

from opendsec import DSecClient, DSecError, DSecRunArgs

duration = float(sys.argv[1]) if len(sys.argv) > 1 else 60
workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
backends = (sys.argv[3] if len(sys.argv) > 3 else "container,microvm").split(",")

ok = collections.Counter()
fails = []
lat = []


async def worker(i, client, backend, end):
    while time.time() < end:
        t0 = time.time()
        stage = "create"
        try:
            sb = await client.run_sandbox(DSecRunArgs(backend=backend, image="root/py:3.12",
                                                      cpu_cores_limit=1, memory_limit_mb=512), timeout=120)
            stage = "shell"
            r = await sb.run_shell("python3 -c 'print(6*7)'", timeout=60)
            if r.stdout.strip() != "42":
                raise DSecError("bad_output", repr(r.stdout))
            stage = "stop"
            await sb.stop()
            ok[backend] += 1
            lat.append(time.time() - t0)
        except Exception as e:  # noqa: BLE001 - record everything
            reason = getattr(e, "reason", type(e).__name__)
            fails.append((time.strftime("%H:%M:%S"), client.endpoint, backend, stage, reason, str(e)[:160]))
            await asyncio.sleep(0.5)  # a real client backs off


async def main():
    clients = [await DSecClient(retry_timeout=60).open()]   # OPENDSEC_ADDR: all apiservers
    end = time.time() + duration
    tasks = [worker(i, clients[i % len(clients)], backends[i % len(backends)], end) for i in range(workers)]

    async def report():
        while time.time() < end:
            await asyncio.sleep(10)
            print(f"{time.strftime('%H:%M:%S')} ok={dict(ok)} fails={len(fails)}", flush=True)

    await asyncio.gather(report(), *tasks)
    lat.sort()
    p = lambda q: lat[int(q * (len(lat) - 1))] if lat else 0  # noqa: E731
    print(f"DONE ok={dict(ok)} total={sum(ok.values())} fails={len(fails)} "
          f"p50={p(.5):.2f}s p99={p(.99):.2f}s max={p(1):.2f}s")
    for f in fails[:30]:
        print("FAIL", *f)
    for c in clients:
        await c.close()


asyncio.run(main())
