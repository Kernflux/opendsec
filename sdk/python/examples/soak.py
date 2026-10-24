"""OpenDsec 稳定性测试：长时间跑混合负载，每个操作记一行 CSV，供 soak_report.py 按时间段统计。

    export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=root/prod OPENDSEC_CA=./ca.crt
    python soak.py 172800 8 soak.csv           # 跑 48 小时，8 个并发

负载（并发数按比例分配，至少各 1 个）：
- cycle：创建 -> 执行命令 -> 写文件再读回 -> 停止，container 和 microvm 轮流；
- long：建一个 sandbox 保持 LONG_HOLD 秒（默认 600），每 5 秒追加一行并检查行数，然后停止；
- pause：microvm 写入标记 -> 暂停 -> 恢复 -> 读回标记 -> 停止；
- fork：microvm 写入标记 -> fork 出 2 个 -> 每个读回标记 -> 全部停止。
所有 sandbox 带同一个 task_id，结束时报告还没结束的 sandbox（泄漏）并停掉它们。

CSV 列：time（操作开始的 unix 时间）、kind、backend、op、ok（1/0）、seconds、reason。
op 为 cycle 的行代表一个完整循环；其余行是其中的单个操作。
"""
import asyncio
import csv
import os
import random
import sys
import time

from opendsec import DSecClient, DSecError, DSecRunArgs

duration = float(sys.argv[1]) if len(sys.argv) > 1 else 3600
workers = int(sys.argv[2]) if len(sys.argv) > 2 else 8
out_path = sys.argv[3] if len(sys.argv) > 3 else "soak.csv"
long_hold = float(os.environ.get("LONG_HOLD", "600"))
task_id = os.environ.get("SOAK_TASK", f"soak-{int(time.time())}")

out = open(out_path, "a", newline="", buffering=1)
log = csv.writer(out)
if out.tell() == 0:
    log.writerow(["time", "kind", "backend", "op", "ok", "seconds", "reason"])
counts = {"ok": 0, "fail": 0}


def args(backend):
    return DSecRunArgs(backend=backend, image="root/py:3.12", cpu_cores_limit=1, memory_limit_mb=512,
                       task_id=task_id, ttl_running_stop=3600)


class Cycle:
    """Times each operation of one cycle; a failure ends the cycle."""

    def __init__(self, kind, backend):
        self.kind, self.backend, self.t0 = kind, backend, time.time()
        self.sandboxes = []

    async def op(self, name, coro):
        t = time.time()
        try:
            r = await coro
        except Exception as e:  # noqa: BLE001 - record everything
            log.writerow([f"{t:.3f}", self.kind, self.backend, name, 0, f"{time.time() - t:.3f}", reason(e)])
            raise
        log.writerow([f"{t:.3f}", self.kind, self.backend, name, 1, f"{time.time() - t:.3f}", ""])
        return r

    async def create(self):
        sb = await self.op("create", client.run_sandbox(args(self.backend), timeout=120))
        self.sandboxes.append(sb)
        return sb

    async def check(self, name, sb, cmd, want):
        r = await self.op(name, sb.run_shell(cmd, timeout=60))
        if r.stdout.strip() != want:
            raise DSecError("bad_output", f"{name}: {r.stdout[:80]!r} want {want!r}")

    async def run(self, body):
        try:
            await body(self)
            for sb in self.sandboxes:
                await self.op("stop", sb.stop())
            ok, why = 1, ""
        except Exception as e:  # noqa: BLE001
            ok, why = 0, reason(e)
            for sb in self.sandboxes:  # best effort: leave nothing running
                try:
                    await sb.stop()
                except Exception:  # noqa: BLE001
                    pass
        log.writerow([f"{self.t0:.3f}", self.kind, self.backend, "cycle", ok, f"{time.time() - self.t0:.3f}", why])
        counts["ok" if ok else "fail"] += 1
        if not ok:
            await asyncio.sleep(0.5)  # a real client backs off


def reason(e):
    return f"{getattr(e, 'reason', type(e).__name__)}: {str(e)[:120]}".replace("\n", " ")


async def cycle_body(c):
    sb = await c.create()
    await c.check("shell", sb, "python3 -c 'print(6*7)'", "42")
    data = os.urandom(64 * 1024)
    await c.op("write", sb.write_file("/tmp/blob", data))
    if await c.op("read", sb.read_file("/tmp/blob")) != data:
        raise DSecError("bad_output", "read back different bytes")


async def long_body(c):
    sb = await c.create()
    end, n = time.time() + long_hold * random.uniform(0.5, 1.5), 0
    while time.time() < end and time.time() < stop_at:
        n += 1
        await c.check("exec", sb, f"echo {n} >> /tmp/n && wc -l < /tmp/n", str(n))
        await asyncio.sleep(5)


async def pause_body(c):
    sb = await c.create()
    mark = os.urandom(8).hex()
    await c.check("shell", sb, f"echo {mark} > /root/mark && cat /root/mark", mark)
    await c.op("pause", sb.pause())
    await asyncio.sleep(random.uniform(1, 10))
    await c.op("resume", sb.resume())
    await c.check("check", sb, "cat /root/mark", mark)


async def fork_body(c):
    sb = await c.create()
    mark = os.urandom(8).hex()
    await c.check("shell", sb, f"echo {mark} > /root/mark && cat /root/mark", mark)
    copies = await c.op("fork", sb.fork(2))
    c.sandboxes += [x for x in copies if not isinstance(x, DSecError)]
    for x in copies:
        if isinstance(x, DSecError):
            raise x
        await c.check("check", x, "cat /root/mark", mark)


async def worker(kind, i):
    body = {"cycle": cycle_body, "long": long_body, "pause": pause_body, "fork": fork_body}[kind]
    n = 0
    while time.time() < stop_at:
        backend = ("container", "microvm")[(i + n) % 2] if kind in ("cycle", "long") else "microvm"
        n += 1
        await Cycle(kind, backend).run(body)


def plan(n):
    """cycle about half, long about a quarter, one pause and one fork worker."""
    kinds = ["pause", "fork"]
    rest = max(n - 2, 2)
    kinds += ["long"] * max(rest // 3, 1)
    kinds += ["cycle"] * (rest - max(rest // 3, 1))
    return kinds


async def main():
    global client, stop_at
    client = await DSecClient(retry_timeout=60).open()
    stop_at = time.time() + duration
    kinds = plan(workers)
    print(f"task {task_id}: workers {kinds}", flush=True)

    async def report():
        while time.time() < stop_at:
            await asyncio.sleep(60)
            print(f"{time.strftime('%F %T')} cycles ok={counts['ok']} fail={counts['fail']}", flush=True)

    await asyncio.gather(report(), *(worker(k, i) for i, k in enumerate(kinds)))
    left = await client.list_sandboxes(task_id=task_id)  # only those not ended
    if left:
        await client.stop_task(task_id)
    print(f"DONE cycles ok={counts['ok']} fail={counts['fail']} left_running={len(left)}", flush=True)
    await client.close()


asyncio.run(main())
