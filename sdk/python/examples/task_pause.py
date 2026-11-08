"""Pause a whole batch of sandboxes at once and resume it: what training
does when it is preempted or waits for new weights.

Every sandbox of the batch carries the same task_id. Each runs a process
that appends the time to a file every 0.2 s. The program pauses the task
(one call) for 4 s, resumes it (one call), and checks in every sandbox that
the record has a gap of about 4 s (nothing ran while paused) and goes on
after it (the same processes continued), then stops the task.

Prerequisites: a cluster with the microvm or container backend; any image
with a shell (OPENDSEC_IMAGE, default root/py:3.12; OPENDSEC_BACKEND,
default microvm). Install and environment as in execute_code.py.

    python task_pause.py

Expected output (ids differ):

    task demo-4f2a: 4 sandboxes running
    paused 4 (failed 0); states: PAUSED x4
    resumed 4 (failed 0)
    every sandbox: a 4 s gap while paused, ticking again after it
    stopped task demo-4f2a

While paused: microVMs keep their memory (the cluster may reclaim it to
swap), containers are frozen; CPU is released either way. Resume can fail
for lack of room; the result counts such failures (failed > 0) and those
sandboxes stay paused.

Cleanup: stop_task in `finally` stops every sandbox of the task; they also
carry ttl_max (10 min) in case this program is killed. Anyone can clean up
a batch later with its task id (list_sandboxes(task_id=...), stop_task).
"""
import asyncio
import os
import uuid

from opendsec import DSecClient, DSecError, DSecRunArgs

N = 4
PAUSE = 4.0
TICK = "while :; do date +%s >> /tmp/ticks; sleep 0.2; done"


async def ticks(sb) -> list[int]:
    out = (await sb.exec(["cat", "/tmp/ticks"], timeout=30)).stdout
    return [int(x) for x in out.split()]


async def main() -> None:
    backend = os.environ.get("OPENDSEC_BACKEND", "microvm")
    image = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")
    task = "demo-" + uuid.uuid4().hex[:4]
    async with DSecClient() as client:
        try:
            sbs = await client.run_sandboxes(DSecRunArgs(backend=backend, image=image, cpu_cores_limit=0.5,
                                                         memory_limit_mb=256, task_id=task, ttl_max=600), N)
            bad = [s for s in sbs if isinstance(s, Exception)]
            if bad:
                raise bad[0]
            for sb in sbs:
                await sb.run_shell_background(TICK, session="ticker")
            print(f"task {task}: {len(sbs)} sandboxes running")
            await asyncio.sleep(1)

            r = await client.pause_task(task)
            states = [(await sb.refresh()).state for sb in sbs]
            print(f"paused {r.affected} (failed {r.failed}); states: {states[0]} x{states.count(states[0])}")
            assert r.failed == 0 and set(states) == {"PAUSED"}, (r, states)
            # Nothing is read while paused: a call into a paused sandbox would
            # resume it (transparent resume).
            await asyncio.sleep(PAUSE)
            r = await client.resume_task(task)
            print(f"resumed {r.affected} (failed {r.failed})")
            assert r.failed == 0, r
            await asyncio.sleep(1.5)
            for sb in sbs:
                t = await ticks(sb)
                i = max(range(len(t) - 1), key=lambda i: t[i + 1] - t[i])
                gap, ticks_after = t[i + 1] - t[i], len(t) - (i + 1)
                # date +%s is whole seconds: a 4 s pause shows as a 3-5 s gap.
                assert gap >= PAUSE - 1 and ticks_after >= 3, (sb.id, gap, ticks_after, t[-10:])
            print(f"every sandbox: a {PAUSE:.0f} s gap while paused, ticking again after it")
        finally:
            await client.stop_task(task)
            print(f"stopped task {task}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except DSecError as e:
        raise SystemExit(f"OpenDsec error {e.code}: {e.message}\n{e.next_steps}")
