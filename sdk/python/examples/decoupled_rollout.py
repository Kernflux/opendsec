"""Decoupled rollout with OpenDsec sandboxes (spec §22.4, the paper's RL use).

Each trajectory is an agent acting in its own sandbox: the policy (an LLM
behind an inference service) proposes an action, the sandbox executes it,
the observation goes back to the policy. Rollout and training are
decoupled: trajectories do not wait for each other (each step goes as soon
as its own inference returns), and sandboxes stay out of the way of the
GPUs:

* while a trajectory waits for inference its sandbox is paused, so it holds
  no CPU (and, with pause_reclaim or microVMs, no memory); the next command
  resumes it transparently;
* when the trainer publishes new weights, the whole rollout task is paused
  in one call (pause_task) and resumed after (resume_task);
* sandboxes end with the job (stop_task).

Run against a cluster with a container runtime, e.g.
``opendsecctl cluster up -runtime linux``::

    python examples/decoupled_rollout.py --addr ... --token ... --image host

The policy here is a stand-in (a random wait, a scripted action), so the
example measures the sandbox side only.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import time
from dataclasses import dataclass, field

from opendsec import DSecClient, DSecContainerRunArgs, Sandbox


@dataclass
class Stats:
    steps: int = 0
    pauses: int = 0
    exec_s: float = 0.0
    trajectories: list[list[str]] = field(default_factory=list)


async def policy(observation: str, step: int, think_s: float) -> str:
    """Stand-in for an inference call: latency varies per request."""
    await asyncio.sleep(random.uniform(0.5, 1.5) * think_s)
    return f"echo step {step} >> /tmp/trajectory; wc -l < /tmp/trajectory"


async def trajectory(sb: Sandbox, steps: int, think_s: float, pause: bool, stats: Stats) -> list[str]:
    obs, seen = "start", []
    for step in range(steps):
        if pause:
            await sb.pause()  # nothing to do until the policy answers
            stats.pauses += 1
        action = await policy(obs, step, think_s)
        t0 = time.monotonic()
        r = await sb.run_shell(action, timeout=60)  # resumes a paused sandbox
        stats.exec_s += time.monotonic() - t0
        if r.exit_code != 0:
            raise RuntimeError(f"{sb.id}: {r.stderr}")
        obs = r.stdout.strip()
        seen.append(obs)
        stats.steps += 1
    return seen


async def run(addr: str, token: str, project: str, image: str, backend: str, n: int, steps: int,
              think_s: float, pause: bool, task: str, mem_mb: int = 256, disk_mb: int = 0) -> Stats:
    stats = Stats()
    async with DSecClient(addr, token, project) as client:
        args = DSecContainerRunArgs(container_image=image, backend=backend, memory_limit_mb=mem_mb, disk_mb=disk_mb,
                                    cpu_cores_limit=1, ttl_running_stop=600, task_id=task)
        created = await client.run_containers(args, n)
        sandboxes = [s for s in created if isinstance(s, Sandbox)]
        if len(sandboxes) != n:
            await client.stop_task(task)
            raise RuntimeError(f"created {len(sandboxes)} of {n} sandboxes: {[e for e in created if not isinstance(e, Sandbox)]}")
        try:
            rollout = asyncio.gather(*(trajectory(sb, steps, think_s, pause, stats) for sb in sandboxes))
            # Halfway, the trainer swaps weights: freeze the rollout task.
            await asyncio.sleep(steps * think_s / 2)
            await client.pause_task(task)
            await asyncio.sleep(think_s)
            await client.resume_task(task)
            stats.trajectories = await rollout
        finally:
            await client.stop_task(task)
    return stats


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--addr", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--project", default="root")
    p.add_argument("--image", default="host")
    p.add_argument("--backend", default="container")
    p.add_argument("--trajectories", type=int, default=8)
    p.add_argument("--steps", type=int, default=5)
    p.add_argument("--think", type=float, default=0.5, help="mean inference latency, seconds")
    p.add_argument("--no-pause", action="store_true", help="keep sandboxes running while waiting")
    a = p.parse_args()
    t0 = time.monotonic()
    s = asyncio.run(run(a.addr, a.token, a.project, a.image, a.backend, a.trajectories, a.steps, a.think,
                        not a.no_pause, f"rollout-{int(t0)}"))
    took = time.monotonic() - t0
    print(f"{len(s.trajectories)} trajectories, {s.steps} steps in {took:.1f}s; "
          f"{s.pauses} pauses; sandbox exec {s.exec_s / max(s.steps, 1) * 1000:.0f} ms/step")


if __name__ == "__main__":
    main()
