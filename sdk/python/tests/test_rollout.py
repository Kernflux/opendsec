"""Rollouts (opendsec.rollout, python -m opendsec rollout) against real
container sandboxes (`opendsecctl cluster up -runtime linux`, image "host").
Skipped unless running as root."""

import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest

from opendsec import DSecClient, DSecContainerRunArgs, inputs_from_count

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPENDSECCTL = os.path.join(ROOT, "bin", "opendsecctl")

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="container runtime needs root")

# The command of the tests: what it does depends on the payload's mode.
SCRIPT = r"""
import json, os, sys, time
p = json.load(open(os.environ["OPENDSEC_INPUT_PATH"]))
m = p["mode"]
print("input", os.environ["OPENDSEC_INPUT_ID"], m)
if m == "ok":
    json.dump({"reward": p.get("x", 0) * 2}, open("/tmp/result.json", "w"))
elif m == "fail":
    print("boom", file=sys.stderr); sys.exit(3)
elif m == "sleep":
    time.sleep(p.get("s", 60))
elif m == "badjson":
    open("/tmp/result.json", "w").write("{not json")
elif m == "big":
    open("/tmp/result.json", "w").write("[" + "1," * 200000 + "1]")
elif m == "loud":
    sys.stdout.write("x" * 100000)
    json.dump({}, open("/tmp/result.json", "w"))
"""
CMD = ["python3", "-c", SCRIPT]


def args(**kw) -> DSecContainerRunArgs:
    return DSecContainerRunArgs(container_image="host", memory_limit_mb=128, cpu_cores_limit=0.25, **kw)


@pytest.fixture(scope="module")
def cluster():
    state = tempfile.mkdtemp(prefix="opendsec")
    proc = subprocess.Popen([OPENDSECCTL, "cluster", "up", "-sim-edges", "2", "-runtime", "linux",
                             "-state-dir", state, "-disk-reserve-mb", "64", "-log", "warn"], stdout=subprocess.PIPE, text=True)
    env = None
    for line in proc.stdout:
        m = re.search(r"OPENDSEC_ADDR=(\S+) OPENDSEC_TOKEN=(\S+)", line)
        if m:
            env = {"addr": m.group(1), "token": m.group(2), "proc": proc}
            break
    assert env, "cluster did not start"
    yield env
    proc.terminate()
    proc.wait(30)
    shutil.rmtree(state, ignore_errors=True)


def client(cluster) -> DSecClient:
    return DSecClient(cluster["addr"], cluster["token"], "root")


async def left_running(c: DSecClient, run_id: str) -> list[str]:
    return [s.id for s in await c.list_sandboxes(task_id=run_id) if s.state not in ("STOPPED", "FAILED")]


async def test_command_results_and_concurrency(cluster, tmp_path):
    modes = ["ok"] * 12 + ["fail", "sleep", "badjson", "big", "loud", "noresult"]
    inputs = [{"id": f"in-{i}", "payload": {"mode": m, "x": i, "s": 30}} for i, m in enumerate(modes)]
    peak = 0

    def seen(p):
        nonlocal peak
        peak = max(peak, p.active)

    async with client(cluster) as c:
        run = await c.rollouts.start(args(), inputs, command=CMD, concurrency=4, execution_timeout_s=3,
                                     run_timeout_s=300, result_path="/tmp/result.json", on_progress=seen,
                                     max_result_bytes=100_000, tail_bytes=1000)
        summary = await run.wait()
        by = {r.input_id: r for r in summary.results}
        assert peak <= 4, peak
        assert [r.input_index for r in summary.results] == list(range(len(inputs)))
        for i, m in enumerate(modes):
            r = by[f"in-{i}"]
            want = {"ok": "succeeded", "fail": "failed", "sleep": "timed_out", "badjson": "result_error",
                    "big": "result_error", "loud": "succeeded", "noresult": "result_error"}[m]
            assert r.status == want, (m, r)
            assert r.cleanup_status == "succeeded" and r.sandbox_id, r
        assert by["in-0"].result == {"reward": 0} and by["in-3"].result == {"reward": 6}
        assert by["in-0"].stdout_tail.startswith("input in-0 ok")
        assert by["in-12"].exit_code == 3 and "boom" in by["in-12"].stderr_tail
        assert by["in-16"].output_truncated and len(by["in-16"].stdout_tail) == 1000
        assert "over 100000" in by["in-15"].error["message"]
        assert summary.counts["succeeded"] == 13 and not summary.ok and not summary.leftover
        assert not await left_running(c, run.run_id)

        out = tmp_path / "results.jsonl"
        run.export_jsonl(str(out))
        lines = [json.loads(l) for l in out.read_text().splitlines()]
        assert lines[0]["type"] == "run" and lines[0]["run_id"] == run.run_id and lines[0]["inputs"] == len(inputs)
        assert len(lines) == len(inputs) + 1 and all(l["type"] == "result" for l in lines[1:])
        assert "payload" not in out.read_text()
        with pytest.raises(FileExistsError):
            run.export_jsonl(str(out))


async def test_episode_mode(cluster):
    async def episode(sb, payload):
        total = 0
        for step in range(payload["steps"]):
            r = await sb.exec(["sh", "-c", f"echo $(( {payload['seed']} + {step} ))"])
            total += int(r.stdout)
        if payload["seed"] == 99:
            raise RuntimeError("the policy gave up")
        return {"total": total}

    async with client(cluster) as c:
        summary = await c.rollouts.run(args(), [{"id": str(s), "payload": {"seed": s, "steps": 3}} for s in (1, 2, 99)],
                                       episode=episode, concurrency=3)
        by = {r.input_id: r for r in summary.results}
        assert by["1"].result == {"total": 6} and by["2"].result == {"total": 9}
        assert by["99"].status == "failed" and "gave up" in by["99"].error["message"]


async def test_waits_for_quota(cluster):
    """Concurrency above the project's quota: inputs wait for room, none fail."""
    async with client(cluster) as c:
        try:
            await c.create_project("root", "q2", {"sandboxes": 2})
        except Exception:
            pass
        summary = await c.rollouts.run(args(project="root/q2"), inputs_from_count(6, {"mode": "ok", "x": 1}),
                                       command=CMD, concurrency=6, run_timeout_s=120)
        assert summary.counts["succeeded"] == 6, summary


async def test_misconfigured_stops_early(cluster):
    async with client(cluster) as c:
        t0 = time.monotonic()
        summary = await c.rollouts.run(DSecContainerRunArgs(container_image="root/no-such:1", memory_limit_mb=128),
                                       inputs_from_count(20, {"mode": "ok"}), command=CMD, concurrency=2)
        assert time.monotonic() - t0 < 30
        assert summary.counts["succeeded"] == 0
        assert summary.counts["create_failed"] >= 1
        assert summary.counts["create_failed"] + summary.counts["cancelled"] == 20
        r = summary.results[0]
        assert r.error["code"] in ("not_found", "invalid") and r.error["next_steps"]


async def test_cancel_and_budget(cluster):
    async with client(cluster) as c:
        run = await c.rollouts.start(args(), inputs_from_count(10, {"mode": "sleep", "s": 120}), command=CMD,
                                     concurrency=3, run_timeout_s=600)
        while run.progress().counts.get("running", 0) < 3:
            await asyncio.sleep(0.2)
        summary = await run.cancel()
        assert summary.counts["cancelled"] == 10, summary.counts
        assert not summary.leftover and not await left_running(c, run.run_id)
        assert sum(1 for r in summary.results if r.sandbox_id) == 3  # nothing dispatched after the cancel

        # The run's budget: what runs past it is timed out, the rest never starts.
        t0 = time.monotonic()
        summary = await c.rollouts.run(args(), inputs_from_count(6, {"mode": "sleep", "s": 120}), command=CMD,
                                       concurrency=2, run_timeout_s=6)
        assert time.monotonic() - t0 < 60
        assert summary.counts["timed_out"] == 2 and summary.counts["cancelled"] == 4, summary.counts
        assert not summary.leftover


def cli(cluster, *argv, timeout=180):
    env = dict(os.environ, OPENDSEC_ADDR=cluster["addr"], OPENDSEC_TOKEN=cluster["token"], OPENDSEC_PROJECT="root")
    env.pop("OPENDSEC_CA", None)
    return subprocess.run([sys.executable, "-m", "opendsec", "rollout", *argv], env=env, capture_output=True,
                          text=True, timeout=timeout)


def test_cli_run_rerun_cleanup(cluster, tmp_path):
    inputs = tmp_path / "inputs.jsonl"
    inputs.write_text("".join(json.dumps({"id": f"i{n}", "payload": {"mode": m, "x": n}}) + "\n"
                              for n, m in enumerate(["ok", "fail", "ok", "fail"])))
    common = ["--image", "host", "--backend", "container", "--cpu", "0.25", "--memory-mb", "128",
              "--inputs", str(inputs), "--result-path", "/tmp/result.json", "--progress", "plain"]
    out1 = tmp_path / "r1.jsonl"
    p = cli(cluster, "run", *common, "--output", str(out1), "--", *CMD)
    assert p.returncode == 1, p.stderr
    assert "\033" not in p.stderr and "failed 2" in p.stderr, p.stderr
    rows = [json.loads(l) for l in out1.read_text().splitlines()]
    assert [r["status"] for r in rows[1:]] == ["succeeded", "failed", "succeeded", "failed"]
    assert cli(cluster, "run", *common, "--output", str(out1), "--", *CMD).returncode == 2  # no overwrite

    # Rerun only the failed ones, with a command that now succeeds.
    out2 = tmp_path / "r2.jsonl"
    p = cli(cluster, "rerun", "--inputs", str(inputs), "--results", str(out1), "--output", str(out2),
            "--image", "host", "--backend", "container", "--progress", "none",
            "--", "sh", "-c", "echo '{}' > /tmp/result.json")
    assert p.returncode == 0, p.stderr
    rows2 = [json.loads(l) for l in out2.read_text().splitlines()]
    assert rows2[0]["source_run_id"] == rows[0]["run_id"] and rows2[0]["attempt"] == 2
    assert sorted(r["input_id"] for r in rows2[1:]) == ["i1", "i3"]
    assert all(r["status"] == "succeeded" and r["attempt"] == 2 for r in rows2[1:])

    # A client killed mid-run: cleanup by run id stops what it left.
    env = dict(os.environ, OPENDSEC_ADDR=cluster["addr"], OPENDSEC_TOKEN=cluster["token"], OPENDSEC_PROJECT="root")
    env.pop("OPENDSEC_CA", None)
    slow = tmp_path / "slow.jsonl"
    slow.write_text("".join(json.dumps({"id": str(n), "payload": {"mode": "sleep", "s": 300}}) + "\n" for n in range(6)))
    proc = subprocess.Popen([sys.executable, "-m", "opendsec", "rollout", "run", "--image", "host", "--backend",
                             "container", "--cpu", "0.25", "--memory-mb", "128", "--inputs", str(slow),
                             "--output", str(tmp_path / "r3.jsonl"), "--run-id", "r-killed-1", "--progress", "none",
                             "--concurrency", "3", "--", *CMD], env=env)

    async def running():
        async with client(cluster) as c:
            for _ in range(100):
                if len(await left_running(c, "r-killed-1")) == 3:
                    return True
                await asyncio.sleep(0.2)
    assert asyncio.run(running())
    proc.send_signal(signal.SIGKILL)
    proc.wait()

    async def still():
        async with client(cluster) as c:
            return await left_running(c, "r-killed-1")
    assert len(asyncio.run(still())) == 3  # the client died; its sandboxes did not
    p = cli(cluster, "cleanup", "r-killed-1")
    assert p.returncode == 0 and "nothing left running" in p.stderr, p.stderr
    assert not asyncio.run(still())


def test_cli_interrupt_cleans_up(cluster, tmp_path):
    """Ctrl-C (SIGINT) cancels the run, stops its sandboxes, writes what is known."""
    env = dict(os.environ, OPENDSEC_ADDR=cluster["addr"], OPENDSEC_TOKEN=cluster["token"], OPENDSEC_PROJECT="root")
    env.pop("OPENDSEC_CA", None)
    inputs = tmp_path / "in.jsonl"
    inputs.write_text("".join(json.dumps({"id": str(n), "payload": {"mode": "sleep", "s": 300}}) + "\n" for n in range(4)))
    out = tmp_path / "out.jsonl"
    proc = subprocess.Popen([sys.executable, "-m", "opendsec", "rollout", "run", "--image", "host", "--backend",
                             "container", "--cpu", "0.25", "--memory-mb", "128", "--inputs", str(inputs),
                             "--output", str(out), "--run-id", "r-int-1", "--progress", "none", "--concurrency", "2",
                             "--", *CMD], env=env, stderr=subprocess.PIPE, text=True)

    async def running():
        async with client(cluster) as c:
            for _ in range(100):
                if len(await left_running(c, "r-int-1")) == 2:
                    return True
                await asyncio.sleep(0.2)
    assert asyncio.run(running())
    proc.send_signal(signal.SIGINT)
    _, err = proc.communicate(timeout=120)
    assert proc.returncode == 130, err
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    assert all(r["status"] == "cancelled" for r in rows[1:]), rows

    async def still():
        async with client(cluster) as c:
            return await left_running(c, "r-int-1")
    assert not asyncio.run(still())


@pytest.mark.skipif(not os.environ.get("OPENDSEC_ROLLOUT_SCALE"), reason="set OPENDSEC_ROLLOUT_SCALE=1 (100 inputs, ~1 min)")
async def test_scale_acceptance(cluster):
    """The spec's acceptance (§6.7): 100 inputs at concurrency 10 with mixed
    outcomes; 100 episodes of 20 steps."""
    modes = (["ok"] * 7 + ["fail", "badjson", "sleep"]) * 10
    inputs = [{"id": f"s{i}", "payload": {"mode": m, "x": i, "s": 30}} for i, m in enumerate(modes)]
    peak = 0

    def seen(p):
        nonlocal peak
        peak = max(peak, p.active)

    async with client(cluster) as c:
        summary = await c.rollouts.run(args(), inputs, command=CMD, concurrency=10, execution_timeout_s=2,
                                       result_path="/tmp/result.json", on_progress=seen)
        assert peak <= 10, peak
        assert summary.counts["succeeded"] == 70 and summary.counts["failed"] == 10
        assert summary.counts["result_error"] == 10 and summary.counts["timed_out"] == 10
        assert not summary.leftover and all(r.cleanup_status == "succeeded" for r in summary.results)
        print("\n", summary)

        async def episode(sb, payload):
            n = 0
            for _ in range(20):
                n = int((await sb.exec(["sh", "-c", f"echo $(( {n} + 1 ))"])).stdout)
            return n

        summary = await c.rollouts.run(args(), inputs_from_count(100), episode=episode, concurrency=10)
        assert summary.counts["succeeded"] == 100 and all(r.result == 20 for r in summary.results), summary
        assert not summary.leftover
        print(summary)


async def test_rides_out_edge_restart(cluster):
    """The edges restart mid-run (SIGUSR1 to the test cluster): commands in
    flight finish once each (not run twice), every input succeeds, nothing
    is left."""
    script = ("import json,os,time; time.sleep(1.5); "
              "open('/tmp/runs','a').write('x'); json.dump({'runs': len(open('/tmp/runs').read())}, open('/tmp/result.json','w'))")
    async with client(cluster) as c:
        run = await c.rollouts.start(args(), inputs_from_count(12), command=["python3", "-c", script], concurrency=6,
                                     result_path="/tmp/result.json")
        while run.progress().counts.get("running", 0) < 6:
            await asyncio.sleep(0.1)
        cluster["proc"].send_signal(signal.SIGUSR1)
        summary = await run.wait()
        assert summary.counts["succeeded"] == 12, [(r.status, r.error) for r in summary.results]
        assert all(r.result == {"runs": 1} for r in summary.results)  # each command ran once
        assert not summary.leftover
