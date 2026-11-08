"""Runtime API through the SDK against real container sandboxes
(`opendsecctl cluster up -runtime linux`). Skipped unless running as root."""

import asyncio
import os
import re
import shutil
import signal
import subprocess
import tempfile

import pytest

from opendsec import INVALID, DSecClient, DSecContainerRunArgs, DSecError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPENDSECCTL = os.path.join(ROOT, "bin", "opendsecctl")

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="container runtime needs root")


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


async def test_paper_example_run_shell(cluster):
    client = DSecClient(cluster["addr"], cluster["token"], "root")
    await client.open()
    args = DSecContainerRunArgs(
        container_image="host",          # P2 dev image; P3 adds real layered images
        # The paper uses 4096 MB; edges now admit against real host capacity,
        # so stay within what a small dev machine can hold.
        memory_limit_mb=256, cpu_cores_limit=4,
        ttl_running_stop=300,            # idle timeout
        network_rules={"npm": False, "pypi": True},
        init_user="root",
    )
    sandbox = await client.run_container(args, timeout=120)
    result = await sandbox.run_shell("echo hello world")
    assert result.ok and result.stdout == "hello world\n"
    await sandbox.stop()
    await client.close()


async def test_shell_files_stream_http(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        sb = await client.run_container(DSecContainerRunArgs(container_image="host", memory_limit_mb=512))

        # Persistent session state; per-command env.
        await sb.run_shell("mkdir -p /work && cd /work && export N=3")
        r = await sb.run_shell('echo "$PWD $N $EXTRA"', env={"EXTRA": "x"})
        assert r.stdout == "/work 3 x\n"
        # `exit` ends that session's shell (a fresh one starts on the next call),
        # so do it in a separate session.
        r = await sb.run_shell("exit 4", session="scratch")
        assert r.exit_code == 4 and not r.ok

        # Timeout kills the command, not the session.
        r = await sb.run_shell("sleep 30", timeout=0.3)
        assert r.timed_out

        # Files.
        await sb.write_file("/work/a.py", "print(sum(range(10)))\n")
        r = await sb.run_shell("python3 a.py > out.txt")
        assert await sb.read_file("/work/out.txt") == b"45\n"
        names = [e.name for e in await sb.list_dir("/work")]
        assert names == ["a.py", "out.txt"]
        await sb.remove("/work/out.txt")
        with pytest.raises(DSecError):
            await sb.stat("/work/out.txt")
        # Past gRPC's 4 MB default: a 20 MB file both ways, 10 MB of output.
        big = bytes(range(256)) * (20 << 12)
        await sb.write_file("/work/big", big)
        assert await sb.read_file("/work/big") == big
        assert len((await sb.run_shell("head -c 10485760 /work/big")).stdout_bytes) == 10 << 20
        await sb.remove("/work/big")

        # Streaming.
        chunks, exit_ = [], None
        async for kind, data in sb.stream_shell("for i in 1 2 3; do echo $i; sleep 0.1; done"):
            if kind == "stdout":
                chunks.append(data)
            elif kind == "exit":
                exit_ = data
        assert b"".join(chunks) == b"1\n2\n3\n" and exit_.exit_code == 0

        # Background + async output.
        cid = await sb.run_shell_background("sleep 0.2; echo bg", session="jobs")
        r = await sb.get_output(cid, session="jobs", wait=5)
        assert r.done and r.stdout == "bg\n"

        # HTTP from inside the sandbox to a server in the same sandbox.
        await sb.run_shell("cd /work && (python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &)", session="web")
        await sb.run_shell("for i in $(seq 100); do python3 -c 'import urllib.request as u; u.urlopen(\"http://127.0.0.1:8080/\", timeout=1)' 2>/dev/null && break; sleep 0.05; done")  # wait until it serves
        h = await sb.http("http://127.0.0.1:8080/a.py")
        assert h.status == 200 and h.body == b"print(sum(range(10)))\n"
        assert set(await sb.list_sessions()) >= {"default", "jobs", "web"}
        await sb.close_session("web")
        with pytest.raises(DSecError):
            await sb.http("http://127.0.0.1:8080/", timeout=2)

        # Pause, then a runtime call resumes transparently.
        await sb.pause()
        assert (await sb.run_shell("echo $N")).stdout == "3\n"
        assert (await sb.refresh()).state == "RUNNING"
        await sb.stop()


async def test_sim_has_no_runtime(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        from opendsec import DSecRunArgs
        sb = await client.run_sandbox(DSecRunArgs(backend="sim", memory_limit_mb=128))
        with pytest.raises(DSecError) as e:
            await sb.run_shell("true")
        assert e.value.reason == INVALID
        await sb.stop()


async def test_decoupled_rollout_example(cluster):
    """examples/decoupled_rollout.py end to end (spec §22.4)."""
    import importlib.util
    path = os.path.join(os.path.dirname(__file__), "..", "examples", "decoupled_rollout.py")
    spec = importlib.util.spec_from_file_location("decoupled_rollout", path)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod  # dataclasses look the module up
    spec.loader.exec_module(mod)
    stats = await mod.run(cluster["addr"], cluster["token"], "root", "host", "container",
                          n=3, steps=3, think_s=0.2, pause=True, task="rollout-test", mem_mb=64, disk_mb=64)
    assert stats.steps == 9 and stats.pauses == 9
    # Each trajectory saw its own sandbox's state grow step by step.
    assert all(t == ["1", "2", "3"] for t in stats.trajectories), stats.trajectories
    async with DSecClient(cluster["addr"], cluster["token"], "root") as c:
        assert not [s for s in await c.list_sandboxes(task_id="rollout-test") if s.state != "STOPPED"]


async def test_calls_ride_out_edge_restart(cluster):
    """A stream and a shell command in flight while the edge restarts (with a
    second of outage) complete as if nothing happened: the stream resumes
    where it broke, and the retried command is not run twice."""
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        sb = await client.run_container(DSecContainerRunArgs(container_image="host", memory_limit_mb=256))
        await sb.run_shell("true", session="other")

        async def blocking():
            return await sb.run_shell("sleep 2; echo once >> /tmp/runs; echo fg", session="other")
        fg = asyncio.create_task(blocking())
        out, exit_ = b"", None
        async for kind, data in sb.stream_shell("for i in 1 2 3 4 5 6 7 8; do echo $i; sleep 0.4; done"):
            if kind == "stdout":
                if not out:
                    cluster["proc"].send_signal(signal.SIGUSR1)
                out += data
            elif kind == "exit":
                exit_ = data
        assert out == b"".join(b"%d\n" % i for i in range(1, 9)), out
        assert exit_ is not None and exit_.ok
        r = await fg
        assert r.ok and r.stdout == "fg\n", r
        assert (await sb.read_file("/tmp/runs")) == b"once\n"
        await sb.stop()


async def test_exec_argv_and_processes(cluster):
    """exec passes each argument as it is (no shell), and times out; the
    process API streams a process's events."""
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        async with client.sandbox(DSecContainerRunArgs(container_image="host", memory_limit_mb=256)) as sb:
            tricky = "a b; echo pwned $(id) `x` '\"*"
            r = await sb.exec(["printf", "%s|", tricky, "--x"])
            assert r.ok and r.stdout == tricky + "|--x|", r.stdout
            r = await sb.exec(["sh", "-c", "exit 7"])
            assert r.exit_code == 7 and not r.ok
            r = await sb.exec(["sleep", "30"], timeout=1)
            assert r.timed_out
            r = await sb.exec(["id", "-u"], user="65534")
            assert r.stdout.strip() == "65534"
            r = await sb.exec(["pwd"], cwd="/tmp", env={"X": "1"})
            assert r.stdout.strip() == "/tmp"

            out, code = b"", None
            async for ev in sb.start_process("sh", ["-c", "echo out; echo err >&2; exit 3"]):
                if ev.stdout:
                    out += ev.stdout
                if ev.exit_code is not None:
                    code = ev.exit_code
            assert out == b"out\n" and code == 3


async def test_sandbox_scope(cluster):
    """client.sandbox stops its sandbox when the block ends, also on errors,
    and caps its life when none was asked."""
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        async with client.sandbox(DSecContainerRunArgs(container_image="host", memory_limit_mb=256)) as sb:
            assert sb.info.spec.ttl_max_s == 3600
            first = sb
        await first.refresh()
        assert first.state == "STOPPED"

        with pytest.raises(RuntimeError) as ei:
            async with client.sandbox(DSecContainerRunArgs(container_image="host", memory_limit_mb=256)) as sb:
                second = sb
                raise RuntimeError("the work failed")
        assert str(ei.value) == "the work failed"
        await second.refresh()
        assert second.state == "STOPPED"

        with pytest.raises(RuntimeError) as ei:
            async with client.sandbox(DSecContainerRunArgs(container_image="host", memory_limit_mb=256, ttl_max=120),
                                      keep_on_error=True) as sb:
                kept = sb
                raise RuntimeError("debug me")
        await kept.refresh()
        assert kept.state == "RUNNING" and kept.info.spec.ttl_max_s == 120
        if hasattr(ei.value, "__notes__"):
            assert kept.id in ei.value.__notes__[0]
        await kept.stop()


def _run_example(cluster, name: str, extra: dict | None = None) -> str:
    import sys
    path = os.path.join(os.path.dirname(__file__), "..", "examples", name)
    env = dict(os.environ, OPENDSEC_ADDR=cluster["addr"], OPENDSEC_TOKEN=cluster["token"], OPENDSEC_PROJECT="root",
               OPENDSEC_BACKEND="container", OPENDSEC_IMAGE="host", **(extra or {}))
    env.pop("OPENDSEC_CA", None)
    out = subprocess.run([sys.executable, path], env=env, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout


async def test_example_execute_code(cluster):
    out = _run_example(cluster, "execute_code.py")
    assert "exit 0" in out and "stdout: [1, 4, 9, 16, 25]" in out and "sandbox stopped" in out, out


async def test_example_task_pause(cluster):
    out = _run_example(cluster, "task_pause.py")
    assert "a 4 s gap while paused, ticking again after it" in out and "stopped task" in out, out
    task = re.search(r"task (demo-\w+):", out).group(1)
    async with DSecClient(cluster["addr"], cluster["token"], "root") as c:
        assert not [s for s in await c.list_sandboxes(task_id=task) if s.state != "STOPPED"]


@pytest.mark.skipif(not os.environ.get("OPENDSEC_EXAMPLE_MICROVM"),
                    reason="memory_fork.py needs a cluster with microVMs (KVM): set OPENDSEC_EXAMPLE_MICROVM=1 "
                           "and OPENDSEC_ADDR/TOKEN/PROJECT/IMAGE for one (docs/RELEASING.md)")
async def test_example_memory_fork():
    import sys
    path = os.path.join(os.path.dirname(__file__), "..", "examples", "memory_fork.py")
    out = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0 and "OK: memory inherited and isolated" in out.stdout, out.stdout + out.stderr
