"""SDK tests against a real in-process cluster started by `opendsecctl cluster up`."""

import asyncio
import os
import re
import subprocess

import pytest

from opendsec import (FORBIDDEN, INVALID, QUOTA_EXCEEDED, UNAUTHENTICATED, DSecClient,
                     DSecContainerRunArgs, DSecError, DSecRunArgs, Sandbox)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPENDSECCTL = os.path.join(ROOT, "bin", "opendsecctl")


@pytest.fixture(scope="module")
def cluster():
    proc = subprocess.Popen([OPENDSECCTL, "cluster", "up", "-sim-edges", "4", "-log", "warn"],
                            stdout=subprocess.PIPE, text=True)
    env = None
    for line in proc.stdout:
        m = re.search(r"OPENDSEC_ADDR=(\S+) OPENDSEC_TOKEN=(\S+)", line)
        if m:
            env = {"addr": m.group(1), "token": m.group(2)}
            break
    assert env, "cluster did not start"
    yield env
    proc.terminate()
    proc.wait(10)


async def test_paper_example(cluster):
    client = DSecClient(cluster["addr"], cluster["token"], "root")
    await client.open()
    args = DSecContainerRunArgs(
        container_image="registry.example/sphinx-9658:official",
        memory_limit_mb=4096, cpu_cores_limit=4,
        ttl_running_stop=300,  # idle timeout
        network_rules={"npm": False, "pypi": True},
        init_user="root",
    )
    sandbox = await client.run_container(args, timeout=120)
    assert sandbox.state == "RUNNING"
    assert sandbox.id.startswith(sandbox.edge_id + ".")
    assert sandbox.info.spec.image == "registry.example/sphinx-9658:official"
    await sandbox.pause()
    assert sandbox.state == "PAUSED"
    await sandbox.touch()  # transparent resume
    assert sandbox.state == "RUNNING"
    await sandbox.stop()
    assert sandbox.state == "STOPPED"
    await client.close()


async def test_batch_tasks_and_iam(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root") as admin:
        await admin.create_project("root", "rl", {"sandboxes": 50})
        tok = await admin.create_principal("root/rl", "harness", "service")
        await admin.grant("root/rl", "harness", ["sandbox.create", "sandbox.operate"])

    async with DSecClient(cluster["addr"], tok, "root/rl") as h:
        assert await h.whoami() == "harness"
        args = DSecContainerRunArgs(container_image="img", task_id="job-1", memory_limit_mb=512)
        res = await h.run_containers(args, 40)
        assert all(not isinstance(r, DSecError) for r in res), res
        assert len({r.edge_id for r in res}) == 4

        # Quota: 50 sandboxes in root/rl.
        more = await h.run_containers(args, 20)
        errs = [r for r in more if isinstance(r, DSecError)]
        assert len(errs) == 10 and all(e.reason == QUOTA_EXCEEDED for e in errs)

        r = await h.pause_task("job-1")
        assert r.affected == 60 - 10 and r.failed == 0
        r = await h.stop_task("job-1")
        assert r.affected == 50
        assert await h.list_sandboxes(task_id="job-1") == []

        with pytest.raises(DSecError) as e:
            await h.create_project("root", "nope")
        assert e.value.reason == FORBIDDEN

    async with DSecClient(cluster["addr"], "dsk.harness.bad", "root/rl") as bad:
        with pytest.raises(DSecError) as e:
            await bad.run_container(DSecContainerRunArgs(container_image="img"))
        assert e.value.reason == UNAUTHENTICATED


async def test_fork(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        src = await client.run_sandbox(DSecRunArgs(backend="sim", memory_limit_mb=512, disk_mb=100,
                                                   task_id="fork-job", labels={"role": "src"}))
        spec = src.info.spec
        assert spec.resources.disk_mb == 100
        assert spec.ttl_running_stop_s == 3600 and spec.ttl_max_s == 86400  # cluster defaults
        forks = await src.fork(count=3, ttl_max=600, labels={"step": "1"})
        assert len(forks) == 3 and all(isinstance(f, Sandbox) for f in forks), forks
        snaps = {f.info.spec.snapshot for f in forks}
        assert len(snaps) == 1 and snaps != {""}
        for f in forks:
            s = f.info.spec
            assert f.edge_id == src.edge_id  # copies stay next to their snapshot
            assert s.ttl_max_s == 600 and s.task_id == "fork-job" and s.resources.disk_mb == 100
            assert dict(s.labels) == {"role": "src", "step": "1"}
        await src.refresh()
        assert src.state == "RUNNING"
        with pytest.raises(DSecError) as e:
            await src.fork(count=0)
        assert e.value.reason == INVALID
        await client.stop_task("fork-job")


async def test_create_retry_is_idempotent(cluster):
    """A retried create (spec §27.5) returns the sandbox its first attempt made."""
    from opendsec._pb.opendsec.v1 import opendsec_pb2, types_pb2
    from opendsec.client import _call, _new_lease

    client = DSecClient(cluster["addr"], cluster["token"], "root")
    await client.open()
    stub = client._need()
    spec = DSecRunArgs(memory_limit_mb=64).to_spec()
    lease = _new_lease()
    first = await stub.CreateSandbox(opendsec_pb2.CreateSandboxRequest(project="root", spec=spec, lease=lease))
    again = await stub.CreateSandbox(opendsec_pb2.CreateSandboxRequest(project="root", spec=spec, lease=lease, retry=True))
    assert again.id == first.id
    # A retry whose first attempt never arrived creates the sandbox.
    fresh = _new_lease()
    made = await stub.CreateSandbox(opendsec_pb2.CreateSandboxRequest(project="root", spec=spec, lease=fresh, retry=True))
    assert made.id.endswith("." + fresh)
    for sid in (first.id, made.id):
        await Sandbox(client, await stub.GetSandbox(types_pb2.SandboxRef(id=sid))).stop()
    # Ended: a late retry reports it rather than starting a new one.
    with pytest.raises(DSecError) as e:
        await _call(stub.CreateSandbox(opendsec_pb2.CreateSandboxRequest(project="root", spec=spec, lease=lease, retry=True)))
    assert e.value.reason == INVALID
    await client.close()


async def test_batch_retry_same_request_id():
    """A bulk creation whose stream breaks (UNAVAILABLE) is repeated with
    retry set and the same request_id, so the server returns the sandboxes
    the first attempt made instead of making more."""
    import grpc

    from opendsec._pb.opendsec.v1 import opendsec_pb2, types_pb2

    req = opendsec_pb2.CreateSandboxesRequest(project="root", count=3, request_id="a" * 26)
    seen = []

    def result(i):
        return opendsec_pb2.CreateSandboxResult(index=i, sandbox=types_pb2.Sandbox(id=f"e1.{'a' * 26}aa{i}"))

    def make():
        seen.append((req.request_id, req.retry))

        async def stream():
            yield result(0)
            if len(seen) == 1:
                raise grpc.aio.AioRpcError(grpc.StatusCode.UNAVAILABLE, grpc.aio.Metadata(), grpc.aio.Metadata(), "edge gone")
            for i in (1, 2):
                yield result(i)
        return stream()

    out = await DSecClient("127.0.0.1:1", "t", "root", retry_timeout=5)._batch(make, req, 3)
    assert seen == [("a" * 26, False), ("a" * 26, True)]
    assert [s.id for s in out] == [f"e1.{'a' * 26}aa{i}" for i in range(3)]


async def test_batch_replay_is_not_progress():
    """A stream that replays the same result and breaks again every time
    stops at retry_timeout: replayed results are not progress."""
    import grpc

    from opendsec._pb.opendsec.v1 import opendsec_pb2, types_pb2

    req = opendsec_pb2.CreateSandboxesRequest(project="root", count=3, request_id="b" * 26)

    def make():
        async def stream():
            yield opendsec_pb2.CreateSandboxResult(index=0, sandbox=types_pb2.Sandbox(id="e1." + "b" * 26 + "aa0"))
            raise grpc.aio.AioRpcError(grpc.StatusCode.UNAVAILABLE, grpc.aio.Metadata(), grpc.aio.Metadata(), "edge gone")
        return stream()

    with pytest.raises(DSecError):
        await asyncio.wait_for(DSecClient("127.0.0.1:1", "t", "root", retry_timeout=1)._batch(make, req, 3), 10)
