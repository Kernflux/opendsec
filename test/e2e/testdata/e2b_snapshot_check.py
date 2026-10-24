"""Acceptance check of E2B's fork and snapshots through the gateway (spec §37.10).

Run with E2B_API_URL, E2B_SANDBOX_URL and E2B_API_KEY set to the gateway and
an OpenDsec token. With MEMORY=1 (microVM templates) it also checks that forks
and sandboxes created from a snapshot keep the source's running processes.
Prints "OK <n> checks" on success.
"""
import os
import time
import uuid

from e2b import Sandbox

memory = os.environ.get("MEMORY") == "1"
checks = 0


def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1


def has_holder(s):
    return any("holder" in " ".join([p.cmd] + p.args) for p in s.commands.list())


made = []
src = Sandbox.create(timeout=300)
made.append(src)
try:
    src.files.write("/tmp/f", "v1")
    if memory:
        src.commands.run("exec -a holder sleep 600", background=True)

    # Fork: copies of the running sandbox, which keeps running.
    t0 = time.time()
    forks = src.fork(count=2, timeout=120)
    fork_ms = (time.time() - t0) * 1000
    check(len(forks) == 2 and all(isinstance(f, Sandbox) for f in forks), f"fork: {forks}")
    made += forks
    check(len({f.sandbox_id for f in forks} | {src.sandbox_id}) == 3, "fork ids")
    for f in forks:
        check(f.files.read("/tmp/f") == "v1", "a fork sees the source's files")
        if memory:
            check(has_holder(f), "a fork keeps the source's processes")
    forks[0].files.write("/tmp/f", "fork")
    check(src.files.read("/tmp/f") == "v1" and forks[1].files.read("/tmp/f") == "v1", "forks diverge")
    check(src.is_running(), "the source runs on")

    # A snapshot: an id to create sandboxes from, listed until deleted.
    t0 = time.time()
    snap = src.create_snapshot()
    snap_ms = (time.time() - t0) * 1000
    check(snap.snapshot_id and snap.names == [snap.snapshot_id], f"snapshot: {snap}")
    check(src.commands.run("cat /tmp/f").stdout == "v1", "the source runs on after a snapshot")
    ids = [s.snapshot_id for s in src.list_snapshots().next_items()]
    check(snap.snapshot_id in ids, f"listed for its sandbox: {ids}")
    check(snap.snapshot_id in [s.snapshot_id for s in Sandbox.list_snapshots().next_items()], "listed")
    t0 = time.time()
    s2 = Sandbox.create(snap.snapshot_id, timeout=120)
    create_ms = (time.time() - t0) * 1000
    made.append(s2)
    check(s2.files.read("/tmp/f") == "v1", "a sandbox from the snapshot has its files")
    if memory:
        check(has_holder(s2), "a sandbox from the snapshot keeps its processes")
    f2 = s2.fork(count=1)[0]
    made.append(f2)
    check(f2.files.read("/tmp/f") == "v1", "a sandbox from a snapshot forks")

    # A named snapshot: the name with E2B's default tag; taking it again
    # replaces it.
    name = "e2b-check-" + uuid.uuid4().hex[:8]
    named = src.create_snapshot(name)
    check(named.snapshot_id.endswith("/" + name + ":default"), f"named: {named}")
    src.files.write("/tmp/f", "v2")
    again = src.create_snapshot(name)
    check(again.snapshot_id == named.snapshot_id, "the name again")
    check([s.snapshot_id for s in Sandbox.list_snapshots(name=name).next_items()] == [named.snapshot_id], "by name")
    s3 = Sandbox.create(named.snapshot_id, timeout=60)
    made.append(s3)
    check(s3.files.read("/tmp/f") == "v2", "the name's latest snapshot")

    for sid in (snap.snapshot_id, named.snapshot_id):
        check(Sandbox.delete_snapshot(sid) is True, "delete")
        check(Sandbox.delete_snapshot(sid) is False, "delete again")
    left = [s.snapshot_id for s in Sandbox.list_snapshots().next_items()]
    check(snap.snapshot_id not in left and named.snapshot_id not in left, "listed after delete")
finally:
    for s in made:
        try:
            s.kill()
        except Exception:
            pass
print(f"OK {checks} checks; fork x2 {fork_ms:.0f} ms, snapshot {snap_ms:.0f} ms, create from it {create_ms:.0f} ms")
