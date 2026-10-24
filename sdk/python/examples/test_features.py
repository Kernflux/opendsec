"""OpenDsec 功能测试：逐项验证 SDK 的功能，每项输出 PASS / FAIL。

    export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=root/prod OPENDSEC_CA=./ca.crt
    python test_features.py            # 全部
    python test_features.py basics     # 只跑名字里含 basics 的项
用完会停掉自己创建的 sandbox、删掉自己做的镜像。
"""
import asyncio
import sys
import time
import traceback

from opendsec import DSecClient, DSecError, DSecRunArgs

results = []
tag = time.strftime("%H%M%S")


async def check(name, coro):
    t0 = time.time()
    try:
        await coro
        results.append((name, "PASS", f"{time.time()-t0:.1f}s"))
    except DSecError as e:
        if e.reason != "forbidden":
            raise_ = e
        else:  # the identity lacks a permission this item needs: not a failure
            results.append((name, "SKIP", f"no permission: {e.message}"))
            return
        results.append((name, "FAIL", f"DSecError: {str(raise_)[:200]}"))
        traceback.print_exc()
    except Exception as e:  # noqa: BLE001
        results.append((name, "FAIL", f"{type(e).__name__}: {str(e)[:200]}"))
        traceback.print_exc()


def need(cond, msg):
    if not cond:
        raise AssertionError(msg)


def args(backend, **kw):
    return DSecRunArgs(backend=backend, image="root/py:3.12", cpu_cores_limit=1,
                       memory_limit_mb=1024, ttl_running_stop=300, **kw)


async def basics(c, backend):
    sb = await c.run_sandbox(args(backend))
    try:
        r = await sb.run_shell("python3 -c 'print(6*7)'")
        need(r.stdout.strip() == "42" and r.exit_code == 0, r)
        r = await sb.run_shell("exit 3")
        need(r.exit_code == 3, r)
        await sb.run_shell("export FOO=bar; cd /tmp", session="s1")
        r = await sb.run_shell("echo $FOO $(pwd)", session="s1")
        need(r.stdout.strip() == "bar /tmp", r.stdout)
        need("s1" in await sb.list_sessions(), "session missing")
        await sb.close_session("s1")
        r = await sb.run_shell("sleep 5", timeout=1)
        need(r.timed_out, "no timeout")
        cid = await sb.run_shell_background("for i in 1 2 3; do echo $i; sleep 0.3; done")
        r = await sb.get_output(cid, wait=10)
        need(r.done and r.stdout.split() == ["1", "2", "3"], r)
        chunks = [k async for k, _ in sb.stream_shell("for i in 1 2 3; do echo $i; sleep 0.3; done")]
        need(chunks.count("stdout") >= 2 and chunks[-1] == "exit", chunks)
        data = bytes(range(256)) * 4096
        await sb.write_file("/root/d/blob", data)
        need(await sb.read_file("/root/d/blob") == data, "file mismatch")
        need((await sb.stat("/root/d/blob")).size == len(data), "stat")
        need([f.name for f in await sb.list_dir("/root/d")] == ["blob"], "list_dir")
        await sb.remove("/root/d", recursive=True)
        r = await sb.run_shell("test -e /root/d; echo $?")
        need(r.stdout.strip() == "1", "remove")
        await sb.run_shell_background("cd /root && echo hi > index.html && exec python3 -m http.server 8080", session="srv")
        for _ in range(50):
            try:
                h = await sb.http("http://127.0.0.1:8080/index.html")
                if h.status == 200:
                    break
            except DSecError:
                pass
            await asyncio.sleep(0.2)
        need(h.status == 200 and h.body.strip() == b"hi", h)
        r = await sb.run_shell("python3 -c \"import urllib.request;print(urllib.request.urlopen('https://pypi.org/simple/',timeout=10).status)\"")
        need(r.stdout.strip() == "200", ("internet", r.stdout, r.stderr))
        await sb.update_network({"*": False}, replace=True)
        r = await sb.run_shell("python3 -c \"import urllib.request;urllib.request.urlopen('https://pypi.org/simple/',timeout=5)\"", timeout=20)
        need(r.exit_code != 0, "egress not blocked")
        await sb.update_network({"*": True}, replace=True)
        r = await sb.run_shell("python3 -c \"import urllib.request;print(urllib.request.urlopen('https://pypi.org/simple/',timeout=10).status)\"")
        need(r.stdout.strip() == "200", "egress not restored")
        r = await sb.run_shell("python3 -c \"import urllib.request;urllib.request.urlopen('http://100.100.100.200/',timeout=3)\"", timeout=20)
        need(r.exit_code != 0, "metadata reachable")
        await sb.touch()
        need((await sb.refresh()).state == "RUNNING", sb.state)
        found = await c.get_sandbox(sb.id)
        need(found.id == sb.id, "get_sandbox")
    finally:
        await sb.stop()
    need((await sb.refresh()).state in ("STOPPED", "STOPPING"), sb.state)


async def pause_resume(c, backend):
    sb = await c.run_sandbox(args(backend))
    try:
        await sb.run_shell_background("python3 -c \"import time\nn=0\nwhile True:\n n+=1;open('/root/n','w').write(str(n));time.sleep(0.1)\"", session="bg")
        await asyncio.sleep(1)
        await sb.write_file("/root/keep", b"k")
        await sb.pause()
        need((await sb.refresh()).state == "PAUSED", sb.state)
        await sb.resume()
        a = int((await sb.read_file("/root/n")).decode() or 0)
        await asyncio.sleep(1)
        b = int((await sb.read_file("/root/n")).decode() or 0)
        need(b > a > 0, ("process not alive after resume", a, b))
        need(await sb.read_file("/root/keep") == b"k", "file lost")
    finally:
        await sb.stop()


async def fork(c):
    sb = await c.run_sandbox(args("microvm"))
    kids = []
    try:
        await sb.run_shell_background("python3 -c \"import time,random\nx=random.random()\nopen('/root/x','w').write(str(x))\nwhile True:\n open('/root/y','w').write(str(x));time.sleep(0.1)\"", session="bg")
        await asyncio.sleep(1)
        x = await sb.read_file("/root/x")
        kids = await sb.fork(count=3)
        bad = [k for k in kids if isinstance(k, DSecError)]
        need(not bad, bad)
        for k in kids:
            await sb.run_shell("true")
            await asyncio.sleep(0.3)
            need(await k.read_file("/root/y") == x, "fork memory differs")
            await k.run_shell("rm /root/y; sleep 0.5")
            need(await k.read_file("/root/y") == x, "forked process not running")
        need(await sb.read_file("/root/x") == x, "parent changed")
    finally:
        for k in kids:
            if not isinstance(k, DSecError):
                await k.stop()
        await sb.stop()


async def images(c):
    pd, snap = f"{c.project}/smoke:pd{tag}", f"{c.project}/smoke:mem{tag}"
    made = []
    try:
        ct = await c.run_sandbox(args("container"))
        try:
            await ct.run_shell("pip install -q --root-user-action=ignore six && echo baked > /root/baked && rm -rf /tmp/*", timeout=120)
            await ct.pack_diff(pd); made.append(pd)
        finally:
            await ct.stop()
        vm = await c.run_sandbox(args("microvm"))
        try:
            await vm.run_shell("pip install -q --root-user-action=ignore six && echo baked > /root/baked", timeout=120)
            await vm.run_shell_background("python3 -c \"import time\nwhile True:\n open('/root/alive','a').write('.');time.sleep(0.1)\"", session="bg")
            await asyncio.sleep(0.5)
            await vm.create_snapshot(snap, memory=True); made.append(snap)
        finally:
            await vm.stop()
        for m in made:
            await c.get_image(m)
        for img, backend in ((pd, "container"), (pd, "microvm"), (snap, "microvm")):
            s2 = await c.run_sandbox(DSecRunArgs(backend=backend, image=img, cpu_cores_limit=1,
                                                 memory_limit_mb=1024, ttl_running_stop=300))
            try:
                r = await s2.run_shell("cat /root/baked; python3 -c 'import six;print(six.__name__)'", timeout=30)
                need(r.stdout.split() == ["baked", "six"], (img, backend, r.stdout, r.stderr))
                if img == snap:
                    n = len(await s2.read_file("/root/alive"))
                    await asyncio.sleep(1)
                    need(len(await s2.read_file("/root/alive")) > n, "memory snapshot process not resumed")
            finally:
                await s2.stop()
    finally:
        for m in made:
            await c.delete_image(m)


async def batch_task(c):
    task = f"smoke-{tag}"
    res = await c.run_sandboxes(args("microvm", task_id=task), 40)
    bad = [r for r in res if isinstance(r, DSecError)]
    need(not bad, bad[:3])
    need(len(await c.list_sandboxes(task_id=task)) == 40, "list task")
    await c.pause_task(task)
    need(all(s.state == "PAUSED" for s in await c.list_sandboxes(task_id=task)), "pause_task")
    await c.resume_task(task)
    need(all(s.state == "RUNNING" for s in await c.list_sandboxes(task_id=task)), "resume_task")
    rs = await asyncio.gather(*[s.run_shell("echo ok") for s in res])
    need(all(r.stdout.strip() == "ok" for r in rs), "shell after resume_task")
    await c.stop_task(task)
    await asyncio.sleep(2)
    need(not await c.list_sandboxes(task_id=task), "stop_task")


async def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    c = await DSecClient(retry_timeout=60).open()   # OPENDSEC_ADDR / OPENDSEC_TOKEN / OPENDSEC_PROJECT / OPENDSEC_CA
    print("as", await c.whoami(), "project", c.project)
    tests = [(f"{b}: basics (shell/session/bg/stream/files/http/network)", lambda b=b: basics(c, b))
             for b in ("container", "microvm")]
    tests += [(f"{b}: pause/resume", lambda b=b: pause_resume(c, b)) for b in ("container", "microvm")]
    tests += [("microvm: fork x3", lambda: fork(c)),
              ("images: pack_diff + memory snapshot", lambda: images(c)),
              ("batch 40 + task pause/resume/stop", lambda: batch_task(c))]
    try:
        for name, t in tests:
            if only in name:
                await check(name, t())
                print(*results[-1], sep="  |  ", flush=True)
    finally:
        await c.close()
    n = {k: sum(r[1] == k for r in results) for k in ("PASS", "FAIL", "SKIP")}
    print(f"\nPASS {n['PASS']}  FAIL {n['FAIL']}  SKIP {n['SKIP']}")
    sys.exit(1 if n["FAIL"] else 0)


asyncio.run(main())
