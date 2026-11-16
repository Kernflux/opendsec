"""Release check, as a caller: a container's /.opendsec/run is within its disk,
io_uring is refused, and command output still comes through a pipe."""
import asyncio
import os
from opendsec import DSecClient, DSecRunArgs

IMAGE = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")

URING = "import ctypes,os; l=ctypes.CDLL(None,use_errno=True); r=l.syscall(425,4,ctypes.byref(ctypes.create_string_buffer(120))); print(r, os.strerror(ctypes.get_errno()) if r<0 else 'ok')"

async def main():
    c = await DSecClient(retry_timeout=60).open()
    sb = await c.run_sandbox(DSecRunArgs(backend="container", image=IMAGE, cpu_cores_limit=1, memory_limit_mb=512,
                                         ttl_running_stop=300, disk_mb=128))
    bad = 0
    def check(ok, what):
        nonlocal bad
        bad += not ok
        print("  ok  " if ok else "  FAIL", what)
    try:
        # With its disk full a command's output is not recorded either: the size goes to /dev/shm.
        full = await sb.run_shell("dd if=/dev/zero of=/.opendsec/run/fill bs=1M count=400 2>/dev/null; stat -c %s /.opendsec/run/fill > /dev/shm/size; echo lost; rm -f /.opendsec/run/fill", timeout=120)
        print(f"      while full: exit {full.exit_code}, stdout {full.stdout!r}, dropped {getattr(full, 'dropped_bytes', '?')}")
        r = await sb.run_shell("cat /dev/shm/size")
        size = int(r.stdout.strip().split()[-1])
        check(size < 140 << 20, f"400 MB into /.opendsec/run of a 128 MB sandbox stops at {size >> 20} MB")
        r = await sb.run_shell("echo still-works")
        check(r.stdout.strip() == "still-works", "commands work after the run dir was full")
        r = await sb.run_shell(f"python3 -c \"{URING}\"")
        check(r.stdout.startswith("-1") and "permitted" in r.stdout, f"io_uring_setup: {r.stdout.strip()} {r.stderr.strip()[:100]}")
        big = await sb.run_shell("python3 -c \"print('x'*5000000)\" | wc -c")
        check(big.stdout.strip() == "5000001", "5 MB of output through a pipe")
    finally:
        await sb.stop()
    print(f"QUOTA {'ok' if not bad else 'FAILED'}")
    raise SystemExit(bad)

asyncio.run(main())
