"""Fork a running microVM: the copies continue from its memory, then go
their own ways.

A Python process in the sandbox keeps a counter in memory only (no file):
it serves "get" and "add N" on 127.0.0.1:7777 inside the VM. The program
sets the counter to 41, forks the sandbox into two copies, and checks:

  1. inherited: both copies' processes still hold 41 (their memory was
     copied, the process was not restarted);
  2. isolated: adding 1 in one copy and 100 in the other gives 42 and 141,
     and the source still holds 41.

Prerequisites: a cluster with the microvm backend (KVM) and an image with
python3 (OPENDSEC_IMAGE, default root/py:3.12). Install and environment as
in execute_code.py.

    python memory_fork.py

Expected output (ids and timings differ; timings depend on the hardware,
the image and the VM's memory, and include the network round trips):

    source e1.aaaa: counter = 41
    fork of 2 copies: 0.31 s (microvm, root/py:3.12, 1 vCPU, 512 MB)
    copy e1.bbbb: inherited 41, after +1 -> 42
    copy e2.cccc: inherited 41, after +100 -> 141
    source e1.aaaa: still 41
    OK: memory inherited and isolated
    stopped 3 sandboxes

A fork copies the VM, not the world outside it: connections to outside
services do not carry over (the copies must reconnect), and credentials in
memory are copied too. Do not fork sandboxes holding secrets you would not
hand to every copy.

Cleanup: every sandbox made here is stopped in `finally`; the source and
the copies also carry ttl_max (10 min) in case this program is killed.
"""
import asyncio
import os
import time

from opendsec import DSecClient, DSecError, DSecRunArgs

SERVER = r"""
import socket
n = 0
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 7777)); s.listen()
while True:
    c, _ = s.accept()
    cmd = c.recv(100).decode().split()
    if cmd and cmd[0] == "add":
        n += int(cmd[1])
    c.sendall(str(n).encode()); c.close()
"""

ASK = """
import socket, sys
for _ in range(100):
    try:
        c = socket.create_connection(("127.0.0.1", 7777), timeout=2); break
    except OSError:
        import time; time.sleep(0.1)
c.sendall(" ".join(sys.argv[1:]).encode()); print(c.recv(100).decode())
"""


async def ask(sb, *cmd: str) -> int:
    r = await sb.exec(["python3", "/tmp/ask.py", *cmd], timeout=30)
    if not r.ok:
        raise RuntimeError(f"{sb.id}: {r.stderr or r.stdout}")
    return int(r.stdout)


async def main() -> None:
    image = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")
    made = []
    async with DSecClient() as client:
        try:
            src = await client.run_sandbox(DSecRunArgs(backend="microvm", image=image, cpu_cores_limit=1,
                                                       memory_limit_mb=512, ttl_max=600))
            made.append(src)
            await src.write_file("/tmp/server.py", SERVER)
            await src.write_file("/tmp/ask.py", ASK)
            await src.run_shell_background("python3 /tmp/server.py", session="server")
            print(f"source {src.id}: counter = {await ask(src, 'add', '41')}")

            t0 = time.monotonic()
            copies = await src.fork(count=2, ttl_max=600)
            took = time.monotonic() - t0
            for c in copies:
                if isinstance(c, Exception):
                    raise c
                made.append(c)
            print(f"fork of {len(copies)} copies: {took:.2f} s (microvm, {image}, 1 vCPU, 512 MB)")

            results = []
            for c, add in zip(copies, (1, 100)):
                inherited = await ask(c, "get")
                after = await ask(c, "add", str(add))
                print(f"copy {c.id}: inherited {inherited}, after +{add} -> {after}")
                results.append((inherited, after))
            source_now = await ask(src, "get")
            print(f"source {src.id}: still {source_now}")
            assert results == [(41, 42), (41, 141)] and source_now == 41, (results, source_now)
            print("OK: memory inherited and isolated")
        finally:
            for sb in made:
                try:
                    await sb.stop()
                except DSecError as e:
                    print(f"stopping {sb.id} failed: {e.code}: {e.message}")
            print(f"stopped {len(made)} sandboxes")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except DSecError as e:
        raise SystemExit(f"OpenDsec error {e.code}: {e.message}\n{e.next_steps}")
