"""Release check, as a caller: private addresses in network rules are refused
(unless the project is in network.private_rule_projects: then skip this check),
names resolve, and a burst of DNS queries from one sandbox leaves the others'
resolution working. Needs sandbox networking with "*" allowed."""
import asyncio
import os
from opendsec import DSecClient, DSecError, DSecRunArgs

IMAGE = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")

BURST = r'''
import socket, struct, random, time
def q(name):
    out = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    for l in name.split("."):
        out += bytes([len(l)]) + l.encode()
    return out + b"\0" + struct.pack(">HH", 1, 1)
ns = [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")][0]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
codes = {}
for i in range(3000):
    s.sendto(q("burst%d.example.com" % i), (ns, 53))
end = time.time() + 6
while time.time() < end:
    try:
        d = s.recv(4096); c = d[3] & 15; codes[c] = codes.get(c, 0) + 1
    except socket.timeout:
        pass
print("answers by rcode:", sorted(codes.items()))
'''

def a(backend, rules):
    return DSecRunArgs(backend=backend, image=IMAGE, cpu_cores_limit=1, memory_limit_mb=512,
                       ttl_running_stop=300, network_rules=rules)

async def code_of(aw):
    try:
        await aw
        return "ok"
    except DSecError as e:
        return e.code

async def main():
    c = await DSecClient(retry_timeout=60).open()
    bad = 0
    def check(ok, what):
        nonlocal bad
        bad += not ok
        print("  ok  " if ok else "  FAIL", what)
    for be in ("container", "microvm"):
        for rule in ("169.254.169.254:80/tcp", "10.255.255.1", "0.0.0.0/0"):
            check(await code_of(c.run_sandbox(a(be, {rule: True}))) == "forbidden", f"{be}: create with {rule} refused")
        sb = await c.run_sandbox(a(be, {"*": True}))
        check(await code_of(sb.update_network({"192.168.0.0/16": True})) == "forbidden", f"{be}: update with a private network refused")
        r = await sb.run_shell("python3 -c \"import socket; print(socket.gethostbyname('pypi.org'))\"", timeout=30)
        check(r.ok, f"{be}: resolves pypi.org ({r.stdout.strip()} {r.stderr.strip()[:80]})")
        await sb.write_file("/tmp/burst.py", BURST)
        r = await sb.run_shell("python3 /tmp/burst.py", timeout=60)
        print("      burst of 3000 queries:", r.stdout.strip(), r.stderr.strip()[:200])
        other = await c.run_sandbox(a(be, {"*": True}))
        r2 = await other.run_shell("python3 -c \"import socket; print(socket.gethostbyname('files.pythonhosted.org'))\"", timeout=30)
        check(r.ok and r2.ok, f"{be}: another sandbox resolves after the burst ({r2.stdout.strip()} {r2.stderr.strip()[:80]})")
        r3 = await sb.run_shell("python3 -c \"import socket; print(socket.gethostbyname('example.com'))\"", timeout=30)
        check(r3.ok, f"{be}: the bursting sandbox resolves again ({r3.stdout.strip()} {r3.stderr.strip()[:80]})")
        await sb.stop(); await other.stop()
    print(f"NET {'ok' if not bad else 'FAILED'}")
    raise SystemExit(bad)

asyncio.run(main())
