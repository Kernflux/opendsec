"""Run untrusted code once: a sandbox is made, the code runs, the sandbox goes.

Prerequisites: a running OpenDsec cluster and a token for a project
(see docs/en/USER_GUIDE.md, "Use an existing cluster").

    pip install "git+https://github.com/Kernflux/opendsec#subdirectory=sdk/python"
    export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=...   # and OPENDSEC_CA=ca.crt, or OPENDSEC_TLS=1
    python execute_code.py

Expected output (the sandbox id differs):

    sandbox e1.xxxxxxxx running microvm root/py:3.12
    exit 0 in 0.05 s
    stdout: [1, 4, 9, 16, 25]
    stderr: warning: this went to stderr
    sandbox stopped

Options: OPENDSEC_BACKEND (default microvm; or container), OPENDSEC_IMAGE
(default root/py:3.12; any image with python3).

Cleanup: the sandbox is stopped when the `async with` block ends, also on
errors. If this program is killed, the sandbox stops by itself within an
hour (the block's default ttl_max).

Errors: a failed call raises DSecError; its `next_steps` says what to check
(token, project, quota, image name...).
"""
import asyncio
import json
import os

from opendsec import DSecClient, DSecError, DSecRunArgs

CODE = """
import json, sys
data = json.load(open(sys.argv[1]))
print([x * x for x in data["numbers"]])
print("warning: this went to stderr", file=sys.stderr)
"""


async def main() -> None:
    backend = os.environ.get("OPENDSEC_BACKEND", "microvm")
    image = os.environ.get("OPENDSEC_IMAGE", "root/py:3.12")
    async with DSecClient() as client:
        async with client.sandbox(DSecRunArgs(backend=backend, image=image,
                                              cpu_cores_limit=1, memory_limit_mb=512)) as sb:
            print("sandbox", sb.id, "running", backend, image)
            await sb.write_file("/tmp/main.py", CODE)
            await sb.write_file("/tmp/input.json", json.dumps({"numbers": [1, 2, 3, 4, 5]}))
            r = await sb.exec(["python3", "/tmp/main.py", "/tmp/input.json"], timeout=60)
            print(f"exit {r.exit_code} in {r.duration:.2f} s")
            print("stdout:", r.stdout.strip())
            print("stderr:", r.stderr.strip())
        print("sandbox stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except DSecError as e:
        raise SystemExit(f"OpenDsec error {e.code}: {e.message}\n{e.next_steps}")
