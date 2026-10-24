"""SDK over TLS against `opendsecctl cluster up -tls`, plus token lifecycle."""

import asyncio
import os
import re
import subprocess

import pytest

from opendsec import UNAUTHENTICATED, DSecClient, DSecError, DSecRunArgs

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPENDSECCTL = os.path.join(ROOT, "bin", "opendsecctl")


@pytest.fixture(scope="module")
def cluster():
    proc = subprocess.Popen([OPENDSECCTL, "cluster", "up", "-sim-edges", "2", "-apiservers", "2", "-tls", "-log", "warn"],
                            stdout=subprocess.PIPE, text=True)
    env = None
    for line in proc.stdout:
        m = re.search(r"OPENDSEC_ADDR=(\S+) OPENDSEC_TOKEN=(\S+) OPENDSEC_PROJECT=\S+ OPENDSEC_CA=(\S+)", line)
        if m:
            env = {"addr": m.group(1), "token": m.group(2), "ca": m.group(3)}
            break
    assert env, "cluster did not start"
    yield env
    proc.terminate()
    proc.wait(30)


async def test_tls_and_tokens(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root", ca_file=cluster["ca"]) as admin:
        assert await admin.whoami() == "admin"
        sb = await admin.run_sandbox(DSecRunArgs(backend="sim", memory_limit_mb=128))
        await sb.stop()

        tok = await admin.create_principal("root", "agent-x", ttl=3600)
        await admin.grant("root", "agent-x", ["sandbox.operate"])
        async with DSecClient(cluster["addr"], tok, "root", ca_file=cluster["ca"]) as agent:
            assert await agent.whoami() == "agent-x"
            # The agent mints a short-lived token for itself.
            short, info = await agent.create_token(ttl=60, description="rollout worker")
            assert info.expires_at > 0
            infos = await agent.list_tokens()
            assert {i.description for i in infos} >= {"initial", "rollout worker"}

        async with DSecClient(cluster["addr"], short, "root", ca_file=cluster["ca"]) as worker:
            await worker.list_sandboxes()
            await admin.revoke_token("agent-x", info.id)
            for _ in range(40):  # revocation reaches every apiserver within ~1s
                try:
                    await worker.list_sandboxes()
                except DSecError as e:
                    assert e.reason == UNAUTHENTICATED
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("revoked token still accepted")
        await admin.delete_principal("agent-x")


async def test_plaintext_rejected(cluster):
    async with DSecClient(cluster["addr"], cluster["token"], "root") as plain:
        with pytest.raises(DSecError):
            await asyncio.wait_for(plain.whoami(), 5)
