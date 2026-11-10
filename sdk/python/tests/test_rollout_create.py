"""RolloutRun._create against a fake client: no cluster needed."""

import asyncio

from opendsec import DSecContainerRunArgs
from opendsec.client import DSecError
from opendsec.rollout import CANCELLED, RolloutResult, RolloutRun


class FakeClient:
    def __init__(self, on_fail=None):
        self.calls, self.on_fail = 0, on_fail

    async def run_sandbox(self, args):
        self.calls += 1
        if self.calls == 1:
            if self.on_fail:
                self.on_fail()
            raise DSecError("unavailable", "try again")
        return "sandbox"


def run_of(client) -> RolloutRun:
    run = RolloutRun(client, DSecContainerRunArgs(container_image="host"), [("a", None, None)], command="true", episode=None,
                     shell=False, concurrency=1, execution_timeout_s=None, run_timeout_s=None, result_path=None, run_id="r",
                     on_progress=None, tail_bytes=0, max_result_bytes=0, attempt=1, source_run_id=None)
    run._deadline = float("inf")
    return run


def test_no_retry_while_paused():
    async def main():
        client = FakeClient()
        run = run_of(client)
        client.on_fail = run._running.clear
        task = asyncio.create_task(run._create(run.results[0]))
        await asyncio.sleep(1.2)  # past the longest first backoff
        assert client.calls == 1 and not task.done()
        run._running.set()
        assert await task == "sandbox" and client.calls == 2
    asyncio.run(main())


def test_no_retry_after_the_run_failed():
    async def main():
        fatal = {"code": "forbidden", "message": "no"}
        client = FakeClient()
        run = run_of(client)
        client.on_fail = lambda: setattr(run, "_fatal", fatal)
        r = run.results[0]
        assert await run._create(r) is None
        assert client.calls == 1 and r.status == CANCELLED and r.error == fatal
    asyncio.run(main())
