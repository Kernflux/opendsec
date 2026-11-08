"""Rollouts: run a batch of inputs, each in a fresh sandbox, and collect the
results (docs/private usability spec, P1; docs/en/PYTHON_SDK.md "Rollouts").

    run = await client.rollouts.start(
        args=DSecRunArgs(backend="microvm", image="root/py:3.12"),
        command=["python3", "/app/rollout.py"],          # or episode=async fn
        inputs=[{"id": "seed-1", "payload": {"seed": 1}}, ...],
        concurrency=10, execution_timeout_s=300, run_timeout_s=1800,
        result_path="result.json")
    summary = await run.wait()
    run.export_jsonl("results.jsonl")

Every sandbox of a run carries task_id = run.run_id (and the label
rollout.input_id), so any process can find and stop what a run left:
``client.rollouts.cleanup(run_id)``, or ``opendsecctl task stop <run_id>``.
Sandboxes also carry a ttl_max covering the run's time budget, so a killed
client leaves nothing for long. A client that exits does not go on
dispatching inputs that had not started.

Infrastructure trouble before a command starts (no capacity, quota,
rate limits, an unreachable node) is waited out with backoff within
run_timeout_s; a command or episode that started is never retried.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

from .client import DSecClient, DSecError, DSecRunArgs, Sandbox

# Statuses of a result.
SUCCEEDED = "succeeded"
FAILED = "failed"             # non-zero exit, or the episode raised
TIMED_OUT = "timed_out"
RESULT_ERROR = "result_error"  # exit 0, but the result file is missing, too large or not JSON
CREATE_FAILED = "create_failed"
CANCELLED = "cancelled"
UNKNOWN = "unknown"            # could not tell (e.g. the sandbox's node went away mid-command)
FINAL = (SUCCEEDED, FAILED, TIMED_OUT, RESULT_ERROR, CREATE_FAILED, CANCELLED, UNKNOWN)

# Errors a creation waits out (with backoff, within the run's budget).
_WAIT = {"no_capacity", "quota_exceeded", "rate_limited", "unavailable", "timeout"}
# Errors that mean the run itself is misconfigured: no input can succeed.
_FATAL = {"unauthenticated", "forbidden", "not_found", "invalid"}

INPUT_DIR = "/tmp/opendsec-rollout"
INPUT_PATH = INPUT_DIR + "/input.json"

Episode = Callable[[Sandbox, Any], Awaitable[Any]]


def new_run_id() -> str:
    """r-<UTC date>-<8 random chars>: sortable, unique, a valid task id."""
    return time.strftime("r-%Y%m%d-", time.gmtime()) + base64.b32encode(os.urandom(5)).decode().lower()


def inputs_from_count(n: int, payload: Any = None) -> list[dict]:
    """``n`` inputs with ids 0..n-1 and the same payload, for repeated runs."""
    return [{"id": str(i), "payload": payload} for i in range(n)]


@dataclass
class RolloutResult:
    run_id: str
    input_id: str
    input_index: int
    attempt: int = 1
    status: str = "queued"     # queued | creating | running | collecting | one of FINAL
    sandbox_id: str = ""
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    output_truncated: bool = False
    result: Any = None
    error: dict | None = None  # {"code", "message", "next_steps"}
    cleanup_status: str = ""   # succeeded | failed | skipped | "" (no sandbox)
    duration_ms: int = 0       # the command or episode
    queued_ms: int = 0         # from start() to having a sandbox
    source_run_id: str = ""    # for reruns

    @property
    def done(self) -> bool:
        return self.status in FINAL

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _err(code: str, message: str) -> dict:
    hint = DSecError(code, message).next_steps
    return {"code": code, "message": message[:2000], "next_steps": hint}


@dataclass
class RolloutSummary:
    run_id: str
    counts: dict[str, int]
    results: list[RolloutResult]
    leftover: list[str] = field(default_factory=list)  # sandboxes still running after cleanup
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        """Every input succeeded and nothing is left running."""
        return self.counts.get(SUCCEEDED, 0) == len(self.results) and not self.leftover \
            and all(r.cleanup_status in ("succeeded", "") for r in self.results)

    def failed(self) -> list[RolloutResult]:
        return [r for r in self.results if r.status != SUCCEEDED]

    def __str__(self) -> str:
        parts = [f"{k} {v}" for k, v in self.counts.items() if v]
        s = f"run {self.run_id}: {len(self.results)} inputs, " + ", ".join(parts) + f" in {self.elapsed_s:.1f} s"
        bad = sum(1 for r in self.results if r.cleanup_status == "failed")
        if bad or self.leftover:
            s += f"; NOT CLEANED UP: {bad} stop failures, {len(self.leftover)} sandboxes left " \
                 f"(clean up: opendsecctl task stop {self.run_id})"
        return s


@dataclass
class Progress:
    """A snapshot: counts by status, active sandboxes, cleanup."""

    run_id: str
    total: int
    counts: dict[str, int]
    active: int            # sandboxes being made or in use
    cleanup_pending: int
    cleanup_failed: int
    elapsed_s: float

    def line(self) -> str:
        c = self.counts
        return (f"{self.run_id}  {sum(c.get(s, 0) for s in FINAL)}/{self.total} done  "
                f"ok {c.get(SUCCEEDED, 0)}  failed {c.get(FAILED, 0)}  timed out {c.get(TIMED_OUT, 0)}  "
                f"result errors {c.get(RESULT_ERROR, 0)}  create failed {c.get(CREATE_FAILED, 0)}  "
                f"cancelled {c.get(CANCELLED, 0)}  unknown {c.get(UNKNOWN, 0)}  |  queued {c.get('queued', 0)}  "
                f"active {self.active}  cleanup pending {self.cleanup_pending}  {self.elapsed_s:.0f} s")

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class Rollouts:
    """``client.rollouts``."""

    def __init__(self, client: DSecClient):
        self._client = client

    async def start(self, args: DSecRunArgs, inputs: Iterable[dict], *, command: list[str] | str | None = None,
                    episode: Episode | None = None, shell: bool = False, concurrency: int = 8,
                    execution_timeout_s: float | None = None, run_timeout_s: float = 3600,
                    result_path: str | None = None, run_id: str | None = None,
                    on_progress: Callable[[Progress], None] | None = None,
                    tail_bytes: int = 16 << 10, max_result_bytes: int = 8 << 20, max_payload_bytes: int = 1 << 20,
                    attempt: int = 1, source_run_id: str = "") -> "RolloutRun":
        """Start a run in the background and return its handle (see the
        module doc). ``command`` is an argv list (no shell), or with
        ``shell=True`` a shell command line; or pass ``episode``, an async
        function ``(sandbox, payload) -> JSON-able result``. In command mode
        the payload is at $OPENDSEC_INPUT_PATH (JSON)."""
        if (command is None) == (episode is None):
            raise ValueError("give either command or episode")
        if command is not None:
            if shell and not isinstance(command, str):
                raise ValueError("shell=True takes the command as one string")
            if not shell and (isinstance(command, str) or not list(command)):
                raise ValueError("command is an argv list (or a string with shell=True)")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        items = _check_inputs(inputs, max_payload_bytes)
        run = RolloutRun(self._client, args, items, command=command, episode=episode, shell=shell,
                         concurrency=concurrency, execution_timeout_s=execution_timeout_s,
                         run_timeout_s=run_timeout_s, result_path=result_path, run_id=run_id or new_run_id(),
                         on_progress=on_progress, tail_bytes=tail_bytes, max_result_bytes=max_result_bytes,
                         attempt=attempt, source_run_id=source_run_id)
        run._begin()
        return run

    async def run(self, args: DSecRunArgs, inputs: Iterable[dict], **kw) -> RolloutSummary:
        """start + wait; cancels the run if the caller is cancelled or interrupted."""
        run = await self.start(args, inputs, **kw)
        try:
            return await run.wait()
        except BaseException:
            await asyncio.shield(run.cancel())
            raise

    async def rerun(self, args: DSecRunArgs, inputs: Iterable[dict], previous: Iterable[RolloutResult | dict],
                    statuses: Iterable[str] = (FAILED, TIMED_OUT, RESULT_ERROR, CREATE_FAILED, CANCELLED, UNKNOWN),
                    **kw) -> "RolloutRun":
        """Start a new run of the inputs whose previous result has one of
        ``statuses`` (not succeeded, by default): a new run id, the same
        input ids, attempt + 1, source_run_id set. Whether redoing an input
        is safe (external side effects) is the caller's call."""
        want = set(statuses)
        prev = [r if isinstance(r, dict) else r.to_dict() for r in previous]
        redo = {r["input_id"]: r for r in prev if r.get("status") in want}
        chosen = [i for i in inputs if str(i["id"]) in redo]
        if not chosen:
            raise ValueError("no input to run again")
        first = next(iter(redo.values()))
        return await self.start(args, chosen, attempt=max(r.get("attempt", 1) for r in redo.values()) + 1,
                                source_run_id=first.get("run_id", ""), **kw)

    async def cleanup(self, run_id: str, project: str | None = None) -> list[str]:
        """Stop every sandbox a run left (any process can: by its task id).
        Returns the ids still not stopped (normally none)."""
        await self._client.stop_task(run_id, project)
        left = []
        for _ in range(20):
            left = [s.id for s in await self._client.list_sandboxes(task_id=run_id, project=project)
                    if s.state not in ("STOPPED", "FAILED")]
            if not left:
                break
            await asyncio.sleep(0.5)
        return left


def _check_inputs(inputs: Iterable[dict], max_payload: int) -> list[tuple[str, Any, bytes]]:
    out, seen = [], set()
    for n, i in enumerate(inputs):
        if not isinstance(i, dict) or "id" not in i:
            raise ValueError(f"input {n}: needs an \"id\" (and a \"payload\")")
        iid = str(i["id"])
        if iid in seen:
            raise ValueError(f"input {n}: id {iid!r} is not unique")
        seen.add(iid)
        try:
            data = json.dumps(i.get("payload"), separators=(",", ":")).encode()
        except (TypeError, ValueError) as e:
            raise ValueError(f"input {iid!r}: payload is not JSON: {e}") from None
        if len(data) > max_payload:
            raise ValueError(f"input {iid!r}: payload is {len(data)} bytes, over {max_payload}")
        out.append((iid, i.get("payload"), data))
    if not out:
        raise ValueError("no inputs")
    return out


class RolloutRun:
    """A run in progress (Rollouts.start). Lives in this process: it stops
    dispatching if the process exits; its sandboxes are found by run_id."""

    def __init__(self, client: DSecClient, args: DSecRunArgs, items, *, command, episode, shell, concurrency,
                 execution_timeout_s, run_timeout_s, result_path, run_id, on_progress, tail_bytes,
                 max_result_bytes, attempt, source_run_id):
        self.client, self.items, self.run_id = client, items, run_id
        self.command, self.episode, self.shell = command, episode, shell
        self.concurrency = concurrency
        self.execution_timeout_s, self.run_timeout_s = execution_timeout_s, run_timeout_s
        self.result_path, self.tail_bytes, self.max_result_bytes = result_path, tail_bytes, max_result_bytes
        self.on_progress = on_progress
        labels = dict(args.labels)
        # The run's sandboxes: task_id = run id; lifetime covers the budget.
        ttl = int(run_timeout_s + 300) if run_timeout_s else 0
        if args.ttl_max and (not ttl or args.ttl_max < ttl):
            ttl = args.ttl_max
        self.args = dataclasses.replace(args, task_id=run_id, labels=labels, ttl_max=ttl)
        self.results = [RolloutResult(run_id, iid, n, attempt=attempt, source_run_id=source_run_id)
                        for n, (iid, _, _) in enumerate(items)]
        self._sem = asyncio.Semaphore(concurrency)
        self._tasks: list[asyncio.Task] = []
        self._main: asyncio.Task | None = None
        self._fatal: dict | None = None
        self._cancelled = False
        self._started = 0.0
        self._deadline = 0.0
        self._cleanup_pending = 0
        self._summary: RolloutSummary | None = None
        self.meta = {"type": "run", "run_id": run_id, "started_at": "", "backend": args.backend, "image": args.image,
                     "command": command if not callable(command) else None, "shell": shell,
                     "episode": getattr(episode, "__name__", None) if episode else None,
                     "concurrency": concurrency, "execution_timeout_s": execution_timeout_s,
                     "run_timeout_s": run_timeout_s, "result_path": result_path, "attempt": attempt,
                     "source_run_id": source_run_id, "inputs": len(items)}

    # -- lifecycle --------------------------------------------------------------------

    def _begin(self) -> None:
        loop = asyncio.get_running_loop()
        self._started = loop.time()
        self._deadline = self._started + self.run_timeout_s if self.run_timeout_s else float("inf")
        self.meta["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._tasks = [asyncio.create_task(self._item(n)) for n in range(len(self.items))]
        self._main = asyncio.create_task(self._finish())

    async def __aenter__(self) -> "RolloutRun":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc is not None or not self.done:
            await asyncio.shield(self.cancel())

    @property
    def done(self) -> bool:
        return self._summary is not None

    async def wait(self, timeout: float | None = None) -> RolloutSummary:
        """The summary once every input is final and the cleanup sweep ran.
        With ``timeout``, at most that long: then asyncio.TimeoutError, and
        the run goes on (waiting less does not stop anything)."""
        await asyncio.wait_for(asyncio.shield(self._main), timeout)
        return self._summary

    async def cancel(self, grace_s: float = 30) -> RolloutSummary:
        """Stop dispatching, end what runs, stop every sandbox of the run."""
        self._cancelled = True
        for t in self._tasks:
            if not t.done():
                t.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(self._main), grace_s + 30)
        except asyncio.TimeoutError:
            pass
        return self._summary or self._snapshot_summary()

    async def _finish(self) -> None:
        loop = asyncio.get_running_loop()
        pending = set(self._tasks)
        while pending:
            timeout = None if self._deadline == float("inf") else max(0.0, self._deadline - loop.time())
            done, pending = await asyncio.wait(pending, timeout=timeout)
            if pending and loop.time() >= self._deadline:  # the run's budget is spent
                for t in pending:
                    t.cancel()
                await asyncio.wait(pending)
                pending = set()
        # Sweep: creations cut short (cancelled, budget spent) may still have
        # made a sandbox; nothing of the run may stay.
        leftover: list[str] = []
        try:
            leftover = await Rollouts(self.client).cleanup(self.run_id, self.args.project)
        except DSecError as e:
            leftover = [f"(sweep failed: {e.code}: {e.message})"]
        for r in self.results:
            if not r.done:
                r.status, r.error = UNKNOWN, r.error or _err("internal", "the run ended without a final status")
        self._summary = self._snapshot_summary(leftover)
        self._notify()

    def _snapshot_summary(self, leftover=None) -> RolloutSummary:
        counts = {s: 0 for s in FINAL}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return RolloutSummary(self.run_id, counts, self.results, list(leftover or []),
                              asyncio.get_running_loop().time() - self._started)

    # -- progress ---------------------------------------------------------------------

    def progress(self) -> Progress:
        counts: dict[str, int] = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        active = sum(counts.get(s, 0) for s in ("creating", "running", "collecting")) + self._cleanup_pending
        return Progress(self.run_id, len(self.results), counts, active, self._cleanup_pending,
                        sum(1 for r in self.results if r.cleanup_status == "failed"),
                        asyncio.get_running_loop().time() - self._started)

    def _notify(self) -> None:
        if self.on_progress:
            try:
                self.on_progress(self.progress())
            except Exception:
                pass

    def _set(self, r: RolloutResult, status: str) -> None:
        r.status = status
        self._notify()

    # -- one input --------------------------------------------------------------------

    async def _item(self, n: int) -> None:
        r = self.results[n]
        loop = asyncio.get_running_loop()
        sb: Sandbox | None = None
        try:
            async with self._sem:  # the run's concurrency: from creating to stopped
                if self._fatal or self._cancelled:
                    r.status, r.error = CANCELLED, self._fatal or _err("cancelled", "the run was cancelled")
                    return
                self._set(r, "creating")
                sb = await self._create(r)
                if sb is None:
                    return
                r.sandbox_id = sb.id
                r.queued_ms = int((loop.time() - self._started) * 1000)
                try:
                    await self._execute(r, sb, n)
                finally:
                    await asyncio.shield(self._stop(r, sb))
        except asyncio.CancelledError:
            if not r.done:
                if r.status in ("queued", "creating"):
                    r.status = CANCELLED
                elif r.status == "running":
                    r.status = TIMED_OUT if loop.time() >= self._deadline and not self._cancelled else CANCELLED
                else:
                    r.status = UNKNOWN
                why = "the run's time budget (run_timeout_s) was spent" if not self._cancelled else "the run was cancelled"
                r.error = r.error or _err("cancelled" if self._cancelled else "run_timeout", why)
            if sb is not None and not r.cleanup_status:
                await asyncio.shield(self._stop(r, sb))
        finally:
            self._notify()

    async def _create(self, r: RolloutResult) -> Sandbox | None:
        loop = asyncio.get_running_loop()
        args = dataclasses.replace(self.args, labels={**self.args.labels, "rollout.input_id": r.input_id[:63]})
        delay = 0.5
        while True:
            try:
                return await self.client.run_sandbox(args)
            except DSecError as e:
                if e.code in _FATAL:
                    # Misconfigured (no image, no permission, bad arguments):
                    # no input can succeed, so stop dispatching.
                    r.status, r.error = CREATE_FAILED, _err(e.code, e.message)
                    if self._fatal is None:
                        self._fatal = _err(e.code, f"not started: an earlier input failed: {e.message}")
                    return None
                if e.code not in _WAIT or loop.time() + delay >= self._deadline:
                    r.status, r.error = CREATE_FAILED, _err(e.code, e.message)
                    return None
                await asyncio.sleep(delay * (0.5 + random.random()))
                delay = min(delay * 2, 10.0)

    async def _execute(self, r: RolloutResult, sb: Sandbox, n: int) -> None:
        loop = asyncio.get_running_loop()
        _, payload, data = self.items[n]
        self._set(r, "running")
        t0 = loop.time()
        timeout = self.execution_timeout_s
        if self._deadline != float("inf"):
            left = self._deadline - loop.time()
            timeout = left if timeout is None else min(timeout, left)
        try:
            if self.episode is not None:
                try:
                    value = await asyncio.wait_for(self.episode(sb, payload), timeout)
                except asyncio.TimeoutError:
                    r.status, r.error = TIMED_OUT, _err("timeout", "the episode ran past execution_timeout_s")
                    return
                except DSecError as e:
                    r.status, r.error = (UNKNOWN if e.code == "unavailable" else FAILED), _err(e.code, e.message)
                    return
                except Exception as e:  # the episode's own failure
                    r.status, r.error = FAILED, _err("episode_error", f"{type(e).__name__}: {e}")
                    return
                try:
                    json.dumps(value)
                except (TypeError, ValueError) as e:
                    r.status, r.error = RESULT_ERROR, _err("result_error", f"the episode's result is not JSON: {e}")
                    return
                r.result, r.status = value, SUCCEEDED
                return

            env = {"OPENDSEC_INPUT_PATH": INPUT_PATH, "OPENDSEC_INPUT_ID": r.input_id, "OPENDSEC_RUN_ID": self.run_id}
            await sb.exec(["mkdir", "-p", INPUT_DIR], timeout=60)
            await sb.write_file(INPUT_PATH, data)
            if self.shell:
                res = await sb.run_shell(self.command, timeout=timeout, env=env, session="rollout")
            else:
                res = await sb.exec(self.command, timeout=timeout, env=env)
            r.exit_code = res.exit_code if res.done else None
            r.stdout_tail, cut_o = _tail(res.stdout_bytes, self.tail_bytes)
            r.stderr_tail, cut_e = _tail(res.stderr_bytes, self.tail_bytes)
            r.output_truncated = cut_o or cut_e or res.truncated or res.dropped_bytes > 0
            if res.timed_out:
                r.status, r.error = TIMED_OUT, _err("timeout", "the command ran past execution_timeout_s")
                return
            if res.exit_code != 0:
                r.status, r.error = FAILED, _err("exit_code", f"the command exited with {res.exit_code}")
                return
            if self.result_path:
                self._set(r, "collecting")
                ok, value, err = await self._collect(sb)
                if not ok:
                    r.status, r.error = RESULT_ERROR, err
                    return
                r.result = value
            r.status = SUCCEEDED
        except DSecError as e:
            # Lost mid-command (the node went away): it may have run or not.
            r.status, r.error = (UNKNOWN if e.code in ("unavailable", "not_found") else FAILED), _err(e.code, e.message)
        finally:
            r.duration_ms = int((loop.time() - t0) * 1000)

    async def _collect(self, sb: Sandbox) -> tuple[bool, Any, dict | None]:
        try:
            st = await sb.stat(self.result_path)
        except DSecError as e:
            if e.code == "not_found":
                return False, None, _err("result_error", f"the command exited 0 but wrote no {self.result_path}")
            return False, None, _err(e.code, e.message)
        if st.type != "file":
            return False, None, _err("result_error", f"{self.result_path} is a {st.type}, not a file")
        if st.size > self.max_result_bytes:
            return False, None, _err("result_error", f"{self.result_path} is {st.size} bytes, over {self.max_result_bytes}")
        try:
            data = await sb.read_file(self.result_path, length=self.max_result_bytes)
            return True, json.loads(data), None
        except DSecError as e:
            return False, None, _err(e.code, e.message)
        except ValueError as e:
            return False, None, _err("result_error", f"{self.result_path} is not JSON: {e}")

    async def _stop(self, r: RolloutResult, sb: Sandbox) -> None:
        if r.cleanup_status:
            return
        self._cleanup_pending += 1
        try:
            await asyncio.wait_for(sb.stop(), 60)
            r.cleanup_status = "succeeded"
        except (DSecError, asyncio.TimeoutError) as e:
            r.cleanup_status = "failed"
            if r.error is None:
                code = e.code if isinstance(e, DSecError) else "timeout"
                r.error = _err(code, f"stopping sandbox {sb.id} failed (the run's sweep retries it)")
        finally:
            self._cleanup_pending -= 1

    # -- export -----------------------------------------------------------------------

    def export_jsonl(self, path: str, overwrite: bool = False) -> None:
        """Write the run's metadata line, then one line per input (the
        payloads are not written). Refuses to overwrite unless asked."""
        summary = self._summary or self._snapshot_summary()
        mode = "w" if overwrite else "x"
        with open(path, mode) as f:
            meta = dict(self.meta, counts=summary.counts, leftover=summary.leftover, elapsed_s=round(summary.elapsed_s, 3))
            f.write(json.dumps(meta) + "\n")
            for r in summary.results:
                f.write(json.dumps({"type": "result", **r.to_dict()}) + "\n")


def _tail(b: bytes, n: int) -> tuple[str, bool]:
    if len(b) <= n:
        return b.decode("utf-8", "replace"), False
    return b[-n:].decode("utf-8", "replace"), True


def read_results(path: str) -> tuple[dict, list[dict]]:
    """A run's export: its metadata and its result dicts."""
    meta, results = {}, []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            d = json.loads(line)
            if d.get("type") == "run":
                meta = d
            else:
                d.pop("type", None)
                results.append(d)
    return meta, results


def read_inputs(path: str) -> list[dict]:
    """Inputs from a JSON Lines file: one {"id": ..., "payload": ...} per line."""
    out = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError as e:
                    raise ValueError(f"{path}:{n}: not JSON: {e}") from None
    return out
