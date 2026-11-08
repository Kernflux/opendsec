"""python -m opendsec rollout ...: run a batch of inputs from the command
line (opendsec.rollout). Connection settings come from OPENDSEC_ADDR,
OPENDSEC_TOKEN, OPENDSEC_PROJECT and OPENDSEC_CA or OPENDSEC_TLS.

  python -m opendsec rollout run --image root/py:3.12 --inputs inputs.jsonl \\
      --concurrency 10 --result-path result.json --output results.jsonl -- python3 /app/rollout.py
  python -m opendsec rollout rerun --inputs inputs.jsonl --results results.jsonl --output results-2.jsonl
  python -m opendsec rollout cleanup <run-id>

The command gets each input's payload at $OPENDSEC_INPUT_PATH (JSON). A run
lives in this process: if it exits, inputs not started yet are not run;
what it started is found and stopped by `rollout cleanup <run-id>` (or
`opendsecctl task stop <run-id>`), and stops by itself after the run's time
budget anyway. Exit status: 0 all succeeded and cleaned up, 1 not all, 2
usage or connection errors, 130 interrupted.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .client import DSecClient, DSecError, DSecRunArgs
from .rollout import (CANCELLED, CREATE_FAILED, FAILED, RESULT_ERROR, TIMED_OUT, UNKNOWN, RolloutRun,
                      read_inputs, read_results)


class _Usage(Exception):
    """A usage error: exit status 2."""


def _rules(spec: str) -> dict[str, bool]:
    out = {}
    for part in filter(None, (p.strip() for p in spec.split(","))):
        out[part.lstrip("!")] = not part.startswith("!")
    return out


def _args(ns, meta: dict | None = None) -> DSecRunArgs:
    meta = meta or {}
    image = ns.image or meta.get("image")
    if not image:
        raise _Usage("--image is required")
    return DSecRunArgs(backend=ns.backend or meta.get("backend") or "microvm", image=image,
                       cpu_cores_limit=ns.cpu, memory_limit_mb=ns.memory_mb, disk_mb=ns.disk_mb,
                       network_rules=_rules(ns.net) if ns.net else {})


class _Reporter:
    """Progress to stderr: a redrawn line on a terminal, plain lines every
    10 s otherwise, or JSON lines."""

    def __init__(self, mode: str):
        if mode == "auto":
            mode = "text" if sys.stderr.isatty() else "plain"
        self.mode = mode

    async def run(self, run: RolloutRun) -> None:
        every = {"text": 0.5, "plain": 10, "json": 2}.get(self.mode)
        if every is None:
            return
        try:
            while not run.done:
                self.show(run)
                await asyncio.sleep(every)
        finally:
            self.show(run, last=True)

    def show(self, run: RolloutRun, last: bool = False) -> None:
        p = run.progress()
        if self.mode == "json":
            print(json.dumps({"type": "progress", **p.to_dict()}), file=sys.stderr, flush=True)
        elif self.mode == "text":
            print("\r\033[K" + p.line(), end="\n" if last else "", file=sys.stderr, flush=True)
        else:
            print(p.line(), file=sys.stderr, flush=True)


async def _run(ns, inputs, args, command, shell, attempt=1, source=""):
    async with DSecClient() as client:
        run = await client.rollouts.start(args, inputs, command=command, shell=shell, concurrency=ns.concurrency,
                                          execution_timeout_s=ns.execution_timeout, run_timeout_s=ns.run_timeout,
                                          result_path=ns.result_path, run_id=ns.run_id, attempt=attempt,
                                          source_run_id=source)
        print(f"run {run.run_id}: {len(inputs)} inputs, concurrency {ns.concurrency} "
              f"(clean up if interrupted: python -m opendsec rollout cleanup {run.run_id})", file=sys.stderr, flush=True)
        rep = asyncio.create_task(_Reporter(ns.progress).run(run))
        try:
            summary = await run.wait()
        except BaseException:  # Ctrl-C, or this task cancelled: end the run, keep what is known
            print(f"\ninterrupted: cancelling run {run.run_id} and stopping its sandboxes", file=sys.stderr, flush=True)
            summary = await asyncio.shield(run.cancel())
            run.export_jsonl(ns.output, overwrite=ns.overwrite)
            print(summary, file=sys.stderr)
            raise
        finally:
            await rep
        run.export_jsonl(ns.output, overwrite=ns.overwrite)
        print(summary, file=sys.stderr)
        for r in summary.failed()[:20]:
            e = r.error or {}
            print(f"  {r.input_id}: {r.status} {e.get('code', '')}: {e.get('message', '')}", file=sys.stderr)
        return 0 if summary.ok else 1


def _out_ok(ns) -> None:
    if os.path.exists(ns.output) and not ns.overwrite:
        raise _Usage(f"{ns.output} exists: choose another --output, or --overwrite")


def cmd_run(ns) -> int:
    if not ns.command:
        raise _Usage("give the command after --, e.g. -- python3 /app/rollout.py")
    _out_ok(ns)
    inputs = read_inputs(ns.inputs)
    command = " ".join(ns.command) if ns.shell else ns.command
    return asyncio.run(_run(ns, inputs, _args(ns), command, ns.shell))


def cmd_rerun(ns) -> int:
    _out_ok(ns)
    meta, results = read_results(ns.results)
    want = set(ns.status.split(","))
    redo = {r["input_id"]: r for r in results if r.get("status") in want}
    inputs = [i for i in read_inputs(ns.inputs) if str(i.get("id")) in redo]
    if not inputs:
        print("nothing to run again", file=sys.stderr)
        return 0
    command, shell = (ns.command or meta.get("command")), (ns.shell or meta.get("shell", False))
    if ns.command and shell:
        command = " ".join(ns.command)
    if not command:
        raise _Usage("the results file names no command (an episode run?): give it after --")
    for k in ("result_path", "execution_timeout"):
        if getattr(ns, k) is None:
            setattr(ns, k, meta.get(k if k == "result_path" else "execution_timeout_s"))
    attempt = max(r.get("attempt", 1) for r in redo.values()) + 1
    return asyncio.run(_run(ns, inputs, _args(ns, meta), command, shell, attempt, meta.get("run_id", "")))


def cmd_cleanup(ns) -> int:
    async def go():
        async with DSecClient() as client:
            left = await client.rollouts.cleanup(ns.run_id)
            if left:
                print(f"still not stopped: {' '.join(left)}", file=sys.stderr)
                return 1
            print(f"run {ns.run_id}: nothing left running", file=sys.stderr)
            return 0
    return asyncio.run(go())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m opendsec", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="group", required=True)
    ro = sub.add_parser("rollout", help="batches of inputs, each in a fresh sandbox").add_subparsers(dest="cmd", required=True)

    def common(sp, rerun=False):
        sp.add_argument("--image", required=not rerun, help="<project>/<repo>:<tag>")
        sp.add_argument("--backend", default=None if rerun else "microvm", help="microvm (default) or container")
        sp.add_argument("--cpu", type=float, default=1.0)
        sp.add_argument("--memory-mb", type=int, default=1024)
        sp.add_argument("--disk-mb", type=int, default=0)
        sp.add_argument("--net", default="", help='network rules, e.g. "pypi" or "*" (all), "!name" takes one back')
        sp.add_argument("--inputs", required=True, help="JSON Lines: {\"id\": ..., \"payload\": ...} per line")
        sp.add_argument("--output", required=True, help="results, JSON Lines")
        sp.add_argument("--overwrite", action="store_true", help="replace --output if it exists")
        sp.add_argument("--concurrency", type=int, default=8)
        sp.add_argument("--execution-timeout", type=float, default=None, help="seconds per command")
        sp.add_argument("--run-timeout", type=float, default=3600, help="seconds for the whole run")
        sp.add_argument("--result-path", default=None, help="a JSON file the command writes in the sandbox")
        sp.add_argument("--shell", action="store_true", help="the command is a shell command line")
        sp.add_argument("--run-id", default=None)
        sp.add_argument("--progress", default="auto", choices=["auto", "text", "plain", "json", "none"])
        sp.add_argument("command", nargs=argparse.REMAINDER, help="-- the command and its arguments")

    run = ro.add_parser("run", help="run a command once per input")
    common(run)
    run.set_defaults(fn=cmd_run)
    rerun = ro.add_parser("rerun", help="run again the inputs that did not succeed in a results file")
    common(rerun, rerun=True)
    rerun.add_argument("--results", required=True)
    rerun.add_argument("--status", default=",".join([FAILED, TIMED_OUT, RESULT_ERROR, CREATE_FAILED, CANCELLED, UNKNOWN]),
                       help="which statuses to run again (comma separated)")
    rerun.set_defaults(fn=cmd_rerun)
    cl = ro.add_parser("cleanup", help="stop every sandbox a run left")
    cl.add_argument("run_id")
    cl.set_defaults(fn=cmd_cleanup)

    ns = p.parse_args(argv)
    if getattr(ns, "command", None) and ns.command[0] == "--":
        ns.command = ns.command[1:]
    try:
        return ns.fn(ns)
    except KeyboardInterrupt:
        return 130
    except DSecError as e:
        print(f"OpenDsec error {e.code}: {e.message}\n{e.next_steps}", file=sys.stderr)
        return 2
    except (_Usage, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
