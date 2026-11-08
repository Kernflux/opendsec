"""Declarative image builds (spec §43.4): describe an image in code, the
cluster builds it.

    from opendsec import DSecClient, Template

    t = (Template()
         .from_registry("python:3.12-slim")      # or .from_image("root/py:3.12")
         .apt_install(["git"])
         .pip_install(["pandas", "requests"])
         .copy("./app", "/app")
         .env({"MODE": "prod"})
         .workdir("/app")
         .run("python -m compileall -q /app"))
    async with DSecClient() as client:
        info = await t.build(client, "root/me/myenv:v1")

A build starts a sandbox from the base, runs the steps in order and saves
the result as the image: its files (pack_diff, on a container backend), or
with ``start_cmd``, its running processes too (a memory snapshot on
microVM, which sandboxes then resume from in milliseconds). The image
counts against the project's image quota like any other; a failed step
stops the build (TemplateBuildError) and leaves no image behind, except
the base it imported.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .client import DSecClient, DSecRunArgs, Sandbox


class TemplateBuildError(Exception):
    """A build step failed: ``step`` describes it, ``result`` is its ShellResult."""

    def __init__(self, step: str, result):
        self.step, self.result = step, result
        tail = (result.stderr or result.stdout)[-2000:]
        super().__init__(f"step {step!r} failed (exit {result.exit_code}{', timed out' if result.timed_out else ''}):\n{tail}")


@dataclass
class _Step:
    kind: str  # run | copy | env | workdir
    arg: object
    desc: str


@dataclass
class Template:
    base_image: str = ""
    base_registry: str = ""
    registry_username: str = ""
    registry_password: str = ""
    steps: list[_Step] = field(default_factory=list)
    _env: dict[str, str] = field(default_factory=dict)
    _workdir: str = ""
    _start: str = ""
    _ready: str = ""
    _ready_timeout: float = 120

    # ---- base -------------------------------------------------------------------------

    def from_image(self, image: str) -> "Template":
        """Start from an image in the cluster's store (``<project>/<repo>:<tag>``)."""
        self.base_image, self.base_registry = image, ""
        return self

    def from_registry(self, ref: str, username: str = "", password: str = "") -> "Template":
        """Start from a registry's image (``python:3.12-slim``,
        ``ghcr.io/org/img:tag``); the cluster pulls it (import_image)."""
        self.base_registry, self.base_image = ref, ""
        self.registry_username, self.registry_password = username, password
        return self

    # ---- steps ------------------------------------------------------------------------

    def run(self, cmd: str | Iterable[str]) -> "Template":
        """Run a shell command (or several, in order) as root."""
        for c in [cmd] if isinstance(cmd, str) else cmd:
            self.steps.append(_Step("run", c, c))
        return self

    def pip_install(self, packages: Iterable[str]) -> "Template":
        pk = " ".join(shlex.quote(p) for p in packages)
        return self.run(f"python3 -m pip install --no-cache-dir {pk}")

    def apt_install(self, packages: Iterable[str]) -> "Template":
        pk = " ".join(shlex.quote(p) for p in packages)
        return self.run("export DEBIAN_FRONTEND=noninteractive && apt-get update -q && "
                        f"apt-get install -y -q --no-install-recommends {pk} && rm -rf /var/lib/apt/lists/*")

    def npm_install(self, packages: Iterable[str], global_: bool = True) -> "Template":
        pk = " ".join(shlex.quote(p) for p in packages)
        return self.run(f"npm install {'-g ' if global_ else ''}{pk}")

    def copy(self, src: str, dest: str) -> "Template":
        """Copy a local file or directory into the image at ``dest``."""
        self.steps.append(_Step("copy", (src, dest), f"copy {src} {dest}"))
        return self

    def env(self, env: dict[str, str]) -> "Template":
        """Set environment variables for the later steps and in the image."""
        self.steps.append(_Step("env", dict(env), "env " + " ".join(env)))
        return self

    def workdir(self, path: str) -> "Template":
        """Working directory for the later steps and in the image."""
        self.steps.append(_Step("workdir", path, f"workdir {path}"))
        return self

    def start_cmd(self, cmd: str, ready_cmd: str = "", ready_timeout: float = 120) -> "Template":
        """A process the image keeps running (a server, a kernel): the build
        starts it, waits until ``ready_cmd`` succeeds (e.g. ``curl -sf
        localhost:8888``), and saves memory too. microVM only."""
        self._start, self._ready, self._ready_timeout = cmd, ready_cmd, ready_timeout
        return self

    # ---- build ------------------------------------------------------------------------

    async def build(self, client: DSecClient, name: str, backend: str | None = None, cpu: float = 2,
                    memory_mb: int = 2048, disk_mb: int = 0, step_timeout: float = 1800,
                    log: Callable[[str], None] | None = print) -> object:
        """Build the image ``name`` (``<project>/<repo>:<tag>``, overwritten
        if it exists) and return its info. ``backend`` defaults to
        ``container`` (files only) or, with ``start_cmd``, ``microvm``."""
        say = log or (lambda _m: None)
        if not (self.base_image or self.base_registry):
            raise ValueError("a template needs from_image or from_registry")
        if backend is None:
            backend = "microvm" if self._start else "container"
        if self._start and backend != "microvm":
            raise ValueError("start_cmd needs the microvm backend (it saves memory)")
        base = self.base_image
        if self.base_registry:
            say(f"pulling {self.base_registry}")
            await client.import_image(name, self.base_registry, self.registry_username, self.registry_password,
                                      overwrite=True)
            base = name
        say(f"starting a {backend} sandbox from {base}")
        sb = await client.run_sandbox(DSecRunArgs(backend=backend, image=base, cpu_cores_limit=cpu,
                                                  memory_limit_mb=memory_mb, disk_mb=disk_mb,
                                                  network_rules={"*": True}))
        try:
            env, cwd = await self._run_steps(sb, step_timeout, say)
            if self._start:
                return await self._snapshot(sb, name, env, cwd, say)
            say(f"saving {name}")
            await sb.pack_diff(name, overwrite=True)
            if env or cwd:  # the image's defaults
                return await client.compose_image(name, [name], env=env, workdir=cwd, overwrite=True)
            return await client.get_image(name)
        finally:
            try:
                await sb.stop()
            except Exception:
                pass

    async def _run_steps(self, sb: Sandbox, timeout: float, say) -> tuple[dict[str, str], str]:
        env: dict[str, str] = {}
        cwd = ""
        for i, st in enumerate(self.steps, 1):
            say(f"[{i}/{len(self.steps)}] {st.desc}")
            if st.kind == "env":
                env.update(st.arg)
            elif st.kind == "workdir":
                cwd = st.arg
                r = await sb.run_shell(f"mkdir -p {shlex.quote(cwd)}", timeout=60)
                if not r.ok:
                    raise TemplateBuildError(st.desc, r)
            elif st.kind == "copy":
                await _copy(sb, *st.arg)
            else:
                r = await sb.run_shell(st.arg, timeout=timeout, env=env, cwd=cwd or None)
                if not r.ok:
                    raise TemplateBuildError(st.desc, r)
        return env, cwd

    async def _snapshot(self, sb: Sandbox, name: str, env, cwd, say):
        say(f"starting: {self._start}")
        await sb.run_shell_background(self._start, session="start", env=env, cwd=cwd or None)
        if self._ready:
            deadline = time.monotonic() + self._ready_timeout
            while True:
                r = await sb.run_shell(self._ready, timeout=30, env=env, cwd=cwd or None)
                if r.ok:
                    break
                if time.monotonic() > deadline:
                    raise TemplateBuildError(f"ready: {self._ready}", r)
                await asyncio.sleep(0.5)
        say(f"saving {name} with memory")
        return await sb.create_snapshot(name, memory=True, overwrite=True)


async def _copy(sb: Sandbox, src: str, dest: str) -> None:
    """Copy a local file or tree into the sandbox, keeping modes."""
    if os.path.isfile(src):
        with open(src, "rb") as f:
            await _write(sb, dest, f.read(), os.stat(src).st_mode & 0o7777)
        return
    if not os.path.isdir(src):
        raise FileNotFoundError(src)
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target = dest if rel == "." else os.path.join(dest, rel)
        await sb.run_shell(f"mkdir -p {shlex.quote(target)}", timeout=60)
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.islink(p):
                link = os.readlink(p)
                await sb.run_shell(f"ln -sfn {shlex.quote(link)} {shlex.quote(os.path.join(target, fn))}", timeout=60)
                continue
            with open(p, "rb") as f:
                await _write(sb, os.path.join(target, fn), f.read(), os.stat(p).st_mode & 0o7777)


async def _write(sb: Sandbox, path: str, data: bytes, mode: int) -> None:
    chunk = 32 << 20  # under the 80 MB message limit
    await sb.write_file(path, data[:chunk], mode=mode)
    for off in range(chunk, len(data), chunk):
        await sb.write_file(path, data[off:off + chunk], append=True)
