"""opendsec: async Python SDK for OpenDsec.

Mirrors the paper's example::

    client = DSecClient()
    await client.open()
    args = DSecContainerRunArgs(
        container_image="registry.../sphinx-9658:official",
        memory_limit_mb=4096, cpu_cores_limit=4,
        ttl_running_stop=300,   # idle timeout
        network_rules={"npm": False, "pypi": True},
        init_user="root",
    )
    sandbox = await client.run_container(args, timeout=120)
    await sandbox.stop()

The caller picks the backend explicitly (``run_container``, ``run_sandbox``
with ``backend=...``); the SDK does not abstract over backends.

Runtime operations (``run_shell``, streaming, files, HTTP) need a backend with
a runtime (``container``); ``sim`` sandboxes only support lifecycle calls.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import os
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Iterable

import grpc
from google.rpc import error_details_pb2, status_pb2

from ._pb.opendsec.v1 import cluster_pb2, opendsec_pb2, opendsec_pb2_grpc, iam_pb2, runtime_pb2, types_pb2

State = types_pb2.SandboxState

# Error reasons (stable strings shared with the Go services).
UNAUTHENTICATED = "unauthenticated"
FORBIDDEN = "forbidden"
NOT_FOUND = "not_found"
QUOTA_EXCEEDED = "quota_exceeded"
# The name every apiserver certificate carries (opendsecops certs), checked when
# the endpoint lists several apiservers by address.
APISERVER_NAME = "api.opendsec.internal"

RATE_LIMITED = "rate_limited"  # over the per-principal rate: back off and retry
NO_CAPACITY = "no_capacity"
INVALID = "invalid"
UNAVAILABLE = "unavailable"
TIMEOUT = "timeout"
INTERNAL = "internal"

# Calls failing with these may be repeated as they are, after a pause.
_RETRYABLE = frozenset({"no_capacity", "rate_limited", "unavailable", "timeout"})

_NEXT_STEPS = {
    "unauthenticated": "Check OPENDSEC_TOKEN: it is missing, mistyped, revoked or expired. Get a new token from your project's admin.",
    "forbidden": "Your token lacks a permission on this project (OPENDSEC_PROJECT), or the image's project. Ask a project admin for it.",
    "not_found": "The sandbox, image or project does not exist, or is not yours: check the name (images are <project>/<repo>:<tag>).",
    "quota_exceeded": "The project's quota is used up: stop sandboxes you no longer need or wait for others to end; a project admin can raise it.",
    "rate_limited": "Too many calls at once: slow down and retry.",
    "no_capacity": "The cluster has no room for this sandbox right now: retry later, or ask for fewer CPUs or less memory.",
    "invalid": "The request was refused as it is: read the message, fix the arguments and try again.",
    "unavailable": "An apiserver or the sandbox's node is unreachable (a restart?): retry in a few seconds.",
    "timeout": "The call took too long: retry; for long commands, raise the timeout.",
    "internal": "The cluster failed: retry; if it keeps failing, report it to the cluster's admin with the time and the sandbox id.",
}

_CODE_REASON = {
    grpc.StatusCode.UNAUTHENTICATED: UNAUTHENTICATED,
    grpc.StatusCode.PERMISSION_DENIED: FORBIDDEN,
    grpc.StatusCode.NOT_FOUND: NOT_FOUND,
    grpc.StatusCode.RESOURCE_EXHAUSTED: QUOTA_EXCEEDED,
    grpc.StatusCode.INVALID_ARGUMENT: INVALID,
    grpc.StatusCode.UNAVAILABLE: UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED: TIMEOUT,
}


class DSecError(Exception):
    """An API error. ``reason`` is one of the module-level reason constants
    (a stable machine-readable code); ``retryable`` tells whether the same
    call may be repeated as it is (not whether a task's work may be redone);
    ``next_steps`` is a short hint for people."""

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message

    @property
    def code(self) -> str:
        return self.reason

    @property
    def retryable(self) -> bool:
        return self.reason in _RETRYABLE

    @property
    def next_steps(self) -> str:
        return _NEXT_STEPS.get(self.reason, "")


def _reason_from_trailers(err: grpc.aio.AioRpcError) -> str | None:
    for key, value in err.trailing_metadata() or ():
        if key != "grpc-status-details-bin":
            continue
        st = status_pb2.Status.FromString(value)
        for d in st.details:
            info = error_details_pb2.ErrorInfo()
            if d.Unpack(info) and info.domain == "opendsec":
                return info.reason
    return None


def _wrap(err: grpc.aio.AioRpcError) -> DSecError:
    reason = _reason_from_trailers(err)
    if reason is None and err.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
        # Quota errors carry their reason; a bare RESOURCE_EXHAUSTED is
        # gRPC's own, a message over the size limit.
        reason = INVALID
    reason = reason or _CODE_REASON.get(err.code(), INTERNAL)
    return DSecError(reason, err.details() or "")


async def _call(coro):
    try:
        return await coro
    except grpc.aio.AioRpcError as e:
        raise _wrap(e) from None


class _Retry:
    """Rides out an unreachable edge or apiserver (a restart, a failover):
    ``UNAVAILABLE`` errors are retried with backoff for up to ``window``
    seconds since the last progress."""

    def __init__(self, window: float, hold: asyncio.Event | None = None):
        self.window = window
        self.hold = hold
        self.since: float | None = None
        self.delay = 0.1

    def progress(self) -> None:
        self.since, self.delay = None, 0.1

    async def wait(self, err: DSecError) -> bool:
        """Sleep before the next attempt; False if ``err`` is final."""
        if err.reason != UNAVAILABLE or self.window <= 0:
            return False
        if self.hold is not None and not self.hold.is_set():
            # Held (e.g. the sandbox's rollout is paused): a retry now would
            # resume the sandbox. Wait, then retry with a fresh window.
            await self.hold.wait()
            self.progress()
            return True
        now = asyncio.get_running_loop().time()
        if self.since is None:
            self.since = now
        left = self.since + self.window - now
        if left <= 0:
            return False
        await asyncio.sleep(min(self.delay, left))
        self.delay = min(self.delay * 2, 2.0)
        return True


def _new_lease() -> str:
    """A random idempotency key for a creation (26 lowercase base32 chars)."""
    return base64.b32encode(os.urandom(16)).decode().rstrip("=").lower()


async def _retrying(window: float, make, hold: asyncio.Event | None = None):
    """Await ``make()`` (a fresh call each attempt), retrying UNAVAILABLE
    (not while ``hold`` is cleared)."""
    r = _Retry(window, hold)
    while True:
        try:
            return await _call(make())
        except DSecError as e:
            if not await r.wait(e):
                raise


@dataclass
class ProcessEvent:
    """One event of a process stream: exactly one field is set."""

    started: int | None = None   # pid
    stdout: bytes | None = None
    stderr: bytes | None = None
    pty: bytes | None = None
    exit_code: int | None = None  # -1 when killed by a signal
    exit_status: str = ""


async def _stream_events(call):
    try:
        async for ev in call:
            kind = ev.WhichOneof("event")
            if kind == "started":
                yield ProcessEvent(started=ev.started)
            elif kind in ("stdout", "stderr", "pty"):
                yield ProcessEvent(**{kind: getattr(ev, kind)})
            elif kind == "exit":
                yield ProcessEvent(exit_code=ev.exit.exit_code, exit_status=ev.exit.status or ev.exit.error)
    except grpc.aio.AioRpcError as e:
        raise _wrap(e) from None


# ---- run arguments ------------------------------------------------------------------------


@dataclass
class DSecRunArgs:
    """Backend-independent sandbox request."""

    backend: str = "sim"
    image: str = ""
    cpu_cores_limit: float = 1.0
    memory_limit_mb: int = 2048
    gpus: int = 0
    gpu_mode: str = ""                       # "" | shared | exclusive
    disk_mb: int = 0                         # writable disk size; 0 = backend default
    ttl_running_stop: int = 0                # idle timeout (s); 0 = cluster default (1 h)
    ttl_max: int = 0                         # absolute lifetime cap (s); 0 = cluster default (1 day)
    network_rules: dict[str, bool] = field(default_factory=dict)
    init_user: str = "root"
    task_id: str = ""                        # RL job/task, for task-level actions
    qos: str = "LS"                          # LS | BE
    labels: dict[str, str] = field(default_factory=dict)
    project: str | None = None               # default: the client's project

    def to_spec(self) -> types_pb2.SandboxSpec:
        return types_pb2.SandboxSpec(
            backend=self.backend, image=self.image,
            resources=types_pb2.Resources(cpu_cores=self.cpu_cores_limit,
                                          memory_mb=self.memory_limit_mb, gpus=self.gpus,
                                          disk_mb=self.disk_mb),
            ttl_running_stop_s=self.ttl_running_stop, ttl_max_s=self.ttl_max,
            network_rules=self.network_rules, init_user=self.init_user, task_id=self.task_id,
            qos=self.qos, gpu_mode=self.gpu_mode, labels=self.labels)


@dataclass
class DSecContainerRunArgs(DSecRunArgs):
    """Arguments for ``run_container`` (field names follow the paper)."""

    container_image: str = ""
    backend: str = "container"

    def to_spec(self) -> types_pb2.SandboxSpec:
        spec = super().to_spec()
        spec.image = self.container_image or self.image
        return spec


# ---- runtime results -------------------------------------------------------------------------


@dataclass
class ShellResult:
    cmd_id: int
    exit_code: int
    stdout_bytes: bytes
    stderr_bytes: bytes
    done: bool = True
    timed_out: bool = False
    duration: float = 0.0
    truncated: bool = False
    dropped_bytes: int = 0  # output past the per-stream record limit, dropped

    @property
    def stdout(self) -> str:
        return self.stdout_bytes.decode("utf-8", "replace")

    @property
    def stderr(self) -> str:
        return self.stderr_bytes.decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return self.done and self.exit_code == 0 and not self.timed_out

    @classmethod
    def _from(cls, r) -> "ShellResult":
        return cls(cmd_id=r.cmd_id, exit_code=r.exit_code, stdout_bytes=r.stdout, stderr_bytes=r.stderr,
                   done=r.done, timed_out=r.timed_out, duration=r.duration_s, truncated=r.truncated,
                   dropped_bytes=r.dropped_bytes)


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


def _deadline(timeout: float | None, margin: float = 30.0) -> float | None:
    return None if not timeout else timeout + margin


# ---- sandbox handle -------------------------------------------------------------------------


class Sandbox:
    """Handle to one sandbox. ``info`` is the last-seen server-side record."""

    def __init__(self, client: "DSecClient", info: types_pb2.Sandbox):
        self._client = client
        self.info = info
        # While cleared, calls cut by the sandbox pausing wait to retry (a
        # retry would resume it): set by rollouts while they are paused.
        self.hold: asyncio.Event | None = None

    @property
    def id(self) -> str:
        return self.info.id

    @property
    def edge_id(self) -> str:
        return self.info.edge_id

    @property
    def state(self) -> str:
        return State.Name(self.info.state)

    def __repr__(self) -> str:
        return f"Sandbox({self.id}, {self.state})"

    async def _op(self, method) -> "Sandbox":
        # Retried while the edge or apiserver is unreachable (a restart).
        self.info = await self._retrying(lambda: method(types_pb2.SandboxRef(id=self.id)))
        return self

    async def refresh(self) -> "Sandbox":
        self.info = await self._retrying(lambda: self._client._need().GetSandbox(types_pb2.SandboxRef(id=self.id)))
        return self

    async def stop(self) -> "Sandbox":
        return await self._op(self._client._stub.StopSandbox)

    async def pause(self) -> "Sandbox":
        return await self._op(self._client._stub.PauseSandbox)

    async def resume(self) -> "Sandbox":
        return await self._op(self._client._stub.ResumeSandbox)

    async def update_network(self, rules: dict[str, bool], replace: bool = False) -> "Sandbox":
        """Change the network rules (merged into the current ones, or replacing
        them): rule set names, domains, IPv4 CIDRs or ``"*"``; ``True``
        allows, ``False`` takes back. Denials apply to new connections at once."""
        self.info = await _call(self._client._stub.UpdateNetwork(types_pb2.UpdateNetworkRequest(
            sandbox_id=self.id, rules=rules, replace=replace)))
        return self

    async def touch(self) -> "Sandbox":
        """Mark activity (resets the idle TTL); resumes a paused sandbox."""
        return await self._op(self._client._stub.TouchSandbox)

    # -- runtime (paper: chronus shell sessions behind aether) --

    def _stub(self):
        return self._client._need()

    def _retrying(self, make):
        return _retrying(self._client.retry_timeout, make, self.hold)

    def _exec_req(self, cmd, timeout, session, env, cwd, background=False, user=None):
        # The request id lets a retry find the command instead of running it twice.
        return runtime_pb2.ExecRequest(sandbox_id=self.id, session=session, cmd=cmd, timeout_s=timeout or 0,
                                       env=env or {}, cwd=cwd or "", background=background,
                                       request_id=uuid.uuid4().hex, user=user or "")

    async def run_shell(self, cmd: str, timeout: float | None = None, session: str = "default",
                        env: dict[str, str] | None = None, cwd: str | None = None,
                        user: str | None = None) -> ShellResult:
        """Run ``cmd`` in a persistent shell session (``cd``/``export`` persist
        between calls). ``timeout`` kills what the command started; the session
        survives. ``env``/``cwd`` apply to this command only. A lost connection
        (edge restart) is retried without running the command twice.

        ``user`` (a name, or ``"uid[:gid]"``) is the session's user when this
        call starts the session; a session keeps its user. Run an agent's
        commands in a session of an unprivileged user (e.g. ``"1000"``) and
        grading in another: the agent then cannot reach the other sessions'
        channels and records or change system files. Output past 64 MB per
        stream is dropped (``ShellResult.dropped_bytes``)."""
        req = self._exec_req(cmd, timeout, session, env, cwd, user=user)
        r = await self._retrying(lambda: self._stub().Exec(req, timeout=_deadline(timeout)))
        return ShellResult._from(r)

    async def run_shell_background(self, cmd: str, timeout: float | None = None, session: str = "default",
                                   env: dict[str, str] | None = None, cwd: str | None = None,
                                   user: str | None = None) -> int:
        """Start ``cmd`` and return its command id at once; fetch results with ``get_output``."""
        req = self._exec_req(cmd, timeout, session, env, cwd, background=True, user=user)
        r = await self._retrying(lambda: self._stub().Exec(req))
        return r.cmd_id

    async def exec(self, argv: Iterable[str], timeout: float | None = None, env: dict[str, str] | None = None,
                   cwd: str | None = None, user: str | None = None, session: str | None = None) -> ShellResult:
        """Run a command given as an argv list (no shell syntax: each argument
        reaches the program as it is, so untrusted values are safe) and wait
        for it. Runs in its own shell session (``session``), which keeps
        retries idempotent across a restarting node; ``timeout`` kills it
        (``timed_out`` in the result)."""
        argv = list(argv)
        if not argv:
            raise ValueError("exec needs a command")
        if session is None:  # a session keeps its user: one per user
            session = "exec" if not user else "exec-" + "".join(c if c.isalnum() else "_" for c in user)
        return await self.run_shell(shlex.join(argv), timeout=timeout, session=session, env=env, cwd=cwd, user=user)

    def start_process(self, cmd: str, args: Iterable[str] = (), env: dict[str, str] | None = None,
                      cwd: str = "", user: str = "", tag: str = "", stdin: bool = False):
        """Start a process outside shell sessions (the process API) and stream
        its events: ``started`` (pid), ``stdout``/``stderr`` chunks, ``exit``
        last. The process keeps running if the stream ends; reattach with
        connect_process. Output while no stream is attached is not kept: for
        commands whose output matters, use exec or run_shell."""
        req = runtime_pb2.StartProcessRequest(sandbox_id=self.id, cmd=cmd, args=list(args), env=env or {},
                                              cwd=cwd, user=user, tag=tag, stdin=stdin)
        return _stream_events(self._stub().StartProcess(req))

    def connect_process(self, pid: int = 0, tag: str = ""):
        """Attach to a running process's events (as start_process)."""
        return _stream_events(self._stub().ConnectProcess(runtime_pb2.ProcessRef(sandbox_id=self.id, pid=pid, tag=tag)))

    async def list_processes(self) -> list[runtime_pb2.ProcessInfo]:
        r = await _call(self._stub().ListProcesses(runtime_pb2.ProcessRef(sandbox_id=self.id)))
        return list(r.processes)

    async def send_process_input(self, data: bytes | str, pid: int = 0, tag: str = "") -> None:
        if isinstance(data, str):
            data = data.encode()
        await _call(self._stub().SendProcessInput(runtime_pb2.ProcessInput(sandbox_id=self.id, pid=pid, tag=tag, data=data)))

    async def close_process_stdin(self, pid: int = 0, tag: str = "") -> None:
        await _call(self._stub().CloseProcessStdin(runtime_pb2.ProcessRef(sandbox_id=self.id, pid=pid, tag=tag)))

    async def signal_process(self, signal: int = 15, pid: int = 0, tag: str = "") -> None:
        """Send ``signal`` (default SIGTERM) to the process's process group."""
        await _call(self._stub().SignalProcess(runtime_pb2.ProcessSignal(sandbox_id=self.id, pid=pid, tag=tag, signal=signal)))

    async def get_output(self, cmd_id: int, session: str = "default", wait: float = 0,
                         stdout_offset: int = 0, stderr_offset: int = 0) -> ShellResult:
        """Recorded output of a command (``done`` tells whether it finished)."""
        req = runtime_pb2.OutputRequest(sandbox_id=self.id, session=session, cmd_id=cmd_id, wait_s=wait,
                                        stdout_offset=stdout_offset, stderr_offset=stderr_offset)
        return ShellResult._from(await self._retrying(lambda: self._stub().GetOutput(req, timeout=_deadline(wait))))

    async def stream_shell(self, cmd: str, timeout: float | None = None, session: str = "default",
                           env: dict[str, str] | None = None, cwd: str | None = None, user: str | None = None):
        """Yield ``("stdout"|"stderr", bytes)`` chunks as they are produced, then
        ``("exit", ShellResult)`` (without output) once the command ends. A lost
        connection (edge restart) resumes the stream where it broke: the
        command keeps running in the sandbox and nothing is repeated or lost."""
        req = self._exec_req(cmd, timeout, session, env, cwd, user=user)
        loop = asyncio.get_running_loop()
        end = None if not timeout else loop.time() + timeout + 30
        retry = _Retry(self._client.retry_timeout)
        while True:
            left = None if end is None else max(end - loop.time(), 1)
            call = self._stub().ExecStream(req, timeout=left)
            try:
                async for ev in call:
                    retry.progress()
                    kind = ev.WhichOneof("event")
                    if kind == "stdout":
                        req.stdout_offset += len(ev.stdout)
                        yield kind, ev.stdout
                    elif kind == "stderr":
                        req.stderr_offset += len(ev.stderr)
                        yield kind, ev.stderr
                    elif kind == "exit":
                        yield "exit", ShellResult._from(ev.exit)
                        return
                return
            except grpc.aio.AioRpcError as e:
                err = _wrap(e)
                if not await retry.wait(err):
                    raise err from None
            finally:
                call.cancel()

    async def read_file(self, path: str, offset: int = 0, length: int = 0, session: str = "default") -> bytes:
        req = runtime_pb2.FileRequest(sandbox_id=self.id, session=session, path=path, offset=offset, length=length)
        return (await self._retrying(lambda: self._stub().ReadFile(req))).data

    async def write_file(self, path: str, data: bytes | str, mode: int = 0, append: bool = False,
                         session: str = "default") -> runtime_pb2.FileInfo:
        if isinstance(data, str):
            data = data.encode()
        req = runtime_pb2.WriteFileRequest(sandbox_id=self.id, session=session, path=path, data=data,
                                           mode=mode, append=append)
        if append:  # not idempotent: a retry could append twice
            return await _call(self._stub().WriteFile(req))
        return await self._retrying(lambda: self._stub().WriteFile(req))

    async def list_dir(self, path: str, session: str = "default") -> list[runtime_pb2.FileInfo]:
        req = runtime_pb2.FileRequest(sandbox_id=self.id, session=session, path=path)
        return list((await self._retrying(lambda: self._stub().ListDir(req))).entries)

    async def stat(self, path: str, session: str = "default") -> runtime_pb2.FileInfo:
        req = runtime_pb2.FileRequest(sandbox_id=self.id, session=session, path=path)
        return await self._retrying(lambda: self._stub().Stat(req))

    async def remove(self, path: str, recursive: bool = False, session: str = "default") -> None:
        req = runtime_pb2.FileRequest(sandbox_id=self.id, session=session, path=path, recursive=recursive)
        await _call(self._stub().Remove(req))

    async def http(self, url: str, method: str = "GET", headers: dict[str, str] | None = None,
                   body: bytes = b"", timeout: float = 30, session: str = "default") -> HttpResult:
        """HTTP request made from inside the sandbox (its network namespace)."""
        req = runtime_pb2.HttpRequest(sandbox_id=self.id, session=session, url=url, method=method,
                                      headers=headers or {}, body=body, timeout_s=timeout)
        r = await _call(self._stub().Http(req, timeout=_deadline(timeout)))
        return HttpResult(status=r.status, headers=dict(r.headers), body=r.body)

    async def pack_diff(self, image: str, scrub: Iterable[str] = (), overwrite: bool = False):
        """Snapshot this sandbox's writable layer as a new image ``image``
        (``<project>/<repo>:<tag>``), stacked on the image it was started from.
        Build residue (/tmp, caches, shell history) is dropped; ``scrub`` adds
        more paths. container-type backends only (microvm: create_snapshot).
        Returns the new image's info."""
        return await _call(self._stub().PackDiff(opendsec_pb2.PackDiffRequest(
            sandbox_id=self.id, image=image, scrub=list(scrub), overwrite=overwrite)))

    async def fork(self, count: int = 1, ttl_running_stop: int = 0, ttl_max: int = 0,
                   labels: dict[str, str] | None = None, task_id: str = "",
                   timeout: float | None = 600) -> list["Sandbox | DSecError"]:
        """Copy this running sandbox into ``count`` running sandboxes (up to
        256). This sandbox pauses briefly and keeps its id. Copies inherit its
        spec (``labels`` are added, ``task_id`` replaces the task) and start
        from its state at the fork: files, and memory on microvm. Results are
        in index order; failed copies are DSecError instances. Each copy
        counts against quota like any creation. A lost stream (an edge or
        apiserver restart) is retried without making copies twice."""
        req = opendsec_pb2.ForkSandboxRequest(sandbox_id=self.id, count=count, ttl_running_stop_s=ttl_running_stop,
                                          ttl_max_s=ttl_max, labels=labels or {}, task_id=task_id,
                                          request_id=_new_lease())
        return await self._client._batch(lambda: self._stub().ForkSandbox(req, timeout=timeout), req, count)

    async def create_snapshot(self, image: str, memory: bool = False, overwrite: bool = False):
        """Save this sandbox as image ``image`` (``<project>/<repo>:<tag>``),
        exactly as it is (unlike pack_diff nothing is scrubbed). With
        ``memory`` (microvm only), sandboxes created from the image resume
        from its memory. microvm requires ``memory=True``; for a files-only
        image build on container and use pack_diff. Returns the new image's info."""
        return await _call(self._stub().CreateSnapshot(opendsec_pb2.CreateSnapshotRequest(
            sandbox_id=self.id, image=image, memory=memory, overwrite=overwrite)))

    async def list_sessions(self) -> list[str]:
        r = await self._retrying(lambda: self._stub().ListSessions(runtime_pb2.SessionRef(sandbox_id=self.id)))
        return list(r.sessions)

    async def close_session(self, session: str) -> None:
        """End a session, killing every process it started."""
        await _call(self._stub().CloseSession(runtime_pb2.SessionRef(sandbox_id=self.id, session=session)))


# ---- client -----------------------------------------------------------------------------------


class DSecClient:
    """Async client. Defaults come from OPENDSEC_ADDR, OPENDSEC_TOKEN and OPENDSEC_PROJECT."""

    def __init__(self, endpoint: str | None = None, token: str | None = None,
                 project: str | None = None, ca_file: str | None = None,
                 server_name: str | None = None, retry_timeout: float = 60,
                 tls: bool | None = None):
        """``endpoint`` (or OPENDSEC_ADDR) is ``host:port``, or several apiservers
        as ``ip:port,ip:port`` (calls go to whichever are up).
        ``ca_file`` (or OPENDSEC_CA) enables TLS, trusting that CA certificate;
        ``tls`` (or OPENDSEC_TLS=1) enables it with the system's trusted CAs,
        for apiservers behind a public certificate.
        ``retry_timeout``: how long runtime calls (shell, streams, file reads)
        keep retrying while the sandbox's edge or the apiserver is unreachable,
        e.g. restarting; 0 disables retries."""
        self.endpoint = endpoint or os.environ.get("OPENDSEC_ADDR", "127.0.0.1:7100")
        self.token = token or os.environ.get("OPENDSEC_TOKEN", "")
        self.project = project or os.environ.get("OPENDSEC_PROJECT", "root")
        self.ca_file = ca_file or os.environ.get("OPENDSEC_CA") or None
        self.server_name = server_name
        self.retry_timeout = retry_timeout
        if tls is None:
            tls = os.environ.get("OPENDSEC_TLS", "").lower() in ("1", "true", "yes")
        self.tls = tls
        self._channel: grpc.aio.Channel | None = None
        self._stub: opendsec_pb2_grpc.DSecStub | None = None

    async def open(self) -> "DSecClient":
        if self._channel is None:
            # Messages up to 80 MB each way, as the servers allow: a 64 MB
            # file read, 16 MB of command output per call.
            options = [("grpc.max_receive_message_length", 80 << 20), ("grpc.max_send_message_length", 80 << 20),
                       # Reconnect quickly after an apiserver restart (gRPC's default backs off to 2 min).
                       ("grpc.initial_reconnect_backoff_ms", 100), ("grpc.max_reconnect_backoff_ms", 2000),
                       # Ping every 10 s: a connection to an apiserver that went
                       # away silently (network partition, host down) fails within
                       # ~15 s, and calls move to the others, instead of waiting for
                       # their deadlines. Servers allow pings every 5 s.
                       ("grpc.keepalive_time_ms", 10000), ("grpc.keepalive_timeout_ms", 5000),
                       ("grpc.keepalive_permit_without_calls", 1), ("grpc.http2.max_pings_without_data", 0)]
            target, server_name = self.endpoint, self.server_name
            addrs = [a.strip() for a in self.endpoint.split(",") if a.strip()]
            if len(addrs) > 1:
                # Several apiservers (spec §27.8): calls are spread over the
                # reachable ones and move off one that goes down. The
                # certificates of all apiservers carry APISERVER_NAME.
                target = "ipv4:" + ",".join(addrs)
                options.append(("grpc.lb_policy_name", "round_robin"))
                server_name = server_name or APISERVER_NAME
            if self.ca_file:
                with open(self.ca_file, "rb") as f:
                    creds = grpc.ssl_channel_credentials(root_certificates=f.read())
                if server_name:
                    options.append(("grpc.ssl_target_name_override", server_name))
                self._channel = grpc.aio.secure_channel(target, creds, options=options)
            elif self.tls:
                if server_name:
                    options.append(("grpc.ssl_target_name_override", server_name))
                self._channel = grpc.aio.secure_channel(target, grpc.ssl_channel_credentials(), options=options)
            else:
                # Plaintext: dev clusters only; production apiservers require TLS.
                self._channel = grpc.aio.insecure_channel(target, options=options)
            self._stub = opendsec_pb2_grpc.DSecStub(_AuthChannel(self._channel, self.token))
        return self

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = self._stub = None

    async def __aenter__(self) -> "DSecClient":
        return await self.open()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _need(self) -> opendsec_pb2_grpc.DSecStub:
        if self._stub is None:
            raise RuntimeError("call await client.open() first")
        return self._stub

    # -- creation --

    async def run_sandbox(self, args: DSecRunArgs, timeout: float | None = 120) -> Sandbox:
        """Create a sandbox; ``timeout`` bounds the whole creation (seconds).

        While the apiserver is unreachable (a restart, a failover) the call is
        retried for up to ``retry_timeout``. Each creation carries its own
        idempotency key, so a retry after a lost answer returns the sandbox
        the first attempt made instead of a second one (spec §27.5)."""
        req = opendsec_pb2.CreateSandboxRequest(project=args.project or self.project, spec=args.to_spec(),
                                            lease=_new_lease())
        loop = asyncio.get_running_loop()
        end = None if timeout is None else loop.time() + timeout
        r = _Retry(self.retry_timeout)
        while True:
            left = None if end is None else max(0.1, end - loop.time())
            try:
                return Sandbox(self, await _call(self._need().CreateSandbox(req, timeout=left)))
            except DSecError as e:
                if (end is not None and loop.time() >= end) or not await r.wait(e):
                    raise
                req.retry = True

    @property
    def rollouts(self):
        """Batches of inputs, each in a fresh sandbox (opendsec.rollout)."""
        from .rollout import Rollouts
        return Rollouts(self)

    def sandbox(self, args: DSecRunArgs, timeout: float | None = 120, keep_on_error: bool = False):
        """A sandbox for the length of an ``async with`` block, stopped when
        it ends, also on errors::

            async with client.sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12")) as sb:
                r = await sb.exec(["python3", "-c", "print(6*7)"])

        Without its own ``ttl_max`` the sandbox lives at most an hour, so a
        killed program leaves nothing for long. A failure to stop it never
        hides the block's own error (it is added as a note). With
        ``keep_on_error`` a sandbox whose block raised is left running (until
        its TTL) for debugging, and its id logged in the error."""
        return _SandboxScope(self, args, timeout, keep_on_error)

    async def run_container(self, args: DSecContainerRunArgs, timeout: float | None = 120) -> Sandbox:
        return await self.run_sandbox(args, timeout)

    async def run_sandboxes(self, args: DSecRunArgs, count: int,
                            timeout: float | None = 600) -> list[Sandbox | DSecError]:
        """Bulk-create ``count`` sandboxes (up to 32K per call). Results are in
        index order; failed items are DSecError instances."""
        req = opendsec_pb2.CreateSandboxesRequest(project=args.project or self.project,
                                              spec=args.to_spec(), count=count, request_id=_new_lease())
        return await self._batch(lambda: self._need().CreateSandboxes(req, timeout=timeout), req, count)

    async def _batch(self, make, req, count: int) -> list[Sandbox | DSecError]:
        """Collect a bulk creation's results. While the apiserver or edge is
        unreachable the call is repeated with ``req.retry`` set: the server
        finds what earlier attempts made by ``req.request_id`` and creates
        only the rest (needs a 0.11 cluster)."""
        out: list[Sandbox | DSecError | None] = [None] * count
        r = _Retry(self.retry_timeout)
        while True:
            try:
                async for x in make():
                    # A retry replays what earlier attempts made: only a
                    # result not seen before is progress, else a stream that
                    # keeps breaking after its replay would retry forever.
                    if out[x.index] is None:
                        r.progress()
                    out[x.index] = (Sandbox(self, x.sandbox) if not x.error_reason
                                    else DSecError(x.error_reason, x.error_message))
                break
            except grpc.aio.AioRpcError as e:
                err = _wrap(e)
                if not await r.wait(err):
                    raise err from None
                req.retry = True
        return [x if x is not None else DSecError(TIMEOUT, "no result") for x in out]

    async def run_containers(self, args: DSecContainerRunArgs, count: int,
                             timeout: float | None = 600) -> list[Sandbox | DSecError]:
        return await self.run_sandboxes(args, count, timeout)

    # -- queries --

    async def get_sandbox(self, sandbox_id: str) -> Sandbox:
        return Sandbox(self, await _call(self._need().GetSandbox(types_pb2.SandboxRef(id=sandbox_id))))

    async def list_sandboxes(self, task_id: str = "", include_ended: bool = False,
                             project: str | None = None) -> list[Sandbox]:
        f = types_pb2.SandboxFilter(project=project or self.project, task_id=task_id, include_ended=include_ended)
        resp = await _call(self._need().ListSandboxes(f))
        return [Sandbox(self, s) for s in resp.sandboxes]

    async def cluster_status(self) -> cluster_pb2.Snapshot:
        return await _call(self._need().ClusterStatus(types_pb2.Empty()))

    # -- task-level actions (RL preemption / job end) --

    async def _task(self, task_id: str, action, project: str | None) -> types_pb2.TaskActionResult:
        req = opendsec_pb2.TaskActionRequest(project=project or self.project, task_id=task_id, action=action)
        return await _call(self._need().ApplyTaskAction(req))

    async def pause_task(self, task_id: str, project: str | None = None):
        return await self._task(task_id, types_pb2.TASK_PAUSE, project)

    async def resume_task(self, task_id: str, project: str | None = None):
        return await self._task(task_id, types_pb2.TASK_RESUME, project)

    async def stop_task(self, task_id: str, project: str | None = None):
        return await self._task(task_id, types_pb2.TASK_STOP, project)

    # -- IAM management (same API for humans and agents) --

    async def whoami(self) -> str:
        return (await _call(self._need().WhoAmI(types_pb2.Empty()))).id

    async def create_project(self, parent: str, name: str, quota: dict[str, float] | None = None) -> iam_pb2.Project:
        return await _call(self._need().CreateProject(iam_pb2.CreateProjectRequest(parent=parent, name=name, quota=quota or {})))

    async def create_principal(self, project: str, principal_id: str, kind: str = "agent",
                               ttl: float = 0) -> str:
        """Create a principal in ``project``; returns its first token
        (lifetime ``ttl`` seconds, 0 = server default)."""
        r = await _call(self._need().CreatePrincipal(iam_pb2.CreatePrincipalRequest(
            project=project, id=principal_id, kind=kind, ttl_s=ttl)))
        return r.token

    async def create_token(self, principal: str | None = None, ttl: float = 0,
                           description: str = "") -> tuple[str, iam_pb2.TokenInfo]:
        """Issue a token for ``principal`` (default: yourself). Returns (token, info)."""
        principal = principal or await self.whoami()
        r = await _call(self._need().CreateToken(iam_pb2.CreateTokenRequest(
            principal=principal, ttl_s=ttl, description=description)))
        return r.token, r.info

    async def list_tokens(self, principal: str | None = None) -> list[iam_pb2.TokenInfo]:
        r = await _call(self._need().ListTokens(iam_pb2.ListTokensRequest(principal=principal or "")))
        return list(r.tokens)

    async def revoke_token(self, principal: str, token_id: str) -> None:
        """Revoke a token; it stops working on every apiserver within ~1s."""
        await _call(self._need().RevokeToken(iam_pb2.RevokeTokenRequest(principal=principal, token_id=token_id)))

    async def delete_principal(self, principal: str) -> None:
        await _call(self._need().DeletePrincipal(iam_pb2.DeletePrincipalRequest(principal=principal)))

    async def delete_project(self, project: str) -> None:
        await _call(self._need().DeleteProject(iam_pb2.DeleteProjectRequest(project=project)))

    async def grant(self, project: str, principal: str, perms: Iterable[str]) -> iam_pb2.Project:
        return await _call(self._need().Grant(iam_pb2.GrantRequest(project=project, principal=principal, perms=list(perms))))

    async def revoke(self, project: str, principal: str, perms: Iterable[str] = ()) -> iam_pb2.Project:
        return await _call(self._need().Revoke(iam_pb2.RevokeRequest(project=project, principal=principal, perms=list(perms))))

    async def set_quota(self, project: str, quota: dict[str, float]) -> iam_pb2.Project:
        return await _call(self._need().SetQuota(iam_pb2.SetQuotaRequest(project=project, quota=quota)))

    # -- shared image store --

    async def list_images(self, project: str | None = None):
        r = await _call(self._need().ListImages(opendsec_pb2.ListImagesRequest(project=project or self.project)))
        return list(r.images)

    async def get_image(self, name: str):
        return await _call(self._need().GetImage(opendsec_pb2.ImageRef(name=name)))

    async def compose_image(self, name: str, parts: Iterable[str], env: dict[str, str] | None = None,
                            workdir: str = "", user: str = "", overwrite: bool = False):
        """Stack images (base, workspace, toolkits...) into ``name`` without copying data."""
        return await _call(self._need().ComposeImage(opendsec_pb2.ComposeImageRequest(
            name=name, parts=list(parts), env=env or {}, workdir=workdir, user=user, overwrite=overwrite)))

    async def delete_image(self, name: str) -> None:
        await _call(self._need().DeleteImage(opendsec_pb2.ImageRef(name=name)))

    async def import_image(self, image: str, ref: str, username: str = "", password: str = "",
                           overwrite: bool = False, timeout: float = 1800):
        """Pull ``ref`` from a registry (``python:3.12-slim``,
        ``ghcr.io/org/img:tag``) into the image store as ``image``
        (``<project>/<repo>:<tag>``). The cluster pulls it; ``username`` and
        ``password`` log in to a private registry. Bounded by the cluster's
        image_import limits and the project's image quota. Returns the new
        image's info."""
        return await _call(self._need().ImportImage(opendsec_pb2.ImportImageRequest(
            image=image, ref=ref, username=username, password=password, overwrite=overwrite), timeout=timeout))

    async def get_project(self, project: str | None = None) -> iam_pb2.Project:
        return await _call(self._need().GetProject(iam_pb2.GetProjectRequest(project=project or self.project)))

    async def get_usage(self, project: str | None = None, start: str = "", end: str = "") -> iam_pb2.UsageReport:
        """Resource usage of a project and its subprojects per UTC day
        (``start``/``end``: ``YYYY-MM-DD``, inclusive); needs project.admin."""
        return await _call(self._need().GetUsage(iam_pb2.UsageRequest(project=project or self.project, **{"from": start}, to=end)))


class _SandboxScope:
    def __init__(self, client: "DSecClient", args: DSecRunArgs, timeout, keep_on_error: bool):
        if not args.ttl_max:
            args = dataclasses.replace(args, ttl_max=3600)
        self.client, self.args, self.timeout, self.keep = client, args, timeout, keep_on_error
        self.sb: Sandbox | None = None

    async def __aenter__(self) -> Sandbox:
        self.sb = await self.client.run_sandbox(self.args, timeout=self.timeout)
        return self.sb

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.sb is None:
            return
        if exc is not None and self.keep:
            _note(exc, f"sandbox {self.sb.id} kept for debugging until its ttl_max ({self.args.ttl_max} s)")
            return
        try:
            await self.sb.stop()
        except Exception as e:  # never hide the block's own error
            if exc is None:
                raise
            _note(exc, f"stopping sandbox {self.sb.id} failed too: {e}")


def _note(exc: BaseException, msg: str) -> None:
    if hasattr(exc, "add_note"):  # Python 3.11+
        exc.add_note(msg)
    else:
        import logging
        logging.getLogger("opendsec").warning("%s (while handling %r)", msg, exc)


class _AuthChannel:
    """Wraps an aio channel so every call carries the bearer token.

    (Call credentials require a secure channel in gRPC, so the token is sent
    as per-call metadata instead.)"""

    def __init__(self, channel: grpc.aio.Channel, token: str):
        self._ch = channel
        self._md = (("authorization", f"Bearer {token}"),)

    def _wrap(self, factory):
        def make(*a, **kw):
            mc = factory(*a, **kw)

            def call(request, *, timeout=None, metadata=None, **kw2):
                return mc(request, timeout=timeout, metadata=tuple(metadata or ()) + self._md, **kw2)
            return call
        return make

    def __getattr__(self, name):
        attr = getattr(self._ch, name)
        if name in ("unary_unary", "unary_stream", "stream_unary", "stream_stream"):
            return self._wrap(attr)
        return attr
