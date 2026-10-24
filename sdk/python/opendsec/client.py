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
import os
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
    """An API error. ``reason`` is one of the module-level reason constants."""

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message


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

    def __init__(self, window: float):
        self.window = window
        self.since: float | None = None
        self.delay = 0.1

    def progress(self) -> None:
        self.since, self.delay = None, 0.1

    async def wait(self, err: DSecError) -> bool:
        """Sleep before the next attempt; False if ``err`` is final."""
        if err.reason != UNAVAILABLE or self.window <= 0:
            return False
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


async def _retrying(window: float, make):
    """Await ``make()`` (a fresh call each attempt), retrying UNAVAILABLE."""
    r = _Retry(window)
    while True:
        try:
            return await _call(make())
        except DSecError as e:
            if not await r.wait(e):
                raise


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
        return _retrying(self._client.retry_timeout, make)

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
        return await _call(self._stub().WriteFile(req))

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
                 server_name: str | None = None, retry_timeout: float = 60):
        """``endpoint`` (or OPENDSEC_ADDR) is ``host:port``, or several apiservers
        as ``ip:port,ip:port`` (calls go to whichever are up).
        ``ca_file`` (or OPENDSEC_CA) enables TLS, trusting that CA certificate.
        ``retry_timeout``: how long runtime calls (shell, streams, file reads)
        keep retrying while the sandbox's edge or the apiserver is unreachable,
        e.g. restarting; 0 disables retries."""
        self.endpoint = endpoint or os.environ.get("OPENDSEC_ADDR", "127.0.0.1:7100")
        self.token = token or os.environ.get("OPENDSEC_TOKEN", "")
        self.project = project or os.environ.get("OPENDSEC_PROJECT", "root")
        self.ca_file = ca_file or os.environ.get("OPENDSEC_CA") or None
        self.server_name = server_name
        self.retry_timeout = retry_timeout
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

    async def get_project(self, project: str | None = None) -> iam_pb2.Project:
        return await _call(self._need().GetProject(iam_pb2.GetProjectRequest(project=project or self.project)))

    async def get_usage(self, project: str | None = None, start: str = "", end: str = "") -> iam_pb2.UsageReport:
        """Resource usage of a project and its subprojects per UTC day
        (``start``/``end``: ``YYYY-MM-DD``, inclusive); needs project.admin."""
        return await _call(self._need().GetUsage(iam_pb2.UsageRequest(project=project or self.project, **{"from": start}, to=end)))


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
