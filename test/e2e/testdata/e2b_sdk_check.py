"""Acceptance check of the E2B gateway with E2B's own Python SDK (spec §37).

Run by TestE2BSDK with E2B_API_URL, E2B_SANDBOX_URL and E2B_API_KEY set to
the gateway and an OpenDsec token. Prints "OK <n> checks" on success.
"""
import time

from e2b import CommandExitException, NotFoundException, PtySize, Sandbox

checks = 0


def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1


sbx = Sandbox.create(timeout=120, envs={"FOO": "bar"}, metadata={"suite": "e2b-check"})
try:
    # Commands.
    r = sbx.commands.run("echo hello; echo err >&2; echo $FOO")
    check(r.exit_code == 0 and r.stdout == "hello\nbar\n" and r.stderr == "err\n", f"run: {r}")
    r = sbx.commands.run("echo $X; pwd", envs={"X": "y"}, cwd="/tmp")
    check(r.stdout == "y\n/tmp\n", f"envs and cwd: {r.stdout!r}")
    try:
        sbx.commands.run("echo partial; exit 3")
        check(False, "a failing command raised nothing")
    except CommandExitException as e:
        check(e.exit_code == 3 and e.stdout == "partial\n", f"exit code: {e.exit_code} {e.stdout!r}")
    out = []
    r = sbx.commands.run("for i in 1 2 3; do echo $i; sleep 0.1; done", on_stdout=out.append)
    check("".join(out) == "1\n2\n3\n", f"streamed output: {out}")

    # Background process with stdin, listed, then finished by its input.
    h = sbx.commands.run("read x; echo got $x", background=True, stdin=True)
    check(any(p.pid == h.pid for p in sbx.commands.list()), "background process not listed")
    sbx.commands.send_stdin(h.pid, "it\n")
    res = h.wait()
    check(res.stdout == "got it\n", f"stdin: {res.stdout!r}")
    h = sbx.commands.run("sleep 60", background=True)
    check(sbx.commands.kill(h.pid), "kill")

    # Files.
    sbx.files.write("/tmp/e2b/a.txt", "content")
    check(sbx.files.read("/tmp/e2b/a.txt") == "content", "write/read")
    big = bytes(range(256)) * 40000  # 10 MB
    sbx.files.write("/tmp/e2b/big.bin", big)
    check(sbx.files.read("/tmp/e2b/big.bin", format="bytes") == big, "10 MB round trip")
    names = sorted(e.name for e in sbx.files.list("/tmp/e2b"))
    check(names == ["a.txt", "big.bin"], f"list: {names}")
    check(sbx.files.make_dir("/tmp/e2b/d") is True, "make_dir")
    check(sbx.files.make_dir("/tmp/e2b/d") is False, "make_dir of an existing directory")
    sbx.files.rename("/tmp/e2b/a.txt", "/tmp/e2b/d/b.txt")
    check(sbx.files.exists("/tmp/e2b/d/b.txt") and not sbx.files.exists("/tmp/e2b/a.txt"), "rename")
    info = sbx.files.get_info("/tmp/e2b/d")
    check(info.type.value == "dir", f"get_info: {info}")
    sbx.files.remove("/tmp/e2b")
    check(not sbx.files.exists("/tmp/e2b"), "remove")
    try:
        sbx.files.read("/nonexistent")
        check(False, "reading a missing file raised nothing")
    except NotFoundException:
        checks += 1

    # A terminal.
    data = []
    t = sbx.pty.create(PtySize(rows=24, cols=80))
    sbx.pty.send_stdin(t.pid, b"stty size; exit\n")
    t.wait(on_pty=lambda d: data.append(d))
    check(b"24 80" in b"".join(data), f"pty: {b''.join(data)!r}")

    # Control: info, list, timeout.
    info = sbx.get_info()
    check(info.sandbox_id == sbx.sandbox_id and info.metadata.get("suite") == "e2b-check", f"info: {info}")
    listed = Sandbox.list().next_items()
    check(any(s.sandbox_id == sbx.sandbox_id for s in listed), "not listed")
    sbx.set_timeout(300)
    check(sbx.get_info().end_at.timestamp() - time.time() > 250, "set_timeout")
    check(sbx.is_running(), "is_running")

    # Connecting from another client.
    other = Sandbox.connect(sbx.sandbox_id)
    check(other.commands.run("echo again").stdout == "again\n", "connect")
finally:
    sbx.kill()

check(not any(s.sandbox_id == sbx.sandbox_id for s in Sandbox.list().next_items()), "listed after kill")
print(f"OK {checks} checks")
