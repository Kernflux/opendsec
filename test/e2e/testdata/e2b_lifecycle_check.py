"""Acceptance check of E2B's lifecycle and network options through the gateway (spec §37.11).

Run with E2B_API_URL, E2B_SANDBOX_URL and E2B_API_KEY set to the gateway and
an OpenDsec token. NETWORK=1 adds the network checks, for edges with
networking and a way out to the internet.
Prints "OK <n> checks" on success.
"""
import json
import os
import time
import urllib.request

from e2b import CommandExitException, Sandbox

checks = 0


def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1


def raises(f, what):
    try:
        f()
    except Exception:
        check(True, what)
        return
    check(False, what + ": no error")


def state(sid):
    try:
        return Sandbox.get_info(sid).state.value
    except Exception:
        return "gone"


def wait_state(sid, want, limit=60):
    deadline = time.time() + limit
    while time.time() < deadline:
        if state(sid) == want:
            return True
        time.sleep(0.5)
    return False


def reach(s, url):
    try:
        s.commands.run(f"python3 -c \"import urllib.request; urllib.request.urlopen('{url}', timeout=5)\"", timeout=20)
        return True
    except CommandExitException:
        return False


def api(method, path, body):
    req = urllib.request.Request(os.environ["E2B_API_URL"] + path, data=json.dumps(body).encode(), method=method,
                                 headers={"X-API-KEY": os.environ["E2B_API_KEY"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.status


made = []
try:
    # autoPause: the timeout pauses; connect resumes with the state kept.
    s = Sandbox.create(timeout=3, lifecycle={"on_timeout": "pause", "auto_resume": True})
    made.append(s)
    s.files.write("/tmp/kept", "yes")
    check(s.get_info().lifecycle["on_timeout"] == "pause", f"lifecycle: {s.get_info().lifecycle}")
    check(wait_state(s.sandbox_id, "paused"), f"paused at the timeout: {state(s.sandbox_id)}")
    s2 = Sandbox.connect(s.sandbox_id, timeout=60)
    check(state(s.sandbox_id) == "running" and s2.files.read("/tmp/kept") == "yes", "connect resumes it")

    # Without it, the timeout kills.
    k = Sandbox.create(timeout=3)
    made.append(k)
    check(k.get_info().lifecycle["on_timeout"] == "kill", "default lifecycle")
    check(wait_state(k.sandbox_id, "gone"), "killed at the timeout")

    # Refresh keeps a sandbox alive at least that long.
    r = Sandbox.create(timeout=30)
    made.append(r)
    check(api("POST", f"/sandboxes/{r.sandbox_id}/refreshes", {"duration": 600}) == 204, "refresh")
    check(r.get_info().end_at.timestamp() - time.time() > 500, "refresh extends")

    # Filesystem-only pauses are refused, not silently made full.
    raises(lambda: r.pause(mode="filesystem"), "filesystem-only pause refused")
    raises(lambda: Sandbox.create(timeout=30, lifecycle={"on_timeout": {"action": "pause", "mode": "filesystem"}}),
           "filesystem-only auto-pause refused")

    if os.environ.get("NETWORK") == "1":
        d = Sandbox.create(timeout=120)
        made.append(d)
        check(reach(d, "https://example.com"), "internet by default")
        n = Sandbox.create(timeout=120, allow_internet_access=False)
        made.append(n)
        check(not reach(n, "https://example.com"), "allow_internet_access=False")
        check(n.get_info().allow_internet_access is False, "info: allow_internet_access")
        a = Sandbox.create(timeout=120, network={"deny_out": ["0.0.0.0/0"], "allow_out": ["pypi.org"]})
        made.append(a)
        check(reach(a, "https://pypi.org/simple/") and not reach(a, "https://example.com"), "allow_out over deny_out")
        check(a.get_info().network.get("allow_out") == ["pypi.org"], f"info: network {a.get_info().network}")
        a.update_network({})
        check(reach(a, "https://example.com"), "update_network replaces the rules")
        a.update_network({"deny_out": ["0.0.0.0/0"]})
        check(not reach(a, "https://example.com"), "update_network denies")
        raises(lambda: Sandbox.create(timeout=30, network={"deny_out": ["8.8.8.8/32"]}), "other denials refused")
finally:
    for s in made:
        try:
            s.kill()
        except Exception:
            pass
print(f"OK {checks} checks")
