"""E2B's Template SDK against the OpenDsec E2B gateway (spec §43.4):
build a template from the gateway's "base" with files, env, workdir and
commands, start sandboxes from it by name, see a failing step reported,
delete it. Prints "OK ..." on success."""

import os
import sys
import tempfile

from e2b import Sandbox, Template

ctx = tempfile.mkdtemp()
os.makedirs(os.path.join(ctx, "app", "lib"))
with open(os.path.join(ctx, "app", "main.sh"), "w") as f:
    f.write("echo app ran\n")
os.chmod(os.path.join(ctx, "app", "main.sh"), 0o755)
with open(os.path.join(ctx, "app", "lib", "data.txt"), "w") as f:
    f.write("data\n")
with open(os.path.join(ctx, "single.txt"), "w") as f:
    f.write("single\n")

logs = []
t = (Template(file_context_path=ctx)
     .from_template("base")
     .copy("app", "/app/")
     .copy("single.txt", "/opt/single.txt")
     .set_envs({"MODE": "prod"})
     .set_workdir("/app")
     .run_cmd('echo built > /opt/marker && test "$MODE" = prod && test "$(pwd)" = /app && echo step-output'))
Template.build(t, "mytpl", cpu_count=1, memory_mb=256, on_build_logs=lambda e: logs.append(e.message))
assert any("step-output" in m for m in logs), logs
assert any("Template built" in m for m in logs), logs

sb = Sandbox.create("mytpl")
try:
    r = sb.commands.run("cat /opt/marker /opt/single.txt lib/data.txt && ./main.sh && echo $MODE && pwd")
    assert r.stdout == "built\nsingle\ndata\napp ran\nprod\n/app\n", repr(r.stdout)
finally:
    sb.kill()

# A rebuild with the files already uploaded, then a failing step.
Template.build(t, "mytpl", cpu_count=1, memory_mb=256)
bad = Template().from_template("base").run_cmd("echo oops >&2; exit 3")
try:
    Template.build(bad, "badtpl", cpu_count=1, memory_mb=256)
    sys.exit("a failing build succeeded")
except Exception as e:
    assert "exited with 3" in str(e) or "oops" in str(e), e

try:
    Sandbox.create("no-such-template")
    sys.exit("created from a template that does not exist")
except Exception:
    pass
print("OK template build, files, env, workdir, failure")
