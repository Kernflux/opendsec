"""Acceptance check of the E2B gateway with E2B's code interpreter SDK (SPEC §37.8).

Run against a gateway whose code-interpreter-v1 template is built by
deploy/e2b/build-code-interpreter.py. Prints "OK <n> checks" on success.
"""
import time
from e2b_code_interpreter import Sandbox

checks = 0
def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1

t0 = time.time()
sbx = Sandbox.create()
created = time.time() - t0
try:
    t1 = time.time()
    ex = sbx.run_code("x = 6 * 7\nprint(\"hi\")\nx")
    first = time.time() - t1
    check(ex.text == "42" and ex.logs.stdout == ["hi\n"] and ex.error is None, f"run_code: {ex}")
    check(sbx.run_code("y = x + 1\ny").text == "43", "state kept between runs")
    ex = sbx.run_code("1/0")
    check(ex.error is not None and ex.error.name == "ZeroDivisionError", f"error: {ex.error}")
    out = []
    sbx.run_code("import time\nfor i in range(3):\n    print(i, flush=True)\n    time.sleep(0.2)", on_stdout=lambda m: out.append(m.line))
    check("".join(out) == "0\n1\n2\n", f"streamed stdout: {out}")  # a print may arrive in parts
    ex = sbx.run_code("import pandas as pd\npd.DataFrame({\"a\": [1, 2], \"b\": [3, 4]})")
    check(ex.results and ex.results[0].html and "<table" in ex.results[0].html, f"pandas: {ex.results}")
    ex = sbx.run_code("import matplotlib.pyplot as plt\nplt.plot([1, 2, 3], [1, 4, 9])\nplt.show()")
    check(any(r.png for r in ex.results), f"chart: {[list(r.formats()) for r in ex.results]}")
    ctx = sbx.create_code_context()
    check(sbx.run_code("x", context=ctx).error is not None, "a new context is fresh")
    check(sbx.run_code("import os\nprint(\"env\", os.environ[\"Z\"])", envs={"Z": "z"}).logs.stdout == ["env z\n"], "run_code envs")
    check(sbx.commands.run("echo base").stdout == "base\n", "commands next to the interpreter")
finally:
    sbx.kill()
print(f"OK {checks} checks; create {created*1000:.0f} ms, first run_code {first*1000:.0f} ms")
