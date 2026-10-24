// Acceptance check of the E2B gateway with E2B's JS SDK (spec §37), the
// counterpart of e2b_sdk_check.py. Run with E2B_API_URL, E2B_SANDBOX_URL and
// E2B_API_KEY set to the gateway and an OpenDsec token, from a directory where
// `npm install e2b` was run. With CI_TEMPLATE set it also checks the code
// interpreter SDK (@e2b/code-interpreter) on that template. Prints
// "OK <n> checks" on success.
import { CommandExitError, NotFoundError, Sandbox } from 'e2b'

let checks = 0
function check(cond, what) {
  if (!cond) throw new Error(what)
  checks++
}

const sbx = await Sandbox.create({ timeoutMs: 120_000, envs: { FOO: 'bar' }, metadata: { suite: 'e2b-js-check' } })
try {
  // Commands.
  let r = await sbx.commands.run('echo hello; echo err >&2; echo $FOO')
  check(r.exitCode === 0 && r.stdout === 'hello\nbar\n' && r.stderr === 'err\n', `run: ${JSON.stringify(r)}`)
  r = await sbx.commands.run('echo $X; pwd', { envs: { X: 'y' }, cwd: '/tmp' })
  check(r.stdout === 'y\n/tmp\n', `envs and cwd: ${JSON.stringify(r.stdout)}`)
  try {
    await sbx.commands.run('echo partial; exit 3')
    check(false, 'a failing command raised nothing')
  } catch (e) {
    check(e instanceof CommandExitError && e.exitCode === 3 && e.stdout === 'partial\n', `exit code: ${e}`)
  }
  const out = []
  await sbx.commands.run('for i in 1 2 3; do echo $i; sleep 0.1; done', { onStdout: (d) => out.push(d) })
  check(out.join('') === '1\n2\n3\n', `streamed output: ${JSON.stringify(out)}`)

  // Background process with stdin, listed, then finished by its input.
  let h = await sbx.commands.run('read x; echo got $x', { background: true, stdin: true })
  check((await sbx.commands.list()).some((p) => p.pid === h.pid), 'background process not listed')
  await sbx.commands.sendStdin(h.pid, 'it\n')
  const res = await h.wait()
  check(res.stdout === 'got it\n', `stdin: ${JSON.stringify(res.stdout)}`)
  h = await sbx.commands.run('sleep 60', { background: true })
  check(await sbx.commands.kill(h.pid), 'kill')

  // Files.
  await sbx.files.write('/tmp/e2b/a.txt', 'content')
  check((await sbx.files.read('/tmp/e2b/a.txt')) === 'content', 'write/read')
  const big = new Uint8Array(10_240_000).map((_, i) => i % 256) // 10 MB
  await sbx.files.write('/tmp/e2b/big.bin', big.buffer)
  const back = await sbx.files.read('/tmp/e2b/big.bin', { format: 'bytes' })
  check(back.length === big.length && back.every((b, i) => b === big[i]), '10 MB round trip')
  const names = (await sbx.files.list('/tmp/e2b')).map((e) => e.name).sort()
  check(names.join() === 'a.txt,big.bin', `list: ${names}`)
  check((await sbx.files.makeDir('/tmp/e2b/d')) === true, 'makeDir')
  check((await sbx.files.makeDir('/tmp/e2b/d')) === false, 'makeDir of an existing directory')
  await sbx.files.rename('/tmp/e2b/a.txt', '/tmp/e2b/d/b.txt')
  check((await sbx.files.exists('/tmp/e2b/d/b.txt')) && !(await sbx.files.exists('/tmp/e2b/a.txt')), 'rename')
  const info = await sbx.files.getInfo('/tmp/e2b/d')
  check(info.type === 'dir', `getInfo: ${JSON.stringify(info)}`)
  await sbx.files.remove('/tmp/e2b')
  check(!(await sbx.files.exists('/tmp/e2b')), 'remove')
  try {
    await sbx.files.read('/nonexistent')
    check(false, 'reading a missing file raised nothing')
  } catch (e) {
    check(e instanceof NotFoundError, `missing file: ${e}`)
  }

  // A terminal.
  const data = []
  const t = await sbx.pty.create({ rows: 24, cols: 80, onData: (d) => data.push(Buffer.from(d)) })
  await sbx.pty.sendInput(t.pid, new TextEncoder().encode('stty size; exit\n'))
  await t.wait()
  check(Buffer.concat(data).toString().includes('24 80'), `pty: ${Buffer.concat(data)}`)

  // Control: info, list, timeout.
  const si = await sbx.getInfo()
  check(si.sandboxId === sbx.sandboxId && si.metadata.suite === 'e2b-js-check', `info: ${JSON.stringify(si)}`)
  check((await Sandbox.list().nextItems()).some((s) => s.sandboxId === sbx.sandboxId), 'not listed')
  await sbx.setTimeout(300_000)
  check((await sbx.getInfo()).endAt.getTime() - Date.now() > 250_000, 'setTimeout')
  check(await sbx.isRunning(), 'isRunning')

  // Connecting from another client.
  const other = await Sandbox.connect(sbx.sandboxId)
  check((await other.commands.run('echo again')).stdout === 'again\n', 'connect')
} finally {
  await sbx.kill()
}
check(!(await Sandbox.list().nextItems()).some((s) => s.sandboxId === sbx.sandboxId), 'listed after kill')

if (process.env.CI_TEMPLATE) {
  const { Sandbox: CI } = await import('@e2b/code-interpreter')
  const t0 = Date.now()
  const ci = await CI.create(process.env.CI_TEMPLATE)
  const created = Date.now() - t0
  let first
  try {
    const t1 = Date.now()
    let ex = await ci.runCode('x = 6 * 7\nprint("hi")\nx')
    first = Date.now() - t1
    check(ex.text === '42' && ex.logs.stdout.join() === 'hi\n' && !ex.error, `runCode: ${JSON.stringify(ex)}`)
    check((await ci.runCode('y = x + 1\ny')).text === '43', 'state kept between runs')
    ex = await ci.runCode('1/0')
    check(ex.error?.name === 'ZeroDivisionError', `error: ${JSON.stringify(ex.error)}`)
    const lines = []
    await ci.runCode('import time\nfor i in range(3):\n    print(i, flush=True)\n    time.sleep(0.2)', { onStdout: (m) => lines.push(m.line) })
    check(lines.join('') === '0\n1\n2\n', `streamed stdout: ${JSON.stringify(lines)}`)
    ex = await ci.runCode('import pandas as pd\npd.DataFrame({"a": [1, 2], "b": [3, 4]})')
    check(ex.results[0]?.html?.includes('<table'), `pandas: ${JSON.stringify(ex.results)}`)
    ex = await ci.runCode('import matplotlib.pyplot as plt\nplt.plot([1, 2, 3], [1, 4, 9])\nplt.show()')
    check(ex.results.some((r) => r.png), `chart: ${ex.results.map((r) => r.formats())}`)
    const ctx = await ci.createCodeContext()
    check((await ci.runCode('x', { context: ctx })).error, 'a new context is fresh')
    ex = await ci.runCode('import os\nprint("env", os.environ["Z"])', { envs: { Z: 'z' } })
    check(ex.logs.stdout.join() === 'env z\n', 'runCode envs')
    check((await ci.commands.run('echo base')).stdout === 'base\n', 'commands next to the interpreter')
  } finally {
    await ci.kill()
  }
  console.log(`code interpreter: create ${created} ms, first runCode ${first} ms`)
}
console.log(`OK ${checks} checks`)
