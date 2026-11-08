"""Template builds (spec §43.4) against real container sandboxes with an
image store (`opendsecctl cluster up -runtime linux -image-store`). The
base image is a static busybox, imported from an OCI archive made here.
Skipped unless running as root with a static busybox at /usr/bin/busybox."""

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile

import pytest

from opendsec import DSecClient, DSecContainerRunArgs, Template, TemplateBuildError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPENDSECCTL = os.path.join(ROOT, "bin", "opendsecctl")
BUSYBOX = "/usr/bin/busybox"

pytestmark = pytest.mark.skipif(os.geteuid() != 0 or not os.path.exists(BUSYBOX),
                                reason="container runtime needs root; base image needs a static busybox")


def _busybox_archive(path: str) -> None:
    """An OCI layout tar of one layer: busybox and its applets."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as tf:
        for d in ("bin", "etc", "tmp", "root", "usr", "usr/bin"):
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode = tarfile.DIRTYPE, 0o1777 if d == "tmp" else 0o755
            tf.addfile(ti)
        tf.add(BUSYBOX, "bin/busybox")
        for applet in ("sh", "echo", "cat", "mkdir", "ln", "ls", "env", "pwd", "true", "rm", "sleep", "test"):
            ti = tarfile.TarInfo("bin/" + applet)
            ti.type, ti.linkname = tarfile.SYMTYPE, "busybox"
            tf.addfile(ti)
    gz = gzip.compress(layer.getvalue())
    diff_id = "sha256:" + hashlib.sha256(layer.getvalue()).hexdigest()
    blobs = {}

    def blob(b: bytes) -> dict:
        d = hashlib.sha256(b).hexdigest()
        blobs[d] = b
        return {"digest": "sha256:" + d, "size": len(b)}

    cfg = json.dumps({"architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/bin:/usr/bin"]},
                      "rootfs": {"type": "layers", "diff_ids": [diff_id]}}).encode()
    man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                      "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **blob(cfg)},
                      "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **blob(gz)}]}).encode()
    index = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                          **blob(man)}]}).encode()
    with tarfile.open(path, "w") as tf:
        for name, data in [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)] + \
                [(f"blobs/sha256/{d}", b) for d, b in blobs.items()]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


@pytest.fixture(scope="module")
def cluster():
    state, store = tempfile.mkdtemp(prefix="opendsec"), tempfile.mkdtemp(prefix="opendsec-store")
    archive = os.path.join(state, "busybox.tar")
    _busybox_archive(archive)
    proc = subprocess.Popen([OPENDSECCTL, "cluster", "up", "-sim-edges", "1", "-runtime", "linux", "-state-dir", state,
                             "-image-store", store, "-disk-reserve-mb", "64", "-log", "warn"],
                            stdout=subprocess.PIPE, text=True)
    env = None
    for line in proc.stdout:
        m = re.search(r"OPENDSEC_ADDR=(\S+) OPENDSEC_TOKEN=(\S+)", line)
        if m:
            env = {"addr": m.group(1), "token": m.group(2)}
            break
    assert env, "cluster did not start"
    out = subprocess.run([OPENDSECCTL, "image", "import", archive, "-as", "root/busybox:1", "-store", store,
                          "-addr", env["addr"], "-token", env["token"]], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    yield env
    proc.terminate()
    proc.wait(30)
    shutil.rmtree(state, ignore_errors=True)
    shutil.rmtree(store, ignore_errors=True)


async def test_template_build(cluster, tmp_path):
    app = tmp_path / "app"
    (app / "lib").mkdir(parents=True)
    (app / "main.sh").write_text("echo app ran\n")
    (app / "main.sh").chmod(0o755)
    (app / "lib" / "data.txt").write_text("data\n")
    t = (Template()
         .from_image("root/busybox:1")
         .run("mkdir -p /opt && echo built > /opt/marker")
         .copy(str(app), "/app")
         .env({"MODE": "prod"})
         .workdir("/app")
         .run('test "$MODE" = prod && test "$(pwd)" = /app'))
    async with DSecClient(cluster["addr"], cluster["token"], "root") as client:
        info = await t.build(client, "root/built:v1", cpu=1, memory_mb=256, log=None)
        assert info.env["MODE"] == "prod" and info.workdir == "/app"
        sb = await client.run_container(DSecContainerRunArgs(container_image="root/built:v1", memory_limit_mb=256))
        try:
            r = await sb.run_shell("cat /opt/marker lib/data.txt && ./main.sh && echo $MODE && pwd")
            assert r.ok, r.stderr
            assert r.stdout == "built\ndata\napp ran\nprod\n/app\n", r.stdout
        finally:
            await sb.stop()

        # A failing step stops the build and names the step.
        bad = Template().from_image("root/busybox:1").run("echo oops >&2; exit 3")
        with pytest.raises(TemplateBuildError) as ei:
            await bad.build(client, "root/bad:v1", cpu=1, memory_mb=256, log=None)
        assert ei.value.result.exit_code == 3 and "oops" in str(ei.value)
        names = [i.name for i in await client.list_images("root")]
        assert "root/bad:v1" not in names
