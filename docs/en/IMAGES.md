# Images and snapshots

Sandboxes start from images. OpenDsec keeps images in an **image store** shared by every node, each image a stack of read-only layers. This page covers image names, importing, making images from sandboxes, using snapshots, and the store's requirements and cleanup.

## 1. Names

An image name is `<project>/<name>:<tag>`:

| Part | Rule | Example |
|---|---|---|
| Project | An existing project path; each segment `[A-Za-z0-9][A-Za-z0-9._-]`, up to 64 characters | `root`, `root/rl` |
| Name | `[a-z0-9][a-z0-9._-]`, up to 128 characters, lower case only | `py`, `swe-4821` |
| Tag | `[A-Za-z0-9_][A-Za-z0-9._-]`, up to 128 characters; `latest` when left out | `3.12`, `v1`, `step3` |

An image belongs to the project in its name, and permissions follow that project:

| Action | Permission |
|---|---|
| Create sandboxes from it, view, list | `layer.use` on the image's project |
| Import, compose, `pack_diff`, snapshot, delete | `layer.publish` on the image's project |

A name without `/` (such as `host`) is a node-local image (`edges[].images`), for development and tests only.

## 2. Importing

Import from a registry or a file with `opendsecctl image import`. Run it **as root on a machine that mounts the image store** (any compute node, or the single-node machine): it writes the layers into the store directly, then registers the image through the API.

```sh
# public registry (docker.io/library/ can be left out for Docker Hub)
opendsecctl image import python:3.12 -as root/py:3.12 -store /mnt/opendsec-images

# private registry: docker login's saved credentials, or pass them
echo "$HARBOR_TOKEN" | opendsecctl image import harbor.example.com/team/app:1.0 -as root/app:1.0 \
    -store /mnt/opendsec-images -username 'robot$ci' -password-stdin

# an internal registry without TLS
opendsecctl image import 10.0.0.5:5000/base:1 -as root/base:1 -store /mnt/opendsec-images -plain-http

# files: a docker save tar, an OCI layout directory or tar
docker save myimage:dev -o myimage.tar
opendsecctl image import ./myimage.tar -as root/rl/myimage:dev -store /mnt/opendsec-images
opendsecctl image import ./bundle.tar#app:1 -as root/app:1 -store /mnt/opendsec-images   # a file holding several images
```

- The image's environment variables, working directory and default user come from its own config (a Dockerfile's `ENV`, `WORKDIR`, `USER`). `ENTRYPOINT` and `CMD` do not run by themselves: you run commands once the sandbox is up.
- Identical layers are stored once: a second image on the same base reuses its layers.
- `-overwrite` replaces an image of the same name; without it, an existing name is an error.
- On a single-node install, `. /root/opendsec-ops/env` already sets `OPENDSEC_IMAGE_STORE`, so `-store` can be left out.

**Data centers without internet access**: save the image to a file on a connected machine, copy it over and import it:

```sh
opendsecctl image save python:3.12 -out python-3.12.oci.tar      # on a connected machine; no cluster needed
opendsecctl image import ./python-3.12.oci.tar -as root/py:3.12 -store /mnt/opendsec-images
```

## 3. Composing

Stack several images in order into a new one, **copying no data**:

```sh
opendsecctl image compose root/rl/swe-4821:v1 \
    root/rl/python:3.12 \          # bottom: the base environment
    root/rl/django-ws:a1b2 \       # middle: a repository and its dependencies
    root/tools/agent-kit:3         # top: the agent's tools
```

```python
await client.compose_image("root/rl/swe-4821:v1",
                           ["root/rl/python:3.12", "root/rl/django-ws:a1b2", "root/tools/agent-kit:3"],
                           env={"TASK": "4821"}, workdir="/srv/repo")
```

- Later images lie on top of earlier ones: a file in an upper layer wins, and a file an upper layer deleted is gone from the result.
- Environment variables are merged in order, with `env` applied last; `workdir` and `user` default to the parts'.
- It suits RL's "base environment × repository × tools" combinations: each part is built once, and any combination costs no extra space.

## 4. Making images from sandboxes

Two ways:

| | `pack_diff` | `create_snapshot` |
|---|---|---|
| Backends | container, fncall | container, microvm |
| Saves | The sandbox's changes against its image, as a new layer on top of that image | The sandbox's whole state; with memory on microVMs |
| Cleanup | Removes `/tmp`, `/var/tmp`, `/root/.cache`, shell and Python history, plus what you add | None; saved as is |
| A sandbox created from it | Starts fresh, with the files as saved | microVM: resumes from the snapshot with its processes running |
| Works for | container and microVM | the same backend (a container snapshot holds files only) |
| Typical use | Reusable environments: dependencies installed, code built | Warm starts: models loaded, services running; the state at one step |

### pack_diff

```python
sb = await client.run_container(DSecContainerRunArgs(
        container_image="root/rl/python:3.12", network_rules={"pypi": True, "github": True}))
await sb.run_shell("git clone https://github.com/org/repo /srv/repo && pip install -e /srv/repo")
img = await sb.pack_diff("root/rl/repo-env:v1", scrub=["srv/repo/.git"])
await sb.stop()
```

```sh
opendsecctl image pack $ID root/rl/repo-env:v1 -scrub srv/repo/.git
```

- `scrub` takes globs relative to `/`.
- The new image records its parent image (`parent`) and has one layer more.
- microVMs do not support `pack_diff`. For a files-only image, build on container: the image works on microVMs too.

### Snapshots

```python
sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12", memory_limit_mb=2048,
                                          network_rules={"pypi": True}))
await sb.run_shell("pip install -q numpy")
await sb.run_shell("(nohup python3 -c 'import numpy, http.server as h; h.test(h.SimpleHTTPRequestHandler, port=8000)' > /tmp/srv.log 2>&1 &)")
img = await sb.create_snapshot("root/rl/warm:v1", memory=True)
await sb.stop()

# created from the snapshot in about 55 ms: the HTTP server, numpy loaded, is already running on port 8000
new = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/warm:v1", memory_limit_mb=2048))
```

```sh
opendsecctl image snapshot $ID root/rl/warm:v1 -memory
```

- microVMs must include memory (`memory=True` / `-memory`).
- Sandboxes created from a snapshot with memory must use the snapshot's `memory_limit_mb`.
- A snapshot is placed only on nodes running the Firecracker version it was made with; after a cluster upgrades Firecracker, older snapshots work only on nodes not yet upgraded, so make them again when needed.
- Every sandbox created from a snapshot gets its own hostname, machine-id and random seed.
- A snapshot can be used at once on the node of its sandbox; meanwhile it is published to the image store in the background, and other nodes can use it once that finishes (seconds to tens of seconds, depending on the store). Creations on other nodes wait for it until then.

### Fork and snapshots

`fork` also takes a snapshot and creates the copies from it, but the snapshot is not registered as an image and is not needed once the copies exist. To create from one state many times over a long period, use `create_snapshot`; for a few copies now, use `fork`.

## 5. The image store

### Requirements

The store is mounted at the same path on every apiserver and edge node (default `/mnt/opendsec-images`), the config's `image_store.root`. NFS, CephFS, JuiceFS and other shared file systems work:

- **Root squash must be off**: edges write snapshots as root, and apiservers delete them.
- With NFS, use version 4.2 and these mount options: `vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev`.
  - 4.1 works too, but cannot find the holes of sparse files: using a memory snapshot on another node then reads it at its full size (more than twice as slow in our tests).
  - `lookupcache=positive` stops the client from caching "file not found". Without it, a node that looked for an image before it was registered could keep missing it for up to a minute.
- Every node needs a distinct NFS client identity (`deploy/node/install.sh` sets one from `/etc/machine-id`); otherwise the server takes nodes with the same host name for one client.

Check the mount before use:

```sh
opendsecctl image store-check -store /mnt/opendsec-images
```

Every required item must be `ok`. The items are listed in the [CLI reference](CLI.md#image-store-check-store-dir).

### Layout

```
<root>/layers/<layer id>/rootfs/...     layer contents (overlay format)
<root>/layers/<layer id>/meta.json
<root>/images/<project>/<name>/<tag>.json   image manifests: the layers and defaults
<root>/snapshots/<id>/...              snapshots (disks, memory)
<root>/vmdisks/...                     microVM image disks (EROFS with erofs_images)
```

Do not change these files by hand; use the `opendsecctl image` commands.

### How nodes use images

- **Containers**: each node keeps local copies of image layers (`layer_cache`, on by default), copied from the store on first use; later containers stack those local layers. Running containers are unaffected when the store is unreachable.
- **microVMs**: each image becomes a read-only image disk on the node. With `erofs_images`, the disk is built once in the store as EROFS and copied to each node; otherwise every node flattens it to ext4 itself. With `image_pmem`, VMs of one image share the host's page cache.
- While the store is unreachable, new creations, `pack_diff`, snapshots and cross-node forks wait until it is back or their calls time out; running microVMs are unaffected.

## 6. Deletion and cleanup

```sh
opendsecctl image delete root/rl/old:v1                      # delete the registration
opendsecctl image gc -store /mnt/opendsec-images -dry-run    # see what would go
opendsecctl image gc -store /mnt/opendsec-images             # remove layers and snapshots no image refers to
```

- `image delete` removes the image's registration only; its layers may still serve other images and are not deleted right away.
- `image gc` removes layers and snapshots no image refers to. Anything younger than `-grace` (default 24 hours) stays, so imports in progress and fresh snapshots are safe. If it cannot read a reference (the shared store failing for a moment, say), `image gc` stops with an error and removes nothing.
- Running sandboxes are unaffected: containers use the node's local copies, microVMs the node's image disks.
- Edges reclaim their own local copies and disk caches.

Run `image gc` regularly (daily, say) on a machine that mounts the store.
