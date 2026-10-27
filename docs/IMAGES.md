# 镜像与快照

sandbox 从镜像启动。OpenDsec 的镜像存放在一个所有节点共享的**镜像库**里，由一组只读的层叠成。这一页说明镜像怎么命名、怎么导入、怎么从 sandbox 制作、快照怎么用，以及镜像库的要求和清理。

## 1. 命名

镜像名是 `<项目>/<名字>:<标签>`：

| 部分 | 规则 | 例子 |
|---|---|---|
| 项目 | 已存在的项目路径，每段 `[A-Za-z0-9][A-Za-z0-9._-]`，最长 64 | `root`、`root/rl` |
| 名字 | `[a-z0-9][a-z0-9._-]`，最长 128，只能小写 | `py`、`swe-4821` |
| 标签 | `[A-Za-z0-9_][A-Za-z0-9._-]`，最长 128；省略时为 `latest` | `3.12`、`v1`、`step3` |

镜像属于它名字里的项目，权限按这个项目判断：

| 操作 | 需要的权限 |
|---|---|
| 用镜像创建 sandbox、查看、列出 | 镜像所属项目上的 `layer.use` |
| 导入、组合、`pack_diff`、快照、删除 | 镜像所属项目上的 `layer.publish` |

不含 `/` 的名字（例如 `host`）是节点上的本地镜像（`edges[].images`），只用于开发和测试。

## 2. 导入

从镜像仓库或文件导入，用 `opendsecctl image import`。必须在**挂载了镜像库的机器上以 root 运行**（例如任意一台计算节点，或单机安装的那台机器）：命令直接把层写进镜像库，再通过 API 登记镜像。

```sh
# 公共仓库（Docker Hub 可以省略 docker.io/library/）
opendsecctl image import python:3.12 -as root/py:3.12 -store /mnt/opendsec-images

# 私有仓库：用 docker login 保存的凭据，或直接传入
echo "$HARBOR_TOKEN" | opendsecctl image import harbor.example.com/team/app:1.0 -as root/app:1.0 \
    -store /mnt/opendsec-images -username 'robot$ci' -password-stdin

# 不带 TLS 的内部仓库
opendsecctl image import 10.0.0.5:5000/base:1 -as root/base:1 -store /mnt/opendsec-images -plain-http

# 文件：docker save 的 tar、OCI layout 目录或 tar
docker save myimage:dev -o myimage.tar
opendsecctl image import ./myimage.tar -as root/rl/myimage:dev -store /mnt/opendsec-images
opendsecctl image import ./bundle.tar#app:1 -as root/app:1 -store /mnt/opendsec-images   # 文件里有多个镜像时
```

- 镜像的环境变量、工作目录、默认用户来自镜像本身的配置（Dockerfile 的 `ENV`、`WORKDIR`、`USER`）。`ENTRYPOINT` 和 `CMD` 不会自动运行：sandbox 启动后由你执行命令。
- 同样内容的层只存一份：导入第二个基于同一基础镜像的镜像时，已有的层直接复用。
- `-overwrite` 覆盖同名镜像；不加时同名镜像已存在会报错。
- 在单机安装的机器上，`. /root/opendsec-ops/env` 之后已经设置好 `OPENDSEC_IMAGE_STORE`，可以省略 `-store`。

**不能访问外网的机房**：在能上网的机器上保存成文件，拷过去再导入：

```sh
opendsecctl image save python:3.12 -out python-3.12.oci.tar      # 能上网的机器，不需要集群
opendsecctl image import ./python-3.12.oci.tar -as root/py:3.12 -store /mnt/opendsec-images
```

## 3. 组合

把几个镜像按顺序叠在一起，得到一个新镜像，**不复制任何数据**：

```sh
opendsecctl image compose root/rl/swe-4821:v1 \
    root/rl/python:3.12 \          # 底层：基础环境
    root/rl/django-ws:a1b2 \       # 中间：代码仓库和它的依赖
    root/tools/agent-kit:3         # 顶层：agent 用的工具
```

```python
await client.compose_image("root/rl/swe-4821:v1",
                           ["root/rl/python:3.12", "root/rl/django-ws:a1b2", "root/tools/agent-kit:3"],
                           env={"TASK": "4821"}, workdir="/srv/repo")
```

- 后面的镜像盖在前面的上面：同名文件以上层为准，上层删除的文件在新镜像里不存在。
- 环境变量按顺序合并，`env` 参数最后追加；`workdir`、`user` 不设置时沿用组成部分的。
- 适合强化学习里「基础环境 × 代码仓库 × 工具」的组合：每个部分只构建一次，任意组合都不占额外空间。

## 4. 从 sandbox 制作镜像

两种方式：

| | `pack_diff` | `create_snapshot` |
|---|---|---|
| 后端 | container、fncall | container、microvm |
| 保存什么 | sandbox 相对启动镜像的改动，作为新的一层叠在原镜像上 | sandbox 的完整状态；microVM 连同内存 |
| 清理 | 清掉 `/tmp`、`/var/tmp`、`/root/.cache`、shell 和 Python 的历史，可以追加 | 不清理，原样保存 |
| 用这个镜像创建的 sandbox | 全新启动，文件和保存时一样 | microVM：从快照恢复，进程从保存时的状态继续运行 |
| 能用在 | container 和 microVM | 同一种后端（container 的快照只含文件） |
| 典型用途 | 构建可复用的环境：装好依赖、编译好代码 | 预热：加载好模型、启动好服务；保存某一步的状态 |

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

- `scrub` 里是相对于 `/` 的 glob，不能含 `..`；不会沿符号链接往下匹配。
- 新镜像记录它的父镜像（`parent`），比父镜像多一层。
- microVM 不支持 `pack_diff`。需要只含文件的镜像时，用 container 构建，得到的镜像 microVM 也能用。

### 快照

```python
sb = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/py:3.12", memory_limit_mb=2048,
                                          network_rules={"pypi": True}))
await sb.run_shell("pip install -q numpy")
await sb.run_shell("(nohup python3 -c 'import numpy, http.server as h; h.test(h.SimpleHTTPRequestHandler, port=8000)' > /tmp/srv.log 2>&1 &)")
img = await sb.create_snapshot("root/rl/warm:v1", memory=True)
await sb.stop()

# 从快照创建：约 55 ms，加载好 numpy 的 HTTP 服务已经在 8000 端口运行
new = await client.run_sandbox(DSecRunArgs(backend="microvm", image="root/rl/warm:v1", memory_limit_mb=2048))
```

```sh
opendsecctl image snapshot $ID root/rl/warm:v1 -memory
```

- microVM 必须带内存（`memory=True` / `-memory`）。
- 用带内存的快照创建 sandbox 时，`memory_limit_mb` 必须和快照时一致。
- 快照只会放到运行时版本（Firecracker 版本）与制作时相同的节点上；集群升级 Firecracker 后，旧快照只能在还没升级的节点上使用，需要时重新制作。
- 每个从快照创建的 sandbox 都有自己的 hostname、machine-id 和随机数种子。
- 快照在 sandbox 所在节点上立即可用；同时在后台发布到镜像库，发布完成后其他节点才能使用（取决于镜像库的速度，几秒到几十秒）。在这之前，别的节点上的创建会等待发布完成。

### fork 与快照的关系

`fork` 也是先做一个快照，再从它创建副本，但快照不登记为镜像，副本创建完就不再需要它。要从同一状态多次、长期地创建，用 `create_snapshot`；只是一次性复制几份，用 `fork`。

## 5. 镜像库

### 要求

镜像库挂在所有 apiserver 和 edge 节点的同一路径（默认 `/mnt/opendsec-images`），配置里的 `image_store.root`。可以用 NFS、CephFS、JuiceFS 等共享文件系统：

- **必须关闭 root squash**：edge 以 root 写快照，apiserver 要删除它们。
- NFS 用 4.2 版本，挂载参数：`vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev`。
  - 4.1 也能用，但找不到稀疏文件里的空洞：跨节点使用内存快照时要按完整大小读一遍（实测慢一倍多）。
  - `lookupcache=positive`：不缓存「文件不存在」。不加的话，一个节点在镜像登记前查过它，之后最长约一分钟仍然找不到。
- 每个节点的 NFS 客户端标识必须不同（`deploy/node/install.sh` 会用 `/etc/machine-id` 设置），否则主机名相同的节点会被服务端当成同一个客户端。

挂好后先检查：

```sh
opendsecctl image store-check -store /mnt/opendsec-images
```

必需项全部为 `ok` 才能使用。逐项说明见[命令行参考](CLI.md#image-store-check-store-目录)。

### 目录结构

```
<root>/layers/<层 id>/rootfs/...      层的内容（overlay 格式）
<root>/layers/<层 id>/meta.json
<root>/images/<项目>/<名字>/<标签>.json   镜像的清单：层的列表和默认设置
<root>/snapshots/<id>/...             快照（磁盘、内存）
<root>/vmdisks/...                    microVM 用的镜像盘（开启 erofs_images 时为 EROFS）
```

不要手动修改这些文件；用 `opendsecctl image` 的命令操作。

### 节点如何使用镜像

- **容器**：在节点本地保存镜像层的副本（`layer_cache`，默认开启），首次使用时从镜像库复制，之后的容器直接叠这些本地层。镜像库中断时，运行中的容器不受影响。
- **microVM**：每个镜像在节点上做成一块只读的镜像盘。开启 `erofs_images` 时，镜像盘在镜像库里以 EROFS 格式构建一次，各节点复制使用；否则每个节点各自展平成 ext4。开启 `image_pmem` 时，同一镜像的 VM 共享宿主机的页缓存。
- 镜像库中断时，新建 sandbox、`pack_diff`、快照、跨节点 fork 会等待，直到恢复或调用超时；已经在运行的 microVM 不受影响。

## 6. 删除与清理

```sh
opendsecctl image delete root/rl/old:v1                      # 删除登记
opendsecctl image gc -store /mnt/opendsec-images -dry-run    # 看会删什么
opendsecctl image gc -store /mnt/opendsec-images             # 删除没有任何镜像引用的层和快照
```

- `image delete` 只删除镜像的登记，层可能还被别的镜像使用，不会马上删除。
- `image gc` 删除没有任何镜像引用的层和快照。比 `-grace`（默认 24 小时）新的不删，避免删掉正在导入或刚制作的数据。有引用读不出来（例如共享存储暂时出错）时，`image gc` 报错退出，什么都不删。
- 已经在运行的 sandbox 不受影响：容器用的是节点上的本地副本，microVM 用的是节点上的镜像盘。
- 节点上的本地副本和镜像盘缓存由 edge 自己回收。

建议定期（例如每天）在一台挂载了镜像库的机器上运行 `image gc`。
