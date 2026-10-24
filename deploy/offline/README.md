# 离线安装（不能访问外网的机器）

离线安装包里有安装 OpenDsec 需要的全部东西，目标机器不用访问外网（SPEC §38）：

| 目录 / 文件 | 内容 |
|---|---|
| `release/<版本>/` | 打包好的版本：全部程序、Firecracker、guest 内核、systemd 单元、许可证 |
| `debs/` | 本地软件源：e2fsprogs、erofs-utils、nftables、iproute2、NFS 的客户端和服务端、python3-venv 和 pip、Prometheus 和 Alertmanager，以及它们的依赖；`apt-local.sh` 从这里安装 |
| `images/` | 基础镜像（OCI 格式的 tar），`IMAGES` 列出每个文件对应的镜像 |
| `wheels/` | Python SDK 及其依赖的 wheel |
| `deploy/`、`docs/` | 部署脚本和文档 |
| `install.sh` | 单机安装 |
| `TARGET` | 适用的系统，例如 `ubuntu-24.04-amd64` |
| `SHA256SUMS` | 每个文件的校验和 |

安装包只适用于 `TARGET` 里的系统（发行版、版本、架构都要一致），因为软件包是按那个系统下载的。

## 制作（在能访问外网的机器上）

在与目标机器同样系统的机器上，从源码仓库执行：

```sh
deploy/offline/build-bundle.sh /data/bundles                   # 默认带 python:3.12
deploy/offline/build-bundle.sh /data/bundles --image docker.io/library/node:22 --image docker.io/library/python:3.12
```

得到 `opendsec-offline-<版本>-<系统>.tar.gz` 和它的 `.sha256`。拷到目标环境后先核对校验和。

- `--no-microvm`：不带 guest 内核，只跑容器。
- `--no-monitoring`：不带 Prometheus 和 Alertmanager。
- 客户自己的镜像：在能访问镜像仓库的机器上执行 `opendsecctl image save <镜像> -out x.tar`。`docker save` 导出的 tar 也能直接导入。

## 单机安装

```sh
tar xzf opendsec-offline-<版本>-<系统>.tar.gz && cd opendsec-offline-<版本>-<系统>
sudo ./install.sh                  # 有 /dev/kvm 时同时启用 microVM
sudo ./install.sh --no-microvm     # 只跑容器
sudo ./install.sh --uninstall      # 全部移除
```

它会校验安装包，然后：从 `debs/` 装好缺的软件包；安装、启动全部组件；导入 `images/` 里的第一个镜像，名为 `root/py:3.12`；建项目 `root/demo` 和它的调用方；各跑一个 sandbox 做检查。结束后：
- 管理员环境：`. /root/opendsec-ops/env`；
- 调用方环境：`. /root/opendsec-ops/demo.env`；
- Python SDK：没有 pip 时先 `sh debs/apt-local.sh python3-venv`，然后
  ```sh
  python3 -m venv ~/v && ~/v/bin/pip install --no-index --find-links wheels opendsec
  . /root/opendsec-ops/demo.env && ~/v/bin/python sdk/python/examples/quickstart.py
  ```

## 多机集群

步骤和 docs/OPERATIONS.md 相同，不同的只有下面几点。在运维机上解开安装包，然后：

1. **软件包**：设置 `export OPENDSEC_DEBS=<安装包>/debs`。之后 `opendsecops install`（edge 节点要的软件包）和 `opendsecops monitor`（Prometheus 等）都从这里安装，不访问外网。
2. **版本**：不用 `opendsecops release`（它要下载依赖），改为：
   ```sh
   <安装包>/deploy/prod/opendsecops release-add <安装包>/release/<版本>
   ```
   它会校验文件，并设为当前版本。之后照常执行 `certs`、`install all`、`start all`。交给 fleet 时，`fleet release push` 用的也是这个目录。
3. **共享存储（NFS）**：在存储服务器和各节点上，用安装包里的软件源装 NFS：
   ```sh
   sh <安装包>/debs/apt-local.sh nfs-kernel-server   # 存储服务器
   sh <安装包>/debs/apt-local.sh nfs-common          # apiserver 和 edge 节点
   ```
   挂载参数照 OPERATIONS.md。
4. **镜像**：
   ```sh
   opendsecctl image import <安装包>/images/python-3.12.tar -as root/py:3.12 -store /mnt/opendsec-images
   ```
   一个文件里有多个镜像时，用 `文件#名字` 选择，例如 `all.tar#python:3.12`。
5. **调用方**：把 `wheels/` 交给调用方，执行 `pip install --no-index --find-links wheels opendsec`。

## 升级

在能访问外网的机器上做新版本的安装包，拷进来后：

```sh
opendsecops release-add <新安装包>/release/<新版本>
opendsecctl fleet release push $OPENDSEC_OPS/releases/<新版本>
opendsecctl fleet rollout create -release <新版本>
```

新版本需要新的软件包时，CHANGELOG 会写明，用新安装包的 `debs/apt-local.sh` 安装。
