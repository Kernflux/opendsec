# 发布流程（维护者）

## 第一次公开前（一次性）

1. 定下仓库地址，把占位的 `OWNER` 换掉：
   ```sh
   git grep -l 'github.com/kernflux/opendsec' | xargs sed -i 's#github.com/kernflux/opendsec#github.com/<组织>/opendsec#g'
   make proto && go build ./... && go test ./...
   ```
   `make proto` 会重新生成 Go 和 Python 的桩代码：proto 里的 `go_package` 也变了。Python 桩要用 grpcio-tools 1.73.1 生成。

   再换掉版权人（目前是个人开发者，以后可能是公司）和商业授权联系方式的占位符（`NOTICE`、`CLA.md`、`CONTRIBUTING.md`、README，以及 `ee/`），确认不再有遗漏：
   ```sh
   git grep -l -e COPYRIGHT_HOLDER -e COMMERCIAL_CONTACT | xargs sed -i -e 's#COPYRIGHT_HOLDER#<版权人>#g' -e 's#COMMERCIAL_CONTACT#<邮箱>#g'
   git grep -n -e COPYRIGHT_HOLDER -e COMMERCIAL_CONTACT -e OWNER   # 应该没有输出
   ```
   `CLA.md` 和 `ee/LICENSE` 是草稿，公开前要请律师审定。
2. 发布 guest 内核：建一个名为 `guest-kernel-6.1.167-opendsec.2` 的 GitHub release。
   - **附件**（GPL-2.0 要求和二进制一起提供完整的对应源码，见 `deploy/guest-kernel/SOURCE.md`）：
     - `vmlinux-6.1.167-opendsec.2`：sha256 必须与 `deploy/deps.lock` 一致，即 `47974d99…`，就是现有测试机上 `/data/opendsec-vm` 里那份；
     - `vmlinux-6.1.167-opendsec.2.config`：从 `deploy/guest-kernel/` 复制；
     - `linux-6.1.167.tar.xz`：kernel.org 的原始源码，sha256 为 `2818053c…`；
     - `build.sh` 和 `opendsec.config`。
   - **说明文字**：贴上 `SOURCE.md` 的内容。
   - 如果改用 CI 或其他机器重新编译，内核不能逐字节复现，所以要同时更新 `deps.lock` 里内核的 sha256，并把新的 `.config` 一起提交（`build.sh` 会把它写到 `<输出>.config`）。
3. 对外仓库从一个干净的初始提交开始，不带内部开发历史，也不带内部文档 `docs/private/`（以及以后的企业版代码 `ee/`）：
   ```sh
   git checkout --orphan public
   git rm -r -q --cached --ignore-unmatch docs/private ee
   git commit -m "OpenDsec <版本>"
   git push <公开仓库> public:main
   ```

## 每个版本

1. 改 `VERSION` 和 `sdk/python/pyproject.toml` 里的版本号，在 `CHANGELOG.md` 里写好这个版本的条目（破坏性变更单独列出，规则见 `docs/VERSIONING.md`），然后提交。
2. `git tag v$(cat VERSION) && git push --tags`。
3. `.github/workflows/release.yml` 会自动完成：
   - 构建；
   - 按 `deps.lock` 取 firecracker、jailer、内核和它们的许可证文件，再收集编进程序的 Go 依赖的许可证（`deploy/third-party-licenses.sh`），一起放进发布包的 `licenses/`；
   - 打包，附件为 `opendsec-<版本>.tar.gz` 和 SDK wheel；
   - 发布 GitHub release。
4. 已有集群升级：先下载并解开 `opendsec-<版本>.tar.gz`，放到运维目录的 `releases/` 下，然后执行 `opendsecctl fleet release push` 和 `fleet rollout create`。详见 docs/OPERATIONS.md §6.2。
5. 示例验收（需要 KVM，CI 里跳过）：在有 KVM 的测试机上，对一个带 microvm 后端的集群运行 SDK 的三个示例，结果写进发布记录：
   ```sh
   export OPENDSEC_ADDR=... OPENDSEC_TOKEN=... OPENDSEC_PROJECT=... OPENDSEC_IMAGE=root/py:3.12
   cd sdk/python/examples && for ex in execute_code.py memory_fork.py task_pause.py; do python $ex || break; done
   # 或者作为测试：OPENDSEC_EXAMPLE_MICROVM=1 pytest tests/test_runtime.py -k memory_fork
   ```
   单机测试集群：`opendsecctl cluster up -sim-edges 1 -runtime linux -image-store DIR -microvm-kernel <vmlinux>`，再 `opendsecctl image import docker.io/library/python:3.12-slim -as root/py:3.12 -store DIR -addr ... -token ...`。容器部分（`execute_code.py`、`task_pause.py`）由 `sdk/python/tests/test_runtime.py` 在 CI 里跑。
6. **升级和回滚演练**（上生产之前，在一个由 fleet 管理的测试集群上，测试集群先运行生产当前的版本）：
   ```sh
   # 在测试集群的运维机上；新旧两个版本都已经 fleet release push
   CALLER_ENV=/root/caller.env PYTHON=/root/v/bin/python \
   CHECK_NEW="..." CHECK_OLD="..." deploy/prod/rehearse-upgrade.sh <新版本> <生产当前的版本>
   ```
   - 脚本在压测下依次做：升级、回滚、再升级，每一步检查 rollout 结果和压测失败的原因，最后列出各节点的告警。压测里只有 `no_capacity`（edge 排空期间）算正常。
   - **回滚必须演练**，不能只演练升级：新版本写下的数据（edge 上的 sandbox 记录、IAM 状态）在回滚后由旧版本读取，fleet 对启动失败的节点自动回退时也一样。2026-11-15 有一次就是这样发现的：旧版本读到记录里不认识的字段会删掉记录、清理 sandbox。
   - `CHECK_NEW` 里创建几个要跨回滚存活的 sandbox（运行中的、暂停的），并检查这个版本的新功能；`CHECK_OLD` 里用旧 SDK 确认它们还在、能恢复。
   - 给 sandbox 记录加字段时，`internal/edge` 的 `TestRecordReadableByEarlierReleases` 会失败并说明该怎么做。
7. **发布后检查**（生产 rollout 之后）：在能访问集群的机器上，用这个版本的 SDK 运行 `deploy/prod/checks/run.sh`（环境变量见脚本开头）。它以调用方身份检查：容器的 `/.opendsec/run` 受磁盘配额限制、io_uring 被拒绝、内网地址的网络规则被拒绝、DNS 突发查询不影响其他 sandbox；给了 `PUBLISH_TOKEN` 时再检查容器的 `pack_diff` 和 fork。另外用调用方手里的旧版 SDK 跑一遍 `sdk/python/examples/test_features.py`，确认旧 SDK 仍然可用。
8. SDK 发布到 PyPI（包名 `opendsec-sdk`，模块名 `opendsec`；`opendsec` 这个 PyPI 名字属于无关项目）：`python -m build --wheel sdk/python && twine upload dist/opendsec_sdk-*`。
