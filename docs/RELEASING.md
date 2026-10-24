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
