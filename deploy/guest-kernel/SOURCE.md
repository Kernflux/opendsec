# Guest kernel: license and corresponding source

OpenDsec releases ship a Linux guest kernel (`vm/vmlinux-6.1.167-opendsec`, the
build `6.1.167-opendsec.2` pinned in `deploy/deps.lock`). Linux is licensed
under the GNU General Public License version 2 with the Linux-syscall-note
exception (`COPYING`, `GPL-2.0`, `Linux-syscall-note` next to this file).

The kernel is built from **unmodified** upstream sources; no patches are
applied. Its complete corresponding source is:

| Part | Where |
|---|---|
| Kernel source | `linux-6.1.167.tar.xz` from https://cdn.kernel.org/pub/linux/kernel/v6.x/ (sha256 `2818053c07976ba4ed5f44deb0f5dc7ae7b0975d7918c313d48d8fe7c4e598cb`); also attached to the `guest-kernel-6.1.167-opendsec.2` release of this project |
| Configuration used | `vmlinux-6.1.167-opendsec.2.config` (also embedded in the binary: `CONFIG_IKCONFIG=y`, read it with `scripts/extract-ikconfig`) |
| Build scripts | `build.sh` and `opendsec.config` in this directory (Firecracker's CI guest config v1.17.0 plus `opendsec.config`, then `make vmlinux`) |
| Compiler | gcc 13.3.0 (Ubuntu 24.04) |

To rebuild: `OUT=vmlinux deploy/guest-kernel/build.sh`. Kernel builds are not
bit-for-bit reproducible (timestamps, build host), so a rebuild differs in its
sha256 but not in function.
