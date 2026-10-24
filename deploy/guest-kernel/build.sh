#!/bin/sh
# Builds the OpenDsec microVM guest kernel (SPEC §19.13): upstream Linux with
# Firecracker's CI guest config plus opendsec.config. Needs gcc, make, flex,
# bison, bc, libelf-dev, libssl-dev.
#
#   deploy/guest-kernel/build.sh            # -> ./vmlinux-6.1.167-opendsec
#   VERSION=6.1.167 WORK=/tmp/k OUT=/opt/opendsec/vm/vmlinux deploy/guest-kernel/build.sh
set -eu
VERSION=${VERSION:-6.1.167}
FC=${FC:-v1.17.0}
here=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$PWD/kbuild}
OUT=${OUT:-$PWD/vmlinux-$VERSION-opendsec}
mkdir -p "$WORK"
cd "$WORK"
[ -f "linux-$VERSION.tar.xz" ] || curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$VERSION.tar.xz"
[ -f "fc-$FC.config" ] || curl -fsSL -o "fc-$FC.config" \
	"https://raw.githubusercontent.com/firecracker-microvm/firecracker/$FC/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
rm -rf "linux-$VERSION"
tar xf "linux-$VERSION.tar.xz"
cd "linux-$VERSION"
cp "../fc-$FC.config" .config
scripts/kconfig/merge_config.sh -m .config "$here/opendsec.config" >/dev/null
make olddefconfig >/dev/null
# Every option asked for must have survived olddefconfig.
grep '^CONFIG_' "$here/opendsec.config" | while read -r opt; do
	grep -qx "$opt" .config || { echo "build.sh: $opt not set (dependency missing?)" >&2; exit 1; }
done
make -j"$(nproc)" vmlinux >/dev/null
cp vmlinux "$OUT"
cp .config "$OUT.config" # part of the corresponding source (SOURCE.md)
echo "$OUT"
