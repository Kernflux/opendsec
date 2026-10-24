#!/bin/bash
# build-bundle.sh OUT_DIR [options]: build an offline install bundle (spec §38)
# for machines without internet access. Run it from the repository on a
# machine that has access and runs the same distribution, release and
# architecture as the target machines (e.g. Ubuntu 24.04, amd64): the
# packages are what its apt sources offer.
#
#   --image REF        a base image to carry (repeatable; default
#                      docker.io/library/python:3.12, imported as root/py:3.12)
#   --no-microvm       no guest kernel (container-only clusters)
#   --kernel FILE      the guest kernel to package (default: deps.lock's)
#   --no-monitoring    leave out the Prometheus and Alertmanager packages
#
# Produces OUT_DIR/opendsec-offline-<version>-<os>.tar.gz and its .sha256.
# Needs Go 1.27+, apt-get and apt-ftparchive (apt-utils), python3 with pip.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
die() { echo "build-bundle: $*" >&2; exit 1; }
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

out= images=() monitoring=1
while [ $# -gt 0 ]; do
	case $1 in
	--image) images+=("${2:?--image REF}"); shift ;;
	--no-microvm) export OPENDSEC_DEPS_SKIP=guest-kernel ;;
	--kernel) OPENDSEC_KERNEL=$(readlink -f "${2:?--kernel FILE}"); export OPENDSEC_KERNEL; shift ;;
	--no-monitoring) monitoring= ;;
	-h|--help) sed -n '2,16p' "$0"; exit 0 ;;
	-*) die "unknown option $1 (--help)" ;;
	*) [ -z "$out" ] || die "one OUT_DIR"; out=$1 ;;
	esac
	shift
done
[ -n "$out" ] || die "usage: build-bundle.sh OUT_DIR [options] (--help)"
[ ${#images[@]} -gt 0 ] || images=(docker.io/library/python:3.12)
for c in apt-get apt-cache apt-ftparchive dpkg python3 sha256sum; do command -v $c >/dev/null || die "needs $c"; done
. /etc/os-release
target=$ID-$VERSION_ID-$(dpkg --print-architecture)
mkdir -p "$out"
out=$(cd "$out" && pwd)

say "building"
export PATH=$PATH:/usr/local/go/bin
make -C "$REPO" build >/dev/null
ver=$("$REPO/bin/opendsecctl" version)
name=opendsec-offline-$ver-$target
B=$out/$name
rm -rf "$B"
mkdir -p "$B/release" "$B/images"

say "packaging release $ver"
ops=$(mktemp -d)
trap 'rm -rf "$ops"' EXIT
OPENDSEC_OPS=$ops "$REPO/deploy/prod/opendsecops" release "$REPO/bin" >/dev/null
cp -a "$ops/releases/$ver" "$B/release/$ver"

say "copying the scripts and docs"
cp -a "$REPO/deploy" "$B/deploy"
mkdir -p "$B/sdk/python" "$B/docs"
cp -a "$REPO/sdk/python/examples" "$B/sdk/python/"
cp "$REPO/README.md" "$REPO/LICENSE" "$REPO/NOTICE" "$B/"
cp "$REPO/docs/OPERATIONS.md" "$REPO/docs/USER_GUIDE.md" "$REPO/docs/E2B.md" "$B/docs/"
cp "$HERE/install.sh" "$B/install.sh"
cp "$HERE/README.md" "$B/OFFLINE.md"

say "downloading packages for $target"
# The edge's programs, NFS for the shared image store, and pip for the
# Python SDK's wheels.
pkgs="e2fsprogs erofs-utils nftables iproute2 util-linux nfs-common nfs-kernel-server python3-venv python3-pip"
[ -z "$monitoring" ] || pkgs="$pkgs prometheus prometheus-alertmanager prometheus-node-exporter"
# The whole dependency closure: what a target machine already has is not
# reinstalled (apt-local.sh), so a minimal one gets what it lacks.
# shellcheck disable=SC2086
closure=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks \
	--no-replaces --no-enhances $pkgs | grep -v -e '^ ' -e '^<' | sort -u)
mkdir -p "$B/debs"
skipped=
for p in $closure; do
	(cd "$B/debs" && apt-get download -qq "$p" >/dev/null 2>&1) || skipped="$skipped $p"
done
[ -z "$skipped" ] || echo "  not downloadable (virtual or foreign-architecture names):$skipped"
(cd "$B/debs" && apt-ftparchive packages . > Packages 2>/dev/null)
cp "$HERE/apt-local.sh" "$B/debs/"
echo "  $(ls "$B/debs"/*.deb | wc -l) packages, $(du -sh "$B/debs" | cut -f1)"

say "saving images"
for ref in "${images[@]}"; do
	f=$(basename "${ref%%@*}" | tr ':/' '--').tar
	"$REPO/bin/opendsecctl" image save "$ref" -out "$B/images/$f" 2>/dev/null
	printf '%s\t%s\n' "$f" "$ref" >> "$B/images/IMAGES"
	echo "  $ref -> images/$f ($(du -sh "$B/images/$f" | cut -f1))"
done

say "building the Python SDK's wheels"
python3 -m pip wheel -q -w "$B/wheels" "$REPO/sdk/python" ||
	die "pip wheel failed (python3 -m pip, with access to a package index)"

echo "$target" > "$B/TARGET"
(cd "$B" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
say "writing $name.tar.gz"
tar -C "$out" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$B"
echo "  $out/$name.tar.gz ($(du -sh "$out/$name.tar.gz" | cut -f1)); unpack it on the target and read OFFLINE.md"
