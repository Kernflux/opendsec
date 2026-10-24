#!/bin/bash
# install.sh [options]: install a single-node OpenDsec on this machine from
# this offline bundle, without internet access (spec §38). It runs
# deploy/quickstart.sh on the bundle's release, packages and base image;
# the options are quickstart's (--no-microvm, --uninstall). Run as root.
# For a multi-node cluster, see OFFLINE.md.
set -euo pipefail
B=$(cd "$(dirname "$0")" && pwd)

. /etc/os-release
here=$ID-$VERSION_ID-$(dpkg --print-architecture 2>/dev/null || uname -m)
want=$(cat "$B/TARGET")
if [ "$here" != "$want" ]; then
	echo "install.sh: this bundle is for $want, this machine is $here: its packages may not install" >&2
	[ "${OPENDSEC_IGNORE_TARGET:-}" = 1 ] || { echo "install.sh: set OPENDSEC_IGNORE_TARGET=1 to try anyway" >&2; exit 1; }
fi
if [ "${1:-}" != --uninstall ]; then
	echo "==> checking the bundle's files"
	(cd "$B" && sha256sum -c --quiet SHA256SUMS) || { echo "install.sh: the bundle is damaged (SHA256SUMS)" >&2; exit 1; }
fi
export OPENDSEC_DEBS=$B/debs
export OPENDSEC_IMAGE=${OPENDSEC_IMAGE:-$B/images/$(head -1 "$B/images/IMAGES" | cut -f1)}
release=$(ls -d "$B"/release/*/ | head -1)
exec "$B/deploy/quickstart.sh" --release "$release" "$@"
