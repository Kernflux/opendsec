#!/bin/sh
# apt-local.sh PKG...: install packages from the package repository this
# script sits in (an offline bundle's debs/, spec §38), without internet
# access and without touching the machine's apt sources. Dependencies the
# machine already has are not reinstalled. Run as root.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ $# -gt 0 ] || { echo "usage: apt-local.sh PKG..." >&2; exit 2; }
lists=$(mktemp -d)
src=$(mktemp)
trap 'rm -rf "$lists" "$src"' EXIT
mkdir -p "$lists/partial"
chmod -R a+rX "$here"
echo "deb [trusted=yes] file:$here ./" > "$src"
# Only this repository, with package lists of its own.
o="-o Dir::Etc::SourceList=$src -o Dir::Etc::SourceParts=- -o Dir::State::Lists=$lists -o APT::Get::List-Cleanup=false -o APT::Sandbox::User=root"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
# shellcheck disable=SC2086
apt-get $o -qq update >/dev/null || { echo "apt-local.sh: reading the repository in $here failed" >&2; exit 1; }
# shellcheck disable=SC2086
apt-get $o install -y -qq --no-install-recommends "$@" >/dev/null
