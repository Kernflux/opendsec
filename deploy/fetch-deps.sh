#!/bin/bash
# fetch-deps.sh OUT_DIR: fetch the runtime dependencies pinned in
# deploy/deps.lock into OUT_DIR/<path>, checking every sha256, and copy the
# lock file to OUT_DIR/deps.lock (spec §28.12). `opendsecctl fleet release
# pack -deps OUT_DIR` then puts them into the release.
#
# Downloads are cached in $OPENDSEC_DEPS_CACHE (default ~/.cache/opendsec-deps).
# $OPENDSEC_DEPS_MIRROR, if set, replaces https://github.com in URLs (for
# networks that cannot reach GitHub); the sha256 check is the same.
#
# $OPENDSEC_KERNEL=<file> takes the guest kernel from that file instead (one
# built with deploy/guest-kernel/build.sh: kernel builds are not bit for bit
# reproducible, so its sha256 cannot be pinned); the deps.lock copied into
# OUT_DIR records the file's own sha256. $OPENDSEC_DEPS_SKIP (names separated
# by spaces, e.g. "guest-kernel") leaves dependencies out, for nodes that
# never run microVMs; a name also skips its "<name>-*" entries (licenses).
set -euo pipefail
out=${1:?usage: fetch-deps.sh OUT_DIR}
here=$(cd "$(dirname "$0")" && pwd)
lock=${OPENDSEC_DEPS_LOCK:-$here/deps.lock}
cache=${OPENDSEC_DEPS_CACHE:-$HOME/.cache/opendsec-deps}
mkdir -p "$out" "$cache"

mode() { case $1 in bin/*) echo 0755 ;; *) echo 0644 ;; esac; } # path in the release

check() { # file sha256
	local got
	got=$(sha256sum "$1" | awk '{print $1}')
	[ "$got" = "$2" ] || { echo "sha256 of $1 is $got, deps.lock wants $2" >&2; return 1; }
}

while read -r name version src sum path; do
	case "$name" in ''|'#'*) continue ;; esac
	skip=
	for k in ${OPENDSEC_DEPS_SKIP:-}; do case $name in "$k" | "$k"-*) skip=1 ;; esac; done # with its license files
	[ -n "$skip" ] && { echo "$name skipped"; continue; }
	dst=$out/$path
	mkdir -p "$(dirname "$dst")"
	if [ "$name" = guest-kernel ] && [ -n "${OPENDSEC_KERNEL:-}" ]; then
		install -m 0644 "$OPENDSEC_KERNEL" "$dst"
		sum=$(sha256sum "$dst" | awk '{print $1}')
		echo "$name $version -> $path (from $OPENDSEC_KERNEL, sha256 $sum)"
		printf '%s %s file:%s %s %s\n' "$name" "$version-local" "$OPENDSEC_KERNEL" "$sum" "$path" >> "$out/deps.lock.local"
		continue
	fi
	echo "$name $version $src $sum $path" >> "$out/deps.lock.local"
	case "$src" in
	url:*)
		url=${src#url:}; member=
		case "$url" in *'#'*) member=${url#*#}; url=${url%%#*} ;; esac
		[ -n "${OPENDSEC_DEPS_MIRROR:-}" ] && url=${url/https:\/\/github.com/$OPENDSEC_DEPS_MIRROR}
		file=$cache/$(basename "$url")
		[ -s "$file" ] || { curl -fsSL --retry 3 -o "$file.part" "$url" && mv "$file.part" "$file"; }
		if [ -n "$member" ]; then
			tmp=$(mktemp -d)
			tar -C "$tmp" -xzf "$file" "$member"
			install -m "$(mode "$path")" "$tmp/$member" "$dst"
			rm -rf "$tmp"
		else
			install -m "$(mode "$path")" "$file" "$dst"
		fi
		;;
	file:*)
		f=${src#file:}
		case "$f" in /*) ;; *) f=$here/$f ;; esac
		install -m 0644 "$f" "$dst"
		;;
	*) echo "$name: unknown source $src" >&2; exit 1 ;;
	esac
	check "$dst" "$sum"
	echo "$name $version -> $path"
done < "$lock"
{ grep -E '^[[:space:]]*(#|$)' "$lock"; cat "$out/deps.lock.local" 2>/dev/null; } > "$out/deps.lock"
rm -f "$out/deps.lock.local"
