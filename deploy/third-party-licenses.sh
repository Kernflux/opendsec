#!/bin/bash
# third-party-licenses.sh OUT_DIR: put the license files of every Go module
# compiled into OpenDsec's binaries, and of the Go standard library, into
# OUT_DIR/licenses/go/, with an index (OUT_DIR/licenses/go/README.md), and
# OpenDsec's own LICENSE and NOTICE into OUT_DIR/licenses/opendsec/.
# `opendsecops release` and the release workflow run it, so that every
# release carries the notices its binaries' licenses ask for (NOTICE).
# Fails if a module has no license file. Needs the Go toolchain and the
# module cache of the build.
set -euo pipefail
out=${1:?usage: third-party-licenses.sh OUT_DIR}/licenses/go
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."
rm -rf "$out"; mkdir -p "$out"
own=$(dirname "$out")/opendsec
rm -rf "$own"; mkdir -p "$own"
install -m 0644 LICENSE NOTICE "$own/"
mods=$(GOFLAGS=-mod=mod go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/... | sort -u)
{
	echo "# Go modules in OpenDsec's binaries"
	echo
	echo "Each directory holds the license (and NOTICE, if any) of one module, unmodified."
	echo "Modules under the Mozilla Public License 2.0 are used unmodified; their source"
	echo "is at https://proxy.golang.org/<module>/@v/<version>.zip and in the module's repository."
	echo
	echo "| Module | Version | License files |"
	echo "|---|---|---|"
} > "$out/README.md"
copy() { # NAME VERSION DIR
	local files
	files=$(cd "$3" && ls | grep -iE '^(LICEN[CS]E|COPYING|NOTICE|PATENTS)([._-].*)?$' || true)
	[ -n "$files" ] || { echo "third-party-licenses: $1 $2 has no license file in $3" >&2; return 1; }
	mkdir -p "$out/$1"
	for f in $files; do install -m 0644 "$3/$f" "$out/$1/$f"; done
	echo "| $1 | $2 | $(echo $files | tr ' ' ',') |" >> "$out/README.md"
}
copy go "$(go env GOVERSION)" "$(go env GOROOT)" # the standard library
while read -r path ver dir; do
	[ -n "$path" ] && copy "$path" "$ver" "$dir"
done <<<"$mods"
echo "licenses of $(($(grep -c '^| ' "$out/README.md") - 1)) Go modules -> $out"
