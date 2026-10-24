#!/bin/bash
# smoke.sh [IMAGE] [BACKENDS]: create one sandbox per backend, run python in
# it, check the output, stop it. Uses OPENDSEC_ADDR, OPENDSEC_TOKEN,
# OPENDSEC_PROJECT and OPENDSEC_CA from the environment. Exits non-zero if
# any backend fails.
set -uo pipefail
img=${1:-root/py:3.12}
backends=${2:-container,microvm}
ctl=${OPENDSECCTL:-opendsecctl}
: "${OPENDSEC_ADDR:?set OPENDSEC_ADDR (and OPENDSEC_TOKEN, OPENDSEC_CA, OPENDSEC_PROJECT)}"
bad=0
for be in ${backends//,/ }; do
	t0=$(date +%s%N)
	out=$("$ctl" sandbox create -backend "$be" -image "$img" -ttl-idle 120 2>&1)
	id=$(sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' <<<"$out" | head -1)
	if [ -z "$id" ]; then
		echo "FAIL $be: create: $(tail -1 <<<"$out")"
		bad=1
		continue
	fi
	got=$("$ctl" exec "$id" python3 -c 'print(6*7)' 2>&1)
	"$ctl" sandbox stop "$id" >/dev/null 2>&1
	took=$(awk -v a="$t0" -v b="$(date +%s%N)" 'BEGIN {printf "%.2f", (b - a) / 1e9}')
	if [ "$got" = 42 ]; then
		echo "ok   $be on ${id%%.*} (${took}s)"
	else
		echo "FAIL $be on ${id%%.*}: python printed '$got'"
		bad=1
	fi
done
exit $bad
