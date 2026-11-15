#!/bin/bash
# rehearse-upgrade.sh NEW OLD
#
# Rehearses a release on a test cluster managed by fleet, under load:
# OLD -> NEW, NEW -> OLD (the rollback), OLD -> NEW again. A release is
# tested only once its rollback is: what NEW writes (sandbox records, IAM
# state) is read by OLD after a rollback, also the one fleet does by itself
# for a node that fails to come up.
#
# Run it on the ops machine of the test cluster, which runs OLD; both
# releases are pushed to fleet already (opendsecctl fleet release push).
#
#   OPENDSEC_OPS    ops directory (admin.token, inventory); default /root/opendsec-ops
#   OPENDSEC_ADDR, OPENDSEC_CA   as for opendsecctl
#   OPENDSECCTL     opendsecctl to use; default: the one in PATH
#   CALLER_ENV      file setting a caller's OPENDSEC_TOKEN and OPENDSEC_PROJECT
#                   (sourced for the load); required
#   PYTHON          python with the opendsec SDK; default python3
#   LOAD            the load script; default sdk/python/examples/load_test.py
#   LOAD_S, LOAD_WORKERS   per phase; default 300 s, 4 workers
#   CHECK_NEW, CHECK_OLD   commands run once the cluster is on that release
#                   (sandboxes made on NEW that must survive OLD, feature
#                   checks, ...); a non-zero exit fails the rehearsal
#   SSH_KEY         key for the nodes' logs; default ~/.ssh/opendsec-ops
#
# It fails (exit 1) when a rollout does not end "done", a check fails, or
# the load has failures other than no_capacity (expected while an edge
# drains; compare their number with earlier rehearsals).
set -u
NEW=${1:?usage: rehearse-upgrade.sh NEW OLD}
OLD=${2:?usage: rehearse-upgrade.sh NEW OLD}
export OPENDSEC_OPS=${OPENDSEC_OPS:-/root/opendsec-ops}
: "${OPENDSEC_ADDR:?set OPENDSEC_ADDR}" "${CALLER_ENV:?set CALLER_ENV}"
CTL=${OPENDSECCTL:-opendsecctl}
PYTHON=${PYTHON:-python3}
LOAD=${LOAD:-$(cd "$(dirname "$0")/../.." && pwd)/sdk/python/examples/load_test.py}
LOAD_S=${LOAD_S:-300} LOAD_WORKERS=${LOAD_WORKERS:-4}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/opendsec-ops}
ADMIN=$(cat "$OPENDSEC_OPS/admin.token") || exit 1
LOGS=$(mktemp -d)
bad=0

step() { printf '\n######## %s  %s\n' "$(date +%T)" "$*"; }
fail() { echo "FAILED: $*"; bad=1; }
asadmin() { OPENDSEC_TOKEN=$ADMIN "$@"; }
caller() { ( . "$CALLER_ENV"; "$@" ); }

# phase TAG RELEASE: the load, a rollout to RELEASE during it, the outcome.
phase() {
	local tag=$1 rel=$2 s
	caller "$PYTHON" "$LOAD" "$LOAD_S" "$LOAD_WORKERS" > "$LOGS/load-$tag.log" 2>&1 &
	sleep 20
	asadmin "$CTL" fleet rollout create -release "$rel" -bake 20 -pause 10 2>&1 | tail -1
	for _ in $(seq 720); do
		s=$(asadmin "$CTL" fleet rollout status 2>&1 | head -1)
		case $s in *running*) sleep 5 ;; *) break ;; esac
	done
	echo "$s"
	case $s in *": done "*"release=$rel "*) ;; *) fail "rollout to $rel: $s"; asadmin "$CTL" fleet rollout status -steps | tail -8 ;; esac
	wait
	grep -vE '^FAIL' "$LOGS/load-$tag.log" | tail -1
	grep -E '^FAIL' "$LOGS/load-$tag.log" | grep -oE '(no_capacity|quota_exceeded|unavailable|timeout|internal|invalid|forbidden|not_found|unauthenticated|rate_limited|conflict)' | sort | uniq -c
	local other
	other=$(grep -E '^FAIL' "$LOGS/load-$tag.log" | grep -vc no_capacity)
	if [ "$other" != 0 ]; then
		fail "$other load failures other than no_capacity:"
		grep -E '^FAIL' "$LOGS/load-$tag.log" | grep -v no_capacity | head -5 | cut -c1-300
	fi
	if ! grep -q '^DONE' "$LOGS/load-$tag.log"; then
		fail "the load did not finish: $(tail -2 "$LOGS/load-$tag.log" | cut -c1-300)"
	fi
	local n
	n=$(asadmin "$CTL" fleet nodes | awk -v r="$rel" 'NR > 1 { for (i = 1; i <= NF; i++) if ($i == r) c[NR]++ } END { for (k in c) if (c[k] >= 2) n++; print n + 0 }')
	echo "nodes running $rel: $n of $(asadmin "$CTL" fleet nodes | awk 'NR > 1' | wc -l)"
}

check() { # WHAT COMMAND
	[ -n "$2" ] || return 0
	echo "--- check on $1: $2"
	bash -c "$2" || fail "check on $1"
}

T0=$(date '+%Y-%m-%d %H:%M:%S')
step "upgrade $OLD -> $NEW"
phase up "$NEW"
check "$NEW" "${CHECK_NEW:-}"
step "rollback $NEW -> $OLD"
phase back "$OLD"
check "$OLD" "${CHECK_OLD:-}"
step "upgrade again $OLD -> $NEW"
phase again "$NEW"
check "$NEW" "${CHECK_NEW:-}"

step "warnings and errors on the nodes since $T0"
grep -v '^ *#' "$OPENDSEC_OPS/inventory" | awk 'NF >= 2 { print $1, $2 }' | while read -r name addr; do
	ssh -n -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 "root@$addr" \
		"journalctl -u 'opendsec-*' -p warning --since '$T0' --no-pager | grep -v '^-- ' | grep -v 'refused a creation; trying another' | sed -E 's/^.*level=/level=/' | cut -c1-200 | sort | uniq -c | sort -rn | head -6" 2>&1 | sed "s/^/$name: /"
done
echo "logs: $LOGS"
if [ $bad = 0 ]; then echo "REHEARSAL ok"; else echo "REHEARSAL FAILED"; fi
exit $bad
