#!/bin/bash
# run.sh: checks of a running cluster after a release, with the current SDK.
# They create a few sandboxes in the caller's project and stop them.
#
#   OPENDSEC_ADDR, OPENDSEC_CA, OPENDSEC_PROJECT, OPENDSEC_TOKEN   a caller's
#   OPENDSEC_IMAGE   an image with python3; default root/py:3.12
#   PUBLISH_TOKEN    a token with layer.publish on the project, for the
#                    pack_diff check; without it that check is skipped
#   PYTHON           python with the opendsec SDK of this release; default python3
#
# Exits non-zero if a check fails.
set -u
cd "$(dirname "$0")"
PYTHON=${PYTHON:-python3}
: "${OPENDSEC_ADDR:?}" "${OPENDSEC_TOKEN:?}" "${OPENDSEC_PROJECT:?}"
bad=0
for c in quota_check.py net_check.py; do
	echo "== $c"
	"$PYTHON" "$c" || bad=1
done
if [ -n "${PUBLISH_TOKEN:-}" ]; then
	echo "== packdiff_check.py"
	OPENDSEC_TOKEN=$PUBLISH_TOKEN "$PYTHON" packdiff_check.py || bad=1
else
	echo "== packdiff_check.py: skipped (no PUBLISH_TOKEN)"
fi
[ $bad = 0 ] && echo "CHECKS ok" || echo "CHECKS FAILED"
exit $bad
