#!/bin/sh
# opendsec-iam-backup: one IAM backup into /var/backups/opendsec, keeping
# OPENDSEC_BACKUP_KEEP_DAYS (default 14) days of them; run by
# opendsec-iam-backup.timer on every IAM node, so each holds its own copies.
# Writes a node_exporter textfile metric (opendsec_iam_backup_last_success_timestamp_seconds).
set -eu
. /etc/opendsec/ops.env
dir=${OPENDSEC_BACKUP_DIR:-/var/backups/opendsec}
keep=${OPENDSEC_BACKUP_KEEP_DAYS:-14}
textfile=${OPENDSEC_TEXTFILE_DIR:-/var/lib/prometheus/node-exporter}
f=$dir/iam-${OPENDSEC_NODE:-$(hostname -s)}-$(date -u +%Y%m%dT%H%M%SZ).json.gz
# OPENDSEC_ADDR: the load balancer, or every apiserver (comma separated, tried in turn).
done=
for a in $(echo "$OPENDSEC_ADDR" | tr ',' ' '); do
	if OPENDSEC_TOKEN=$(cat /etc/opendsec/admin.token) OPENDSEC_CA=/etc/opendsec/pki/ca.crt OPENDSEC_ADDR=$a \
		/usr/local/bin/opendsecctl iam backup -out "$f"; then done=1; break; fi
done
[ -n "$done" ] || { echo "no apiserver answered" >&2; exit 1; }
gzip -t "$f"
find "$dir" -name 'iam-*.json.gz' -mtime +"$keep" -delete
if [ -d "$textfile" ]; then
	printf '# HELP opendsec_iam_backup_last_success_timestamp_seconds Last successful IAM backup.\n# TYPE opendsec_iam_backup_last_success_timestamp_seconds gauge\nopendsec_iam_backup_last_success_timestamp_seconds %s\n' \
		"$(date +%s)" > "$textfile/opendsec_backup.prom.tmp" && mv "$textfile/opendsec_backup.prom.tmp" "$textfile/opendsec_backup.prom"
fi
