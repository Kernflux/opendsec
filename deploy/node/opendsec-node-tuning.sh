#!/bin/sh
# OpenDsec node tuning at boot (installed by install.sh as
# /usr/local/sbin/opendsec-node-tuning, run by opendsec-node-tuning.service).
# It replaces tuned's throughput-performance profile on sandbox nodes: tuned
# runs hdparm on every block device, sandbox loop disks included, hangs on a
# busy node and rolls this tuning back when it is stopped. Sysctls are in
# /etc/sysctl.d/99-zz-opendsec.conf.
set -u
# CPU frequency governor.
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
	[ -w "$g" ] && echo performance > "$g"
done
# Read-ahead of at least 4 MB on real disks (never lowered); sandbox loop
# disks, ram disks and the like keep theirs.
for d in /sys/block/*; do
	case ${d##*/} in loop* | ram* | zram* | nbd* | sr*) continue ;; esac
	ra=$d/queue/read_ahead_kb
	[ -w "$ra" ] && [ "$(cat "$ra")" -lt 4096 ] && echo 4096 > "$ra"
done
exit 0
