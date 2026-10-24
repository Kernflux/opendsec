#!/bin/sh
# Prepares a node for dense sandboxes (SPEC §25.4): the kernel modules the
# edge needs load at boot, udev and networkd leave the edge's devices alone,
# syslog does not fill the root disk with per-sandbox messages (§33.2),
# udisks2, networkd-dispatcher (without scripts) and tuned are off (opendsec-node-tuning sets the CPU governor and
# disk read-ahead instead); the NFS client has a unique id (§33.4); sysctls,
# swap and the edge's mount dependencies survive a reboot. Run as root;
# idempotent.
#
#   OPENDSEC_STATE_DIR  the edge's state_dir (default /data/opendsec-state):
#                       the edge waits for the filesystem holding it
#   OPENDSEC_SWAP_FILE  a swap file to keep on at boot (default: none),
#   OPENDSEC_SWAP_GB    created with this size if missing (default 16)
#   OPENDSEC_DEBS       an offline bundle's package repository (its debs/):
#                       missing packages come from there (spec §38)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
state_dir=${OPENDSEC_STATE_DIR:-/data/opendsec-state}
swap_file=${OPENDSEC_SWAP_FILE:-}
swap_gb=${OPENDSEC_SWAP_GB:-16}

# Programs the edge runs: mkfs.ext4 (writable disks), mkfs.erofs (microVM
# image disks, erofs_images), nft (network policy), ip, fallocate, cp.
need_pkgs=
for t in mkfs.ext4:e2fsprogs mkfs.erofs:erofs-utils nft:nftables ip:iproute2 fallocate:util-linux; do
	command -v "${t%%:*}" >/dev/null 2>&1 || need_pkgs="$need_pkgs ${t#*:}"
done
if [ -n "$need_pkgs" ]; then
	if [ -n "${OPENDSEC_DEBS:-}" ]; then
		echo "installing$need_pkgs (offline)"
		sh "$OPENDSEC_DEBS/apt-local.sh" $need_pkgs
	elif command -v apt-get >/dev/null 2>&1; then
		echo "installing$need_pkgs"
		DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y -qq $need_pkgs >/dev/null 2>&1 ||
			{ apt-get update -qq && DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y -qq $need_pkgs >/dev/null; }
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q $need_pkgs
	else
		echo "install these packages first:$need_pkgs" >&2
		exit 1
	fi
fi

install -m 0644 "$here/modules-opendsec.conf" /etc/modules-load.d/opendsec.conf
modprobe -a overlay dm_snapshot
install -m 0644 "$here/59-opendsec-early.rules" "$here/99-zz-opendsec.rules" /etc/udev/rules.d/
install -d /etc/systemd/network
install -m 0644 "$here/10-opendsec.link" "$here/10-opendsec.network" /etc/systemd/network/
udevadm control --reload
if systemctl is-active -q systemd-networkd; then networkctl reload || systemctl reload systemd-networkd || true; fi
systemctl disable --now udisks2 2>/dev/null || true
# networkd-dispatcher runs networkctl for every link that changes state,
# sandbox links included, to find scripts to run; without scripts it only
# fails on links already gone and floods syslog (SPEC §33.2). Off then.
if systemctl cat networkd-dispatcher.service >/dev/null 2>&1; then
	if [ -z "$(find /etc/networkd-dispatcher /usr/lib/networkd-dispatcher -type f 2>/dev/null | head -1)" ]; then
		systemctl disable -q --now networkd-dispatcher
	else
		echo "note: networkd-dispatcher has scripts, left on; it runs networkctl for every sandbox link" >&2
	fi
fi
# rsyslog: per-sandbox kernel and networkd messages stay in the journal only.
if [ -d /etc/rsyslog.d ] && command -v rsyslogd >/dev/null 2>&1; then
	install -m 0644 "$here/10-opendsec-rsyslog.conf" /etc/rsyslog.d/10-opendsec.conf
	if rsyslogd -N1 >/dev/null 2>&1; then
		systemctl restart rsyslog 2>/dev/null || true
	else
		echo "rsyslog rejects /etc/rsyslog.d/10-opendsec.conf; removed it" >&2
		rm -f /etc/rsyslog.d/10-opendsec.conf
	fi
fi

# NFSv4 clients without an id tell the server only their hostname: nodes
# cloned with one hostname look like one client to the image store's NFS
# server, which drops each one's state whenever the other one connects
# (SPEC §33.4). Give the client this machine's id; it takes effect when the
# store is next mounted afresh (a reboot, or every user of it stopped).
if [ -s /etc/machine-id ]; then
	printf '# Written by deploy/node/install.sh (SPEC §33.4).\noptions nfs nfs4_unique_id=%s\n' "$(cat /etc/machine-id)" \
		> /etc/modprobe.d/opendsec-nfs.conf
	f=/sys/module/nfs/parameters/nfs4_unique_id
	if [ -w "$f" ] && [ -z "$(cat "$f")" ]; then
		cat /etc/machine-id > "$f"
		grep -qE ' nfs4? ' /proc/mounts &&
			echo "note: NFS mounts made before now keep the old client id until remounted afresh (SPEC §33.4)" >&2
	fi
fi

install -m 0644 "$here/99-zz-opendsec.conf" /etc/sysctl.d/99-zz-opendsec.conf
# tuned (reapply_sysctl) applies /etc/sysctl.conf after every sysctl.d file,
# so a swappiness set there would still win at boot: take it out.
if grep -qE '^[[:space:]]*vm\.swappiness' /etc/sysctl.conf 2>/dev/null; then
	sed -i -E 's/^([[:space:]]*vm\.swappiness.*)$/# \1  # moved to sysctl.d\/99-zz-opendsec.conf by OpenDsec/' /etc/sysctl.conf
fi
sysctl -q -p /etc/sysctl.d/99-zz-opendsec.conf

# tuned runs hdparm on every block device, sandbox loop disks included: on a
# busy node it hangs, and a stop rolls its tuning back. Kill it (no rollback)
# and set what it set ourselves, at every boot.
if systemctl cat tuned.service >/dev/null 2>&1; then
	systemctl disable -q tuned
	case $(systemctl is-active tuned) in
	# systemd may report an error after the kill (auxiliary processes): ignore it.
	active | activating | deactivating | reloading) systemctl kill -s SIGKILL tuned || true ;;
	esac
	systemctl stop tuned 2>/dev/null || true
	systemctl reset-failed tuned 2>/dev/null || true
fi
install -m 0755 "$here/opendsec-node-tuning.sh" /usr/local/sbin/opendsec-node-tuning
install -m 0644 "$here/opendsec-node-tuning.service" /etc/systemd/system/opendsec-node-tuning.service

# The edge must not start on the root disk when the filesystem holding its
# state is missing (/data is often nofail): wait for it, fail without it.
install -d /etc/systemd/system/opendsec-edge.service.d
printf '# Written by deploy/node/install.sh.\n[Unit]\nRequiresMountsFor=%s\n' "$state_dir" \
	> /etc/systemd/system/opendsec-edge.service.d/10-node.conf

if [ -n "$swap_file" ]; then
	if [ ! -f "$swap_file" ]; then
		fallocate -l "${swap_gb}G" "$swap_file"
		chmod 600 "$swap_file"
		mkswap -q "$swap_file"
	fi
	if ! awk -v f="$swap_file" '$1 == f && $3 == "swap" { found = 1 } END { exit !found }' /etc/fstab; then
		printf '%s none swap sw,nofail 0 0\n' "$swap_file" >> /etc/fstab
	fi
	swapon --show=NAME --noheadings | grep -qxF "$swap_file" || swapon "$swap_file"
fi
systemctl daemon-reload
systemctl enable -q opendsec-node-tuning
systemctl restart opendsec-node-tuning
echo "node prepared for OpenDsec"
