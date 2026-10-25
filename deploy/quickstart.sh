#!/bin/bash
# quickstart.sh: install a complete single-node OpenDsec cluster on this
# machine (IAM, watcher, apiserver and edge as systemd units), import a base
# image and run a sandbox. Run as root from a clone of the repository:
#
#   deploy/quickstart.sh                 # container + microVM (if /dev/kvm)
#   deploy/quickstart.sh --no-microvm    # containers only
#   deploy/quickstart.sh --kernel FILE   # microVMs with this guest kernel
#   deploy/quickstart.sh --build-kernel  # build the guest kernel first
#   deploy/quickstart.sh --release DIR   # a packaged release, no build (offline bundles)
#   deploy/quickstart.sh --uninstall     # remove everything it installed
#
# It uses the same tooling as a multi-node cluster (deploy/prod/opendsecops,
# docs/OPERATIONS.md): the ops directory ($OPENDSEC_OPS, default
# /root/opendsec-ops) holds the inventory (this machine, ssh address
# "local"), the cluster config, the admin token and the CA, so the cluster
# can be upgraded and extended with other machines later.
#
# Environment: OPENDSEC_IMAGE (base image, default docker.io/library/python:3.12;
# an image archive works too), OPENDSEC_ADDR_IP (the address components listen
# on, default the address of the default route), OPENDSEC_DEBS (an offline
# bundle's package repository, spec §38).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
OPS=${OPENDSEC_OPS:-/root/opendsec-ops}
OPSCMD=$HERE/prod/opendsecops
IMAGE=${OPENDSEC_IMAGE:-docker.io/library/python:3.12}
STORE=/mnt/opendsec-images
export OPENDSEC_OPS=$OPS

microvm=auto kernel= build_kernel= uninstall= release=
while [ $# -gt 0 ]; do
	case $1 in
	--no-microvm) microvm=no ;;
	--kernel) kernel=$(readlink -f "${2:?--kernel FILE}"); shift ;;
	--build-kernel) build_kernel=1 ;;
	--release) release=$(readlink -f "${2:?--release DIR}"); shift ;;
	--uninstall) uninstall=1 ;;
	-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
	*) echo "quickstart: unknown option $1 (--help)" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { echo "quickstart: $*" >&2; exit 1; }
warn() { echo "quickstart: warning: $*" >&2; }

# ---- uninstall -------------------------------------------------------------------------

if [ -n "$uninstall" ]; then
	[ "$(id -u)" = 0 ] || die "run as root"
	say "stopping and removing OpenDsec from this machine"
	systemctl disable --now opendsec-edge 'opendsec-apiserver@*' 'opendsec-watcher@*' 'opendsec-iam@*' \
		'opendsec-fleet@*' opendsec-nodeagent opendsec-iam-backup.timer 2>/dev/null || true
	for u in $(systemctl list-units --all --plain --no-legend 'opendsec-*' | awk '{print $1}'); do systemctl disable --now "$u" 2>/dev/null || true; done
	# Sandboxes the edge left running (keep_sandboxes_on_exit).
	for c in $(find /sys/fs/cgroup -maxdepth 2 -type d -name 'opendsec*' 2>/dev/null | sort -r); do
		for p in $(cat "$c"/cgroup.procs "$c"/*/cgroup.procs 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
	done
	nft list tables 2>/dev/null | awk '/opendsec/ {print $2, $3}' | while read -r fam t; do nft delete table "$fam" "$t" || true; done
	for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^(ods|odsbr|opendsec)'); do ip link delete "$l" 2>/dev/null || true; done
	for d in $(ip netns list 2>/dev/null | awk '/^ods|^opendsec/ {print $1}'); do ip netns delete "$d" || true; done
	awk '$2 ~ /opendsec/ {print $2}' /proc/mounts | sort -r | while read -r m; do umount -l "$m" 2>/dev/null || true; done
	systemctl disable -q opendsec-node-tuning 2>/dev/null || true
	rm -rf /etc/systemd/system/opendsec-* /usr/local/bin/opendsec-* /usr/local/bin/opendsecctl /usr/local/sbin/opendsec-iam-backup \
		/usr/local/sbin/opendsec-node-tuning
	systemctl daemon-reload
	[ -d /sys/fs/cgroup/opendsec ] && find /sys/fs/cgroup/opendsec -depth -type d -exec rmdir {} + 2>/dev/null || true
	rm -rf /etc/opendsec /opt/opendsec /var/lib/opendsec /var/log/opendsec /var/backups/opendsec "$OPS" "$STORE"
	[ -d /data/opendsec-state ] && rm -rf /data/opendsec-state
	say "removed. The node settings of deploy/node/install.sh (sysctl.d, udev rules, modules-load.d, networkd files) stay."
	exit 0
fi

# ---- preflight ----------------------------------------------------------------------------

say "checking this machine"
bad=0
need() { if ! eval "$2"; then echo "  [x] $1" >&2; bad=1; else echo "  [ok] $1"; fi; }
need "running as root" '[ "$(id -u)" = 0 ]'
need "x86_64" '[ "$(uname -m)" = x86_64 ]'
need "systemd" '[ -d /run/systemd/system ]'
need "cgroup v2 (unified hierarchy)" '[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ]'
need "Linux 5.15 or newer" '[ "$(printf "%s\n5.15\n" "$(uname -r | cut -d- -f1)" | sort -V | head -1)" = 5.15 ]'
need "overlay filesystem" 'grep -qw overlay /proc/filesystems || modprobe overlay 2>/dev/null'
for c in curl tar sha256sum mkfs.ext4 ip awk; do need "command $c" "command -v $c >/dev/null"; done
# Building needs Go 1.27+ and make; prebuilt binaries in bin/ or --release DIR need neither.
gover() { v=$(PATH=$PATH:/usr/local/go/bin go env GOVERSION 2>/dev/null) && [ "$(printf "%s\ngo1.27\n" "$v" | sort -V | head -1)" = go1.27 ]; }
if [ -z "$release" ] && [ ! -x "$REPO/bin/opendsecctl" ]; then
	need "Go 1.27+ to build (https://go.dev/dl; or prebuilt binaries in bin/, or --release DIR)" gover
	need "command make (apt install make)" "command -v make >/dev/null"
fi
[ -e "$OPS/inventory" ] && { echo "  [x] $OPS already holds a cluster (run with --uninstall first, or use $OPSCMD)" >&2; bad=1; }
for p in 7001 7002 7011 7100 7201 7400 9461 9462 9463 9464 9467; do
	if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then echo "  [x] port $p is in use" >&2; bad=1; fi
done
[ $bad = 0 ] || die "fix the items marked [x] and run again"

if [ "$microvm" = auto ]; then
	if [ -e /dev/kvm ]; then microvm=yes; else microvm=no; warn "no /dev/kvm: containers only (microVMs need bare metal or nested virtualization)"; fi
fi
if [ "$microvm" = yes ] && [ -n "$build_kernel" ] && [ -z "$kernel" ]; then
	say "building the guest kernel (deploy/guest-kernel/build.sh)"
	for c in gcc make flex bison bc; do command -v $c >/dev/null || die "building the kernel needs $c (apt install build-essential flex bison bc libelf-dev libssl-dev)"; done
	mkdir -p /var/cache/opendsec-kbuild
	kernel=$(WORK=/var/cache/opendsec-kbuild OUT=/var/cache/opendsec-kbuild/vmlinux-opendsec "$HERE/guest-kernel/build.sh" | tail -1)
fi

ip=${OPENDSEC_ADDR_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true)}
# No default route (an isolated network): the first global address.
[ -n "$ip" ] || ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4; exit}')
[ -n "$ip" ] || die "cannot tell this machine's address: set OPENDSEC_ADDR_IP"
name=$(hostname -s | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-\n' '-')
[ -n "$name" ] || name=node1
if mountpoint -q /data; then state=/data/opendsec-state; else state=/var/lib/opendsec/edge-state; fi
echo "  node $name, address $ip, sandbox state in $state, microVMs: $microvm"

# ---- build and package ------------------------------------------------------------------

mkdir -p -m 0700 "$OPS"
if [ -n "$release" ]; then
	say "adding the release $release"
	"$OPSCMD" release-add "$release" >/dev/null
	if [ "$microvm" = yes ] && [ ! -e "$OPS/current/vm/vmlinux-6.1.167-opendsec" ]; then
		die "the release has no guest kernel: rerun with --no-microvm"
	fi
else
	say "building"
	if [ ! -x "$REPO/bin/opendsecctl" ]; then
		export PATH=$PATH:/usr/local/go/bin
		make -C "$REPO" build >/dev/null
	fi
	if [ "$microvm" = no ]; then
		export OPENDSEC_DEPS_SKIP="guest-kernel"
	elif [ -n "$kernel" ]; then
		export OPENDSEC_KERNEL=$kernel
	fi
	if ! "$OPSCMD" release "$REPO/bin"; then
		if [ "$microvm" = yes ] && [ -z "$kernel" ]; then
			die "could not fetch the guest kernel pinned in deploy/deps.lock: rerun with --build-kernel, --kernel FILE, or --no-microvm"
		fi
		die "packaging the release failed"
	fi
fi

# ---- cluster config ---------------------------------------------------------------------

say "writing the cluster config to $OPS"
echo "$name local $ip iam=0 watcher=0 apiserver=0 edge=$name e2b=0" > "$OPS/inventory"
umask 077
printf 'dsk.admin.%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$OPS/admin.token"
umask 022
microvm_backend=
if [ "$microvm" = yes ]; then
	microvm_backend='"microvm": {"runtime": "firecracker", "max_sandboxes": 1000, "default_disk_mb": 2048,
        "firecracker": "/opt/opendsec/current/bin/firecracker", "jailer": "/opt/opendsec/current/bin/jailer",
        "kernel": "/opt/opendsec/current/vm/vmlinux-6.1.167-opendsec", "image_pmem": true, "erofs_images": true,
        "free_page_reporting": true, "cold_age_s": 120},'
fi
e2b_backend=container
[ "$microvm" = yes ] && e2b_backend=microvm
cat > "$OPS/opendsec.json" <<EOF
{
  "tls": {"dir": "/etc/opendsec/pki"},
  "iam": {
    "replicas": [{"id": "0", "addr": "$ip:7001", "raft_addr": "$ip:7011", "data_dir": "/var/lib/opendsec/iam"}],
    "admin_id": "admin",
    "admin_token_file": "/etc/opendsec/admin.token",
    "root_quota": {"sandboxes": 10000},
    "max_token_ttl_s": 7776000
  },
  "watcher": {
    "replicas": [{"id": "0", "addr": "$ip:7002"}],
    "probe_interval": 1, "reconcile_interval": 30, "reconcile_min_age": 60, "lost_edge_grace": 120
  },
  "apiserver": [{"addr": "$ip:7100", "audit_dir": "/var/log/opendsec/audit", "audit_max_mb": 256}],
  "placement": {"k": 2, "max_attempts": 3},
  "image_store": {"root": "$STORE"},
  "network": {"rule_sets": {"pypi": ["pypi.org", "files.pythonhosted.org"]}},
  "e2b": {
    "gateways": [{"addr": "$ip:7400"}],
    "project": "root/demo",
    "templates": {"base": {"image": "root/py:3.12", "backend": "$e2b_backend", "cpu": 2, "memory_mb": 512}}
  },
  "edge_template": {
    "addr": "0.0.0.0:7201", "zone": "onprem",
    "state_dir": "$state", "agent_dir": "/opt/opendsec/current/agents",
    "persist_state": true, "keep_sandboxes_on_exit": true,
    "network": {"enabled": true, "subnet": "10.88.0.0/16", "dns_port": 15353},
    "backends": {
      $microvm_backend
      "container": {"runtime": "linux", "max_sandboxes": 2000, "default_disk_mb": 1024}
    }
  }
}
EOF

# ---- install and start -------------------------------------------------------------------

say "installing (certificates, units, node settings)"
mkdir -p "$STORE" "$state"
"$OPSCMD" certs
"$OPSCMD" install all
say "starting"
"$OPSCMD" start all
ln -sfn /opt/opendsec/current/bin/opendsecctl /usr/local/bin/opendsecctl

cat > "$OPS/env" <<EOF
# Admin access to the cluster: . $OPS/env
export OPENDSEC_ADDR=$ip:7100
export OPENDSEC_TOKEN=\$(cat $OPS/admin.token)
export OPENDSEC_CA=$OPS/pki/ca.crt
export OPENDSEC_PROJECT=root
export OPENDSEC_IMAGE_STORE=$STORE
EOF
chmod 0600 "$OPS/env"
. "$OPS/env"

say "checking the image store"
opendsecctl image store-check -store "$STORE" >/dev/null || die "the image store $STORE lacks a required capability: opendsecctl image store-check -store $STORE"

say "importing $IMAGE as root/py:3.12"
opendsecctl image import "$IMAGE" -as root/py:3.12 >/dev/null

say "creating the project root/demo and its caller"
opendsecctl project create root demo -quota sandboxes=100 >/dev/null
tok=$(opendsecctl principal create root/demo demo -kind agent | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
[ -n "$tok" ] || die "creating the demo principal returned no token"
opendsecctl grant root/demo demo sandbox.create,sandbox.operate,layer.publish >/dev/null  # layer.publish: images of its own (pack_diff, snapshots)
opendsecctl grant root demo layer.use >/dev/null
umask 077
cat > "$OPS/demo.env" <<EOF
# A caller in project root/demo (what you hand a user): . $OPS/demo.env
export OPENDSEC_ADDR=$ip:7100
export OPENDSEC_TOKEN=$tok
export OPENDSEC_CA=$OPS/pki/ca.crt
export OPENDSEC_PROJECT=root/demo
# E2B's SDKs, through the E2B gateway (docs/E2B.md)
export E2B_API_URL=http://$ip:7400
export E2B_SANDBOX_URL=http://$ip:7400
export E2B_API_KEY=$tok
EOF
umask 022

smoke() { # backend
	local id out
	id=$(OPENDSEC_TOKEN=$tok OPENDSEC_PROJECT=root/demo opendsecctl sandbox create -backend "$1" -image root/py:3.12 -ttl-idle 300 |
		sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' | head -1)
	[ -n "$id" ] || { warn "creating a $1 sandbox failed"; return 1; }
	out=$(OPENDSEC_TOKEN=$tok OPENDSEC_PROJECT=root/demo opendsecctl exec "$id" python3 -c 'print(6*7)') || true
	OPENDSEC_TOKEN=$tok OPENDSEC_PROJECT=root/demo opendsecctl sandbox stop "$id" >/dev/null || true
	[ "$out" = 42 ] || { warn "$1 sandbox $id: python printed '$out', want 42"; return 1; }
	echo "  [ok] $1 sandbox ran python"
}
say "running a sandbox"
ok=1
smoke container || ok=
[ "$microvm" = yes ] && { smoke microvm || ok=; }

sdk="./sdk/python" e2b="e2b" venv="apt install python3-venv"
if [ -d "$REPO/wheels" ]; then # an offline bundle
	sdk="--no-index --find-links $REPO/wheels opendsec" e2b="--no-index --find-links $REPO/wheels e2b"
	venv="sh $REPO/debs/apt-local.sh python3-venv"
fi
cat <<EOF

OpenDsec is running on this machine.
  admin:   . $OPS/env        (opendsecctl status, opendsecctl --help)
  caller:  . $OPS/demo.env
           python3 -m venv .venv && .venv/bin/pip install $sdk   (Ubuntu/Debian: $venv)
           .venv/bin/python sdk/python/examples/quickstart.py
  E2B:     the same demo.env sets E2B_API_URL, E2B_SANDBOX_URL and E2B_API_KEY:
           .venv/bin/pip install $e2b, then E2B's SDK runs here (docs/en/E2B.md)
  status:  $OPSCMD status
  remove:  $0 --uninstall
The ops directory $OPS holds the admin token and the CA private key: keep it private.
EOF
[ -n "$ok" ] || die "the cluster is up but a sandbox check failed (journalctl -u opendsec-edge)"
