#!/bin/bash
# Drives the README demo recording (see render.py): types each command,
# then runs exactly that line. Before it, as a reader's shell would be:
# the quickstart has run in /root/opendsec, the SDK is installed in its
# .venv (activated) and demo.py sits next to it. The quickstart itself is
# not rerun: the tail of its log stands in for its minutes.
cd /root/opendsec
cp "$(dirname "$0")/demo.py" demo.py
. .venv/bin/activate
type() { printf '\033[1;32m$\033[0m '; for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.04; done; sleep 0.4; echo; }
run() { type "$1"; eval "$1"; }
type "deploy/quickstart.sh"
printf '\033[2m# ... 6 minutes later (bare metal): built, installed, python:3.12 imported ...\033[0m\n'
grep -E '\[ok\] (container|microvm) sandbox|OpenDsec is running' /root/qs.log
sleep 1.5
run ". /root/opendsec-ops/demo.env"
run "cat demo.py"
sleep 5
run "python demo.py"
sleep 3
