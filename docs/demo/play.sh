#!/bin/bash
# Drives the README demo recording (see render.py): types each
# command, then runs it for real. The quickstart step is not rerun: the
# tail of its log from the run on this machine stands in for its 8 minutes.
cd /root/opendsec
type() { printf '\033[1;32m$\033[0m '; for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.04; done; sleep 0.4; echo; }
type "deploy/quickstart.sh"
printf '\033[2m# ... 8 minutes later (8-core VM): built, installed, python:3.12 imported ...\033[0m\n'
grep -E '\[ok\] (container|microvm) sandbox|OpenDsec is running' /root/qs.log
sleep 1.5
type ". /root/opendsec-ops/demo.env"
. /root/opendsec-ops/demo.env
type "cat demo.py"
cat /root/demo.py
sleep 5
type "python demo.py"
.venv/bin/python /root/demo.py
sleep 3
