#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mkdir -p .apti-sensitive-results
set +e
python3 scripts/apti_v4_probe.py
probe_rc=$?
set -e

exit "$probe_rc"
