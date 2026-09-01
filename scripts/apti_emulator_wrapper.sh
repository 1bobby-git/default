#!/usr/bin/env bash
set -Eeuo pipefail

onboard_pid=""
cleanup() {
  if [[ -n "${onboard_pid:-}" ]]; then
    kill "$onboard_pid" >/dev/null 2>&1 || true
    wait "$onboard_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

(
  for _ in $(seq 1 240); do
    adb shell uiautomator dump /sdcard/apti-autoclick.xml >/dev/null 2>&1 || true
    xml="$(adb shell cat /sdcard/apti-autoclick.xml 2>/dev/null || true)"
    if grep -q 'content-desc="시작하기"' <<<"$xml" || grep -q 'text="시작하기"' <<<"$xml"; then
      adb shell input tap 540 2153
      exit 0
    fi
    sleep 1
  done
) &
onboard_pid=$!

set +e
python3 scripts/apti_secure_probe.py
probe_rc=$?
set -e

exit "$probe_rc"
