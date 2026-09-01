#!/usr/bin/env bash
set -Eeuo pipefail

ui_helper_pid=""
cleanup() {
  if [[ -n "${ui_helper_pid:-}" ]]; then
    kill "$ui_helper_pid" >/dev/null 2>&1 || true
    wait "$ui_helper_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

(
  last_action=""
  last_action_at=0

  for _ in $(seq 1 420); do
    adb shell uiautomator dump /sdcard/apti-autoclick.xml >/dev/null 2>&1 || true
    xml="$(adb shell cat /sdcard/apti-autoclick.xml 2>/dev/null || true)"
    now="$(date +%s)"

    if grep -q 'content-desc="시작하기"' <<<"$xml" || grep -q 'text="시작하기"' <<<"$xml"; then
      if [[ "$last_action" != "start" || $((now - last_action_at)) -ge 5 ]]; then
        adb shell input tap 540 2153
        last_action="start"
        last_action_at="$now"
      fi
    elif grep -q 'content-desc="오늘 그만보기"' <<<"$xml" && grep -q 'content-desc="닫기"' <<<"$xml"; then
      if [[ "$last_action" != "promo-close" || $((now - last_action_at)) -ge 5 ]]; then
        adb shell input tap 961 2205
        last_action="promo-close"
        last_action_at="$now"
      fi
    fi

    sleep 1
  done
) &
ui_helper_pid=$!

set +e
python3 scripts/apti_secure_probe.py
probe_rc=$?
set -e

exit "$probe_rc"
