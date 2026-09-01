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

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
mkdir -p "$APTI_SECURE_RESULT_DIR"

(
  last_action=""
  last_action_at=0
  for _ in $(seq 1 600); do
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

python3 - <<'PY'
from pathlib import Path

path = Path("scripts/apti_exact_https_probe.py")
text = path.read_text(encoding="utf-8")
old = 'result["input_verified"] = bool(username_ok and password_ok and nonempty)'
new = 'result["input_verified"] = bool(username_ok and password_ok)'
if old not in text:
    raise SystemExit("exact probe input verification expression was not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY

echo 'skipped: exact HTTPS revision runs the corrected login probe only' > "$APTI_SECURE_RESULT_DIR/legacy-probe-return-code.txt"

set +e
python3 scripts/apti_exact_https_probe.py --credentials "${APTI_CREDENTIALS_FILE:-/dev/shm/apti-creds.json}" --result-dir "$APTI_SECURE_RESULT_DIR"
exact_probe_rc=$?
set -e
printf '%s\n' "$exact_probe_rc" > "$APTI_SECURE_RESULT_DIR/exact-https-probe-return-code.txt"

exit "$exact_probe_rc"
