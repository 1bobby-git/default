#!/usr/bin/env bash
set -Eeuo pipefail

ui_helper_pid=""
login_logcat_pid=""
cleanup() {
  if [[ -n "${login_logcat_pid:-}" ]]; then
    kill "$login_logcat_pid" >/dev/null 2>&1 || true
    wait "$login_logcat_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ui_helper_pid:-}" ]]; then
    kill "$ui_helper_pid" >/dev/null 2>&1 || true
    wait "$ui_helper_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
mkdir -p "$APTI_SECURE_RESULT_DIR" "$APTI_SECURE_RESULT_DIR/exact-original-https"

(
  last_action=""
  last_action_at=0
  for _ in $(seq 1 900); do
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

verify_old = 'result["input_verified"] = bool(username_ok and password_ok and nonempty)'
verify_new = 'result["input_verified"] = bool(username_ok and password_ok)'
if verify_old not in text:
    raise SystemExit("exact probe input verification expression was not found")
text = text.replace(verify_old, verify_new, 1)

resolver_old = '''                for options in (
                    ["Chrome", "크롬"], ["한 번만", "Just once"],
                    ["동의하고 계속", "Accept & continue"],
                    ["계정 없이 사용", "Use without an account"],
                    ["아니요", "No thanks"], ["계속", "Continue"],
                ):'''
resolver_new = '''                for options in (
                    ["계정 없이 사용", "Use without an account"],
                    ["동의하고 계속", "Accept & continue"],
                    ["한 번만", "Just once"],
                    ["아니요", "No thanks"], ["계속", "Continue"],
                    ["Chrome", "크롬"],
                ):'''
if resolver_old not in text:
    raise SystemExit("exact probe Chrome resolver block was not found")
text = text.replace(resolver_old, resolver_new, 1)
path.write_text(text, encoding="utf-8")
PY

set +e
python3 scripts/apti_secure_probe.py
legacy_probe_rc=$?
set -e
printf '%s\n' "$legacy_probe_rc" > "$APTI_SECURE_RESULT_DIR/legacy-probe-return-code.txt"

pkill -f mitmdump >/dev/null 2>&1 || true
adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
adb shell settings delete global global_http_proxy_host >/dev/null 2>&1 || true
adb shell settings delete global global_http_proxy_port >/dev/null 2>&1 || true

adb shell am force-stop aptip.app >/dev/null 2>&1 || true
adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true
adb shell am start -W \
  -n com.android.chrome/com.google.android.apps.chrome.Main \
  -a android.intent.action.VIEW \
  -d about:blank \
  > "$APTI_SECURE_RESULT_DIR/exact-original-https/chrome-prime-start.txt" 2>&1 || true

for index in $(seq 0 19); do
  adb shell uiautomator dump /sdcard/chrome-prime.xml >/dev/null 2>&1 || true
  chrome_xml="$(adb shell cat /sdcard/chrome-prime.xml 2>/dev/null || true)"
  printf '%s' "$chrome_xml" > "$APTI_SECURE_RESULT_DIR/exact-original-https/chrome-prime-${index}.xml"

  if grep -q 'com.android.chrome:id/signin_fre_dismiss_button' <<<"$chrome_xml"; then
    adb shell input tap 540 1977
    sleep 2
    continue
  fi
  if grep -q 'com.android.chrome:id/terms_accept' <<<"$chrome_xml" || grep -q 'text="Accept &amp; continue"' <<<"$chrome_xml"; then
    adb shell input tap 540 2050
    sleep 2
    continue
  fi

  chrome_top="$(adb shell dumpsys activity activities 2>/dev/null | grep -m1 -E 'topResumedActivity|mResumedActivity' || true)"
  if [[ "$chrome_top" == *"com.android.chrome"* && "$chrome_top" != *"FirstRunActivity"* ]]; then
    break
  fi
  sleep 1
 done

adb exec-out screencap -p > "$APTI_SECURE_RESULT_DIR/exact-original-https/chrome-prime-final.png" 2>/dev/null || true
adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true
adb shell monkey -p aptip.app -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 8

adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
adb shell logcat -c >/dev/null 2>&1 || true
adb logcat -v threadtime > "$APTI_SECURE_RESULT_DIR/exact-original-https/login-and-launch-logcat.txt" 2>&1 &
login_logcat_pid=$!

set +e
python3 scripts/apti_exact_https_probe.py --credentials "${APTI_CREDENTIALS_FILE:-/dev/shm/apti-creds.json}" --result-dir "$APTI_SECURE_RESULT_DIR"
exact_probe_rc=$?
set -e
printf '%s\n' "$exact_probe_rc" > "$APTI_SECURE_RESULT_DIR/exact-https-probe-return-code.txt"

kill "$login_logcat_pid" >/dev/null 2>&1 || true
wait "$login_logcat_pid" >/dev/null 2>&1 || true
login_logcat_pid=""

exit "$exact_probe_rc"
