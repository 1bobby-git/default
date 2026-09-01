#!/usr/bin/env bash
set -Eeuo pipefail

ui_helper_pid=""
login_logcat_pid=""
tcpdump_pid=""
dnsdump_pid=""
tmp_dir=""
cleanup() {
  if [[ -n "${dnsdump_pid:-}" ]]; then
    sudo kill "$dnsdump_pid" >/dev/null 2>&1 || true
    wait "$dnsdump_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${tcpdump_pid:-}" ]]; then
    sudo kill "$tcpdump_pid" >/dev/null 2>&1 || true
    wait "$tcpdump_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${login_logcat_pid:-}" ]]; then
    kill "$login_logcat_pid" >/dev/null 2>&1 || true
    wait "$login_logcat_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ui_helper_pid:-}" ]]; then
    kill "$ui_helper_pid" >/dev/null 2>&1 || true
    wait "$ui_helper_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${tmp_dir:-}" ]]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
exact_dir="$APTI_SECURE_RESULT_DIR/exact-original-https"
mkdir -p "$exact_dir"
tmp_dir="$(mktemp -d -t apti-clean-probe-XXXXXX)"

python3 - <<'PY'
from pathlib import Path

path = Path("scripts/apti_exact_https_probe.py")
text = path.read_text(encoding="utf-8")

verify_old = 'result["input_verified"] = bool(username_ok and password_ok and nonempty)'
verify_new = '''result["input_verified"] = bool(
        username_ok
        and password_ok
        and len(after) >= 2
        and after[0].get("visible_length") == len(credentials["username"])
        and after[1].get("visible_length") == len(credentials["password"])
    )'''
if verify_old not in text:
    raise SystemExit("exact probe input verification expression was not found")
text = text.replace(verify_old, verify_new, 1)

keyboard_old = '    component = resolve_adb_keyboard()\n    keyboard_ready = bool(component and enable_adb_keyboard(component))'
keyboard_new = '    component = None\n    keyboard_ready = False'
if keyboard_old not in text:
    raise SystemExit("exact probe keyboard selection block was not found")
text = text.replace(keyboard_old, keyboard_new, 1)

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

submit_old = '''    login_candidates.sort(key=lambda item: item[0], reverse=True)
    tap_node(login_candidates[0][1])
    result["login_clicked"] = True
    time.sleep(2)

    observations: list[dict[str, Any]] = []'''
submit_new = '''    login_candidates.sort(key=lambda item: item[0], reverse=True)
    tap_node(login_candidates[0][1])
    result["login_clicked"] = True
    time.sleep(1.2)

    retry_root = dump_ui(result_dir, "login-submit-retry", credentials)
    result["login_retry_clicked"] = tap_label(retry_root, ["로그인"], min_y=500)
    if result["login_retry_clicked"]:
        time.sleep(2)

    observations: list[dict[str, Any]] = []'''
if submit_old not in text:
    raise SystemExit("exact probe login submission block was not found")
text = text.replace(submit_old, submit_new, 1)

path.write_text(text, encoding="utf-8")
PY

adb wait-for-device
adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
adb shell settings delete global global_http_proxy_host >/dev/null 2>&1 || true
adb shell settings delete global global_http_proxy_port >/dev/null 2>&1 || true

xapk="$tmp_dir/apti.xapk"
xapk_dir="$tmp_dir/xapk"
mkdir -p "$xapk_dir"
curl -fL --retry 5 --retry-delay 2 "$APTI_XAPK_URL" -o "$xapk"
printf '%s  %s\n' "$APTI_XAPK_SHA256" "$xapk" | sha256sum -c -
unzip -q "$xapk" -d "$xapk_dir"
base_apk="$(find "$xapk_dir" -type f -name 'aptip.app.apk' -print -quit)"
if [[ -z "$base_apk" ]]; then
  echo 'Base Apti APK was not found in XAPK.' >&2
  exit 31
fi
mapfile -t split_apks < <(find "$xapk_dir" -type f -name '*.apk' ! -path "$base_apk" | sort)
adb install-multiple -r -g "$base_apk" "${split_apks[@]}"

build_tools="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)"
if [[ -x "$build_tools/aapt" ]]; then
  "$build_tools/aapt" dump badging "$base_apk" > "$exact_dir/apk-badging.txt" 2>&1 || true
fi

adb shell am force-stop aptip.app >/dev/null 2>&1 || true
adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true
adb shell am start -W \
  -n com.android.chrome/com.google.android.apps.chrome.Main \
  -a android.intent.action.VIEW \
  -d about:blank \
  > "$exact_dir/chrome-prime-start.txt" 2>&1 || true

for index in $(seq 0 24); do
  adb shell uiautomator dump /sdcard/chrome-prime.xml >/dev/null 2>&1 || true
  chrome_xml="$(adb shell cat /sdcard/chrome-prime.xml 2>/dev/null || true)"
  printf '%s' "$chrome_xml" > "$exact_dir/chrome-prime-${index}.xml"

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

adb exec-out screencap -p > "$exact_dir/chrome-prime-final.png" 2>/dev/null || true
adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true

(
  last_action=""
  last_action_at=0
  for _ in $(seq 1 480); do
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

adb shell monkey -p aptip.app -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 10
adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true

sudo apt-get install -y -qq tcpdump >/dev/null
adb shell logcat -c >/dev/null 2>&1 || true
adb logcat -v threadtime > "$exact_dir/login-and-launch-logcat.txt" 2>&1 &
login_logcat_pid=$!
sudo tcpdump -i any -nn -s0 -U -w "$exact_dir/login-and-launch.pcap" '(udp port 53 or tcp port 53 or tcp port 443)' >/dev/null 2>&1 &
tcpdump_pid=$!
sudo tcpdump -i any -nn -l -A '(udp port 53 or tcp port 53)' > "$exact_dir/login-dns.txt" 2>&1 &
dnsdump_pid=$!

set +e
python3 scripts/apti_exact_https_probe.py --credentials "${APTI_CREDENTIALS_FILE:-/dev/shm/apti-creds.json}" --result-dir "$APTI_SECURE_RESULT_DIR"
exact_probe_rc=$?
set -e
printf '%s\n' "$exact_probe_rc" > "$APTI_SECURE_RESULT_DIR/exact-https-probe-return-code.txt"
printf '%s\n' 'manual-clean-install' > "$APTI_SECURE_RESULT_DIR/legacy-probe-return-code.txt"

sudo kill "$dnsdump_pid" >/dev/null 2>&1 || true
wait "$dnsdump_pid" >/dev/null 2>&1 || true
dnsdump_pid=""
sudo kill "$tcpdump_pid" >/dev/null 2>&1 || true
wait "$tcpdump_pid" >/dev/null 2>&1 || true
tcpdump_pid=""
kill "$login_logcat_pid" >/dev/null 2>&1 || true
wait "$login_logcat_pid" >/dev/null 2>&1 || true
login_logcat_pid=""

exit "$exact_probe_rc"
