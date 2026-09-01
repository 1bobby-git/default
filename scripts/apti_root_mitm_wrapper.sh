#!/usr/bin/env bash
set -Eeuo pipefail

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
exact_dir="$APTI_SECURE_RESULT_DIR/root-mitm"
mitm_dir="$exact_dir/mitm"
mkdir -p "$exact_dir" "$mitm_dir"
work="$(mktemp -d -t apti-root-mitm-XXXXXX)"
mitm_pid=""
cleanup() {
  adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
  if [[ -n "${mitm_pid:-}" ]]; then
    kill "$mitm_pid" >/dev/null 2>&1 || true
    wait "$mitm_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

adb wait-for-device
for _ in $(seq 1 180); do
  [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
  sleep 2
done

mitmdump --version > "$exact_dir/mitm-version.txt"
timeout 3 mitmdump -q --listen-host 127.0.0.1 --listen-port 18080 >/dev/null 2>&1 || true
ca_pem="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
test -s "$ca_pem"
ca_hash="$(openssl x509 -inform PEM -subject_hash_old -in "$ca_pem" | head -1)"
printf '%s\n' "$ca_hash" > "$exact_dir/ca-subject-hash.txt"

adb root > "$exact_dir/adb-root.txt" 2>&1 || true
adb wait-for-device
adb remount > "$exact_dir/adb-remount.txt" 2>&1 || true
adb push "$ca_pem" "/system/etc/security/cacerts/${ca_hash}.0" > "$exact_dir/ca-push.txt" 2>&1
adb shell chmod 644 "/system/etc/security/cacerts/${ca_hash}.0"
adb shell ls -l "/system/etc/security/cacerts/${ca_hash}.0" > "$exact_dir/ca-installed.txt"
adb reboot
adb wait-for-device
for _ in $(seq 1 180); do
  [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
  sleep 2
done
sleep 20

xapk="$work/apti.xapk"
xapk_dir="$work/xapk"
mkdir -p "$xapk_dir"
curl -fL --retry 5 --retry-delay 2 "$APTI_XAPK_URL" -o "$xapk"
printf '%s  %s\n' "$APTI_XAPK_SHA256" "$xapk" | sha256sum -c -
unzip -q "$xapk" -d "$xapk_dir"
base_apk="$(find "$xapk_dir" -type f -name 'aptip.app.apk' -print -quit)"
test -n "$base_apk"
mapfile -t split_apks < <(find "$xapk_dir" -type f -name '*.apk' ! -path "$base_apk" | sort)
adb install-multiple -r -g "$base_apk" "${split_apks[@]}" > "$exact_dir/install.txt" 2>&1
adb shell pm list packages | grep 'package:aptip.app' > "$exact_dir/package-installed.txt"
adb shell getprop ro.product.cpu.abilist > "$exact_dir/abilist.txt"
adb shell dumpsys package aptip.app | grep -E 'versionName=|versionCode=|primaryCpuAbi=|secondaryCpuAbi=' > "$exact_dir/package-version.txt" || true

adb shell logcat -c >/dev/null 2>&1 || true
for index in $(seq 1 12); do
  sleep 15
  printf 'sample=%s utc=%s gms_pid=%s\n' "$index" "$(date -u +%FT%TZ)" "$(adb shell pidof com.google.android.gms 2>/dev/null | tr -d '\r' || true)" >> "$exact_dir/gms-stabilization.txt"
done
adb logcat -d -v threadtime > "$exact_dir/gms-stabilization-logcat.txt" 2>&1 || true

python3 - <<'PY'
from pathlib import Path
path = Path('scripts/apti_exact_https_probe.py')
text = path.read_text(encoding='utf-8')
text = text.replace(
    'result["input_verified"] = bool(username_ok and password_ok and nonempty)',
    '''result["input_verified"] = bool(
        username_ok and password_ok and len(after) >= 2
        and after[0].get("visible_length") == len(credentials["username"])
        and after[1].get("visible_length") == len(credentials["password"])
    )''',
    1,
)
text = text.replace(
    '    component = resolve_adb_keyboard()\n    keyboard_ready = bool(component and enable_adb_keyboard(component))',
    '    component = None\n    keyboard_ready = False',
    1,
)
text = text.replace(
    '''    login_candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):''',
    '''    adb_shell("input", "keyevent", "111", quiet=True)
    time.sleep(0.8)
    root = dump_ui(result_dir, "login-ready-to-submit", credentials)
    screenshot(result_dir, "login-ready-to-submit")

    login_candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):''',
    1,
)
text = text.replace(
    '''    login_candidates.sort(key=lambda item: item[0], reverse=True)
    tap_node(login_candidates[0][1])
    result["login_clicked"] = True
    time.sleep(2)

    observations: list[dict[str, Any]] = []''',
    '''    login_candidates.sort(key=lambda item: item[0], reverse=True)
    submit_center = node_center(login_candidates[0][1])
    result["login_submit_center"] = submit_center
    if submit_center:
        adb_shell("input", "tap", str(submit_center[0]), str(submit_center[1]), quiet=True)
    result["login_clicked"] = bool(submit_center)
    click_started = time.time()
    for rapid_tag, target_delay in (("015", 0.15), ("035", 0.35), ("070", 0.70), ("120", 1.20), ("200", 2.00)):
        remaining = target_delay - (time.time() - click_started)
        if remaining > 0:
            time.sleep(remaining)
        dump_ui(result_dir, f"login-rapid-{rapid_tag}", credentials)
        screenshot(result_dir, f"login-rapid-{rapid_tag}")

    observations: list[dict[str, Any]] = []''',
    1,
)
for old in (
    '    adb_shell("settings", "put", "global", "http_proxy", ":0", quiet=True)\n',
    '    adb_shell("settings", "delete", "global", "global_http_proxy_host", quiet=True)\n',
    '    adb_shell("settings", "delete", "global", "global_http_proxy_port", quiet=True)\n',
):
    text = text.replace(old, '', 1)
path.write_text(text, encoding='utf-8')
PY

export APTI_MITM_OUT_DIR="$mitm_dir"
export APTI_MBL_TOKEN_FILE="/dev/shm/apti-mbl-token.txt"
rm -f "$APTI_MBL_TOKEN_FILE"
mitmdump -q --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set connection_strategy=lazy \
  -s scripts/apti_root_mitm_addon.py \
  -w "$mitm_dir/flows.mitm" \
  > "$mitm_dir/mitmdump.log" 2>&1 &
mitm_pid=$!
sleep 2
adb shell settings put global http_proxy 10.0.2.2:8080
adb shell settings get global http_proxy > "$exact_dir/android-proxy.txt"

adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true
adb shell am start -W -n com.android.chrome/com.google.android.apps.chrome.Main -a android.intent.action.VIEW -d about:blank > "$exact_dir/chrome-prime-start.txt" 2>&1 || true
for index in $(seq 0 24); do
  adb shell uiautomator dump /sdcard/chrome-root-prime.xml >/dev/null 2>&1 || true
  xml="$(adb shell cat /sdcard/chrome-root-prime.xml 2>/dev/null || true)"
  printf '%s' "$xml" > "$exact_dir/chrome-prime-${index}.xml"
  if grep -q 'signin_fre_dismiss_button' <<<"$xml" || grep -q 'text="Use without an account"' <<<"$xml"; then
    adb shell input tap 540 1977; sleep 2; continue
  fi
  if grep -q 'terms_accept' <<<"$xml" || grep -q 'text="Accept &amp; continue"' <<<"$xml"; then
    adb shell input tap 540 2050; sleep 2; continue
  fi
  if grep -q 'text="No thanks"' <<<"$xml"; then
    adb shell input tap 567 1745; sleep 2; continue
  fi
  top="$(adb shell dumpsys activity activities | grep -m1 -E 'topResumedActivity|mResumedActivity' || true)"
  [[ "$top" == *com.android.chrome* && "$top" != *FirstRunActivity* ]] && break
  sleep 1
done
adb exec-out screencap -p > "$exact_dir/chrome-prime-final.png" 2>/dev/null || true
adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true

adb shell am force-stop aptip.app >/dev/null 2>&1 || true
adb shell monkey -p aptip.app -c android.intent.category.LAUNCHER 1 > "$exact_dir/app-launch.txt" 2>&1 || true
sleep 10
adb shell logcat -c >/dev/null 2>&1 || true
adb logcat -v threadtime > "$exact_dir/app-logcat.txt" 2>&1 &
logcat_pid=$!
set +e
python3 scripts/apti_exact_https_probe.py \
  --credentials "${APTI_CREDENTIALS_FILE:-/dev/shm/apti-creds.json}" \
  --result-dir "$APTI_SECURE_RESULT_DIR"
probe_rc=$?
set -e
printf '%s\n' "$probe_rc" > "$exact_dir/probe-return-code.txt"
kill "$logcat_pid" >/dev/null 2>&1 || true
wait "$logcat_pid" >/dev/null 2>&1 || true

if [[ -s "$APTI_MBL_TOKEN_FILE" ]]; then
  python3 - <<'PY' > /dev/shm/apti-auth-deeplink.txt
import os, urllib.parse
from pathlib import Path
token = Path(os.environ['APTI_MBL_TOKEN_FILE']).read_text(encoding='utf-8').strip()
target = 'https://v2notice.apti.co.kr/resource/pages/event/APTI000574/app_event.html?isShare=Y&mbl_token=' + urllib.parse.quote(token, safe='')
print('aptip://aptip.app?link=' + urllib.parse.quote(target, safe=''))
PY
  auth_link="$(cat /dev/shm/apti-auth-deeplink.txt)"
  adb shell am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "$auth_link" aptip.app > "$exact_dir/auth-event-start.txt" 2>&1 || true
  for delay in 3 8 15 25; do
    sleep "$delay"
    adb exec-out screencap -p > "$exact_dir/auth-event-${delay}s.png" 2>/dev/null || true
    adb shell uiautomator dump /sdcard/apti-auth-event.xml >/dev/null 2>&1 || true
    adb shell cat /sdcard/apti-auth-event.xml | sed -E 's/(mbl[_-]?token=)[^&" ]+/\1<redacted>/Ig' > "$exact_dir/auth-event-${delay}s-ui.xml" 2>/dev/null || true
    adb shell dumpsys activity activities | sed -E 's/(mbl[_-]?token=)[^ &}]+/\1<redacted>/Ig' > "$exact_dir/auth-event-${delay}s-activities.txt" 2>/dev/null || true
  done
  printf '{"mbl_token_present":true}\n' > "$exact_dir/authenticated-event-attempt.json"
  rm -f /dev/shm/apti-auth-deeplink.txt
else
  printf '{"mbl_token_present":false}\n' > "$exact_dir/authenticated-event-attempt.json"
fi

adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
kill "$mitm_pid" >/dev/null 2>&1 || true
wait "$mitm_pid" >/dev/null 2>&1 || true
mitm_pid=""
rm -f "$APTI_MBL_TOKEN_FILE"
exit 0
