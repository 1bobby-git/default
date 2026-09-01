#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
WORK="$ROOT/.apti-runtime"
DOWNLOAD="$WORK/download"
EXTRACT="$WORK/xapk"
RESULT="$ROOT/apti-runtime-results"
VERSION="${APTI_VERSION:-3.3.59}"
DIRECT_LINK='aptip://aptip.app?link=https%3A%2F%2Fv2notice.apti.co.kr%2Fresource%2Fpages%2Fevent%2FAPTI000574%2Fapp_event.html%3FisShare%3DY'
TRACKING_URL='https://app.apti.co.kr/api/v1/click/St0R8GzQi0yXMdVxcboKLA?deeplink_custom_path=aptip%3A%2F%2Faptip.app%3Flink%3Dhttps%253A%252F%252Fv2notice.apti.co.kr%252Fresource%252Fpages%252Fevent%252FAPTI000574%252Fapp_event.html%253FisShare%253DY&abx_tracker_id=St0R8GzQi0yXMdVxcboKLA'

mkdir -p "$DOWNLOAD" "$EXTRACT" "$RESULT"
exec > >(tee "$RESULT/runtime-probe.log") 2>&1

cleanup() {
  adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
  [[ -n "${LOGCAT_PID:-}" ]] && kill "$LOGCAT_PID" >/dev/null 2>&1 || true
  [[ -n "${FRIDA_PID:-}" ]] && kill "$FRIDA_PID" >/dev/null 2>&1 || true
  [[ -n "${MITM_PID:-}" ]] && kill "$MITM_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

download_apti() {
  local app_spec="aptip.app@${VERSION}"
  docker run --rm -v "$DOWNLOAD:/output" ghcr.io/efforg/apkeep:stable \
    -a "$app_spec" -d apk-pure /output ||
  docker run --rm -v "$DOWNLOAD:/output" ghcr.io/efforg/apkeep:stable \
    -a aptip.app -d apk-pure /output ||
  {
    cargo install apkeep --locked
    "$HOME/.cargo/bin/apkeep" -a "$app_spec" -d apk-pure "$DOWNLOAD" ||
      "$HOME/.cargo/bin/apkeep" -a aptip.app -d apk-pure "$DOWNLOAD"
  }
}

capture_state() {
  local label="$1"
  adb exec-out screencap -p > "$RESULT/${label}.png" || true
  adb shell uiautomator dump /sdcard/window.xml >/dev/null 2>&1 || true
  adb pull /sdcard/window.xml "$RESULT/${label}-ui.xml" >/dev/null 2>&1 || true
  adb shell dumpsys activity activities > "$RESULT/${label}-activities.txt" || true
  adb shell dumpsys window windows > "$RESULT/${label}-windows.txt" || true
  adb shell cat /proc/net/unix | grep -E 'webview_devtools_remote|chrome_devtools_remote' \
    > "$RESULT/${label}-devtools-sockets.txt" || true
}

echo "== emulator =="
adb wait-for-device
adb shell getprop > "$RESULT/getprop.txt"
adb shell getprop ro.product.cpu.abilist | tee "$RESULT/emulator-abilist.txt"
adb shell getprop ro.build.version.release | tee "$RESULT/android-release.txt"
adb shell getprop ro.build.version.sdk | tee "$RESULT/android-sdk.txt"
adb shell wm size | tee "$RESULT/display-size.txt"

echo "== download app =="
download_apti
ARCHIVE="$(find "$DOWNLOAD" -maxdepth 1 -type f \
  \( -iname '*.xapk' -o -iname '*.apks' -o -iname '*.zip' \) -print -quit)"
if [[ -n "${ARCHIVE:-}" ]]; then
  unzip -q "$ARCHIVE" -d "$EXTRACT"
else
  APK="$(find "$DOWNLOAD" -maxdepth 1 -type f -iname '*.apk' -print -quit)"
  [[ -n "${APK:-}" ]] || { echo 'No APK/XAPK downloaded'; exit 2; }
  cp "$APK" "$EXTRACT/base.apk"
fi
find "$EXTRACT" -type f -printf '%P\t%s bytes\n' | sort > "$RESULT/xapk-files.txt"
sha256sum "$DOWNLOAD"/* > "$RESULT/download-sha256.txt" || true

BASE_APK="$(find "$EXTRACT" -type f \
  \( -iname 'base.apk' -o -iname 'aptip.app.apk' \) -print -quit)"
AAPT="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" \
  -type f -name aapt 2>/dev/null | sort -V | tail -1 || true)"
if [[ -x "$AAPT" && -n "${BASE_APK:-}" ]]; then
  "$AAPT" dump badging "$BASE_APK" > "$RESULT/aapt-badging.txt" 2>&1 || true
  "$AAPT" dump xmltree "$BASE_APK" AndroidManifest.xml > "$RESULT/manifest-tree.txt" 2>&1 || true
fi

echo "== install split APK set =="
mapfile -t APK_FILES < <(find "$EXTRACT" -type f -iname '*.apk' -print | sort)
printf '%s\n' "${APK_FILES[@]}" > "$RESULT/install-apks.txt"
set +e
adb install-multiple -r -g "${APK_FILES[@]}" > "$RESULT/install.txt" 2>&1
INSTALL_RC=$?
set -e
cat "$RESULT/install.txt"
if [[ $INSTALL_RC -ne 0 ]]; then
  echo "All-split installation failed; retrying only base, Korean, density and ABI splits."
  mapfile -t SELECTED < <(find "$EXTRACT" -type f -iname '*.apk' |
    grep -E '/(base|aptip\.app|config\.ko|config\.(mdpi|hdpi|xhdpi|xxhdpi|xxxhdpi)|config\.(armeabi_v7a|arm64_v8a|x86|x86_64))\.apk$' || true)
  adb install-multiple -r -g "${SELECTED[@]}" > "$RESULT/install-retry.txt" 2>&1
  cat "$RESULT/install-retry.txt"
fi

adb shell dumpsys package aptip.app > "$RESULT/package-dump.txt"
adb shell cmd package resolve-activity --brief aptip.app |
  tee "$RESULT/launcher-activity.txt" || true

for permission in \
  android.permission.POST_NOTIFICATIONS \
  android.permission.CAMERA \
  android.permission.READ_PHONE_STATE \
  android.permission.READ_PHONE_NUMBERS \
  android.permission.READ_MEDIA_IMAGES \
  android.permission.READ_EXTERNAL_STORAGE \
  android.permission.WRITE_EXTERNAL_STORAGE; do
  adb shell pm grant aptip.app "$permission" >/dev/null 2>&1 || true
done

echo "== start logging =="
adb logcat -c
adb logcat -v threadtime > "$RESULT/logcat-full.txt" 2>&1 &
LOGCAT_PID=$!

echo "== start sanitized MITM capture and install CA =="
python3 -m pip install --disable-pip-version-check -q mitmproxy websocket-client frida-tools
APTI_MITM_JSONL="$RESULT/mitm-network.jsonl" \
  mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set connection_strategy=lazy \
  -s "$ROOT/scripts/apti-mitm-addon.py" > "$RESULT/mitm.log" 2>&1 &
MITM_PID=$!
for _ in $(seq 1 30); do
  [[ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.cer" ]] && break
  sleep 1
done

CERT_OK=0
if [[ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.cer" ]]; then
  adb root >/dev/null 2>&1 || true
  adb wait-for-device
  adb remount > "$RESULT/adb-remount.txt" 2>&1 || true
  CERT_HASH="$(openssl x509 -inform PEM -subject_hash_old \
    -in "$HOME/.mitmproxy/mitmproxy-ca-cert.cer" | head -1)"
  cp "$HOME/.mitmproxy/mitmproxy-ca-cert.cer" "$WORK/${CERT_HASH}.0"
  if adb push "$WORK/${CERT_HASH}.0" "/system/etc/security/cacerts/${CERT_HASH}.0" \
    > "$RESULT/ca-push.txt" 2>&1; then
    adb shell chmod 644 "/system/etc/security/cacerts/${CERT_HASH}.0" || true
    CERT_OK=1
  fi
fi
echo "$CERT_OK" > "$RESULT/system-ca-installed.txt"
if [[ $CERT_OK -eq 1 ]]; then
  adb shell settings put global http_proxy 10.0.2.2:8080
fi

echo "== launch app =="
adb shell am force-stop aptip.app || true
adb shell monkey -p aptip.app -c android.intent.category.LAUNCHER 1 \
  > "$RESULT/monkey-launch.txt" 2>&1 || true
sleep 10
capture_state "01-initial"

echo "== start Frida hook =="
FRIDA_VERSION="$(python3 - <<'PY'
import frida
print(frida.__version__)
PY
)"
curl -fL --retry 3 \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" \
  -o "$WORK/frida-server.xz" || true
if [[ -s "$WORK/frida-server.xz" ]]; then
  xz -df "$WORK/frida-server.xz"
  adb root >/dev/null 2>&1 || true
  adb wait-for-device
  adb push "$WORK/frida-server" /data/local/tmp/frida-server >/dev/null
  adb shell chmod 755 /data/local/tmp/frida-server
  adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &' || true
  sleep 2
  APP_PID="$(adb shell pidof aptip.app | tr -d '\r' | awk '{print $1}')"
  if [[ -n "${APP_PID:-}" ]]; then
    frida -U -p "$APP_PID" -l "$ROOT/scripts/apti-frida-hook.js" \
      > "$RESULT/frida.log" 2>&1 &
    FRIDA_PID=$!
    sleep 3
  fi
fi

echo "== send Apti deep link =="
adb shell am start -W -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE -d "$DIRECT_LINK" \
  > "$RESULT/deeplink-start.txt" 2>&1 || true
cat "$RESULT/deeplink-start.txt"
sleep 5
capture_state "02-deeplink-5s"
sleep 10
capture_state "03-deeplink-15s"
sleep 15
capture_state "04-deeplink-30s"

echo "== inspect and attach CDP =="
python3 - <<'PY' "$RESULT/04-deeplink-30s-devtools-sockets.txt" "$RESULT/devtools-socket-names.txt"
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text("utf-8", errors="replace")
names = []
for line in text.splitlines():
    match = re.search(r"@((?:webview|chrome)_devtools_remote[^ ]*)", line)
    if match and match.group(1) not in names:
        names.append(match.group(1))
Path(sys.argv[2]).write_text("\n".join(names) + "\n", encoding="utf-8")
PY

PORT=9222
while IFS= read -r socket; do
  [[ -n "$socket" ]] || continue
  adb forward --remove "tcp:${PORT}" >/dev/null 2>&1 || true
  if adb forward "tcp:${PORT}" "localabstract:${socket}"; then
    sleep 2
    curl -fsS "http://127.0.0.1:${PORT}/json/list" \
      > "$RESULT/cdp-${PORT}-targets.json" || true
    python3 "$ROOT/scripts/apti-cdp-capture.py" "$PORT" \
      "$RESULT/cdp-${PORT}" > "$RESULT/cdp-${PORT}.log" 2>&1 || true
  fi
  PORT=$((PORT + 1))
done < "$RESULT/devtools-socket-names.txt"

sleep 5
capture_state "05-after-cdp"

echo "== launch tracking URL through Android resolver =="
adb shell am start -W -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE -d "$TRACKING_URL" \
  > "$RESULT/tracking-url-start.txt" 2>&1 || true
sleep 10
capture_state "06-tracking-url"

echo "== summaries =="
grep -aE 'APTI_PROBE|chromium|WebView|flutter|aptip|v2notice|app_event|SSL|CertPath|Handshake|net::' \
  "$RESULT/logcat-full.txt" | tail -20000 > "$RESULT/logcat-relevant.txt" || true

{
  echo '== installed app =='
  grep -E "^package:|^sdkVersion:|^targetSdkVersion:|^application-label:|^launchable-activity:" \
    "$RESULT/aapt-badging.txt" 2>/dev/null || true
  echo
  echo '== deep-link resolver =='
  cat "$RESULT/deeplink-start.txt" 2>/dev/null || true
  echo
  echo '== visible activity after deep link =='
  grep -E 'mResumedActivity|topResumedActivity|ResumedActivity|ACTIVITY ' \
    "$RESULT/04-deeplink-30s-activities.txt" 2>/dev/null | head -200 || true
  echo
  echo '== devtools sockets =='
  cat "$RESULT/devtools-socket-names.txt" 2>/dev/null || true
  echo
  echo '== Frida high-value events =='
  grep -aE 'webview_load_url|webview_add_js_interface|webview_set_user_agent|cookie_|custom_tab_launch|activity_start|main_on_new_intent' \
    "$RESULT/frida.log" 2>/dev/null | head -4000 || true
  echo
  echo '== CDP Apti requests =='
  grep -RhiE 'apti\.co\.kr|v2notice|app_event|APTI000574' \
    "$RESULT"/cdp-*/cdp-network.jsonl 2>/dev/null | head -6000 || true
  echo
  echo '== MITM Apti requests =='
  grep -Ei 'apti\.co\.kr|v2notice|app_event|APTI000574' \
    "$RESULT/mitm-network.jsonl" 2>/dev/null | head -6000 || true
} | tee "$RESULT/SUMMARY.txt"

rm -rf "$DOWNLOAD" "$EXTRACT" "$WORK/frida-server" "$WORK/frida-server.xz" 2>/dev/null || true
