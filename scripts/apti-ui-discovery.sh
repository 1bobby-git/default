#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
WORK="$ROOT/.apti-ui-discovery"
DOWNLOAD="$WORK/download"
EXTRACT="$WORK/xapk"
RESULT="$ROOT/apti-ui-discovery-results"
VERSION="${APTI_VERSION:-3.3.45}"
DIRECT_LINK='aptip://aptip.app?link=https%3A%2F%2Fv2notice.apti.co.kr%2Fresource%2Fpages%2Fevent%2FAPTI000574%2Fapp_event.html%3FisShare%3DY'
mkdir -p "$DOWNLOAD" "$EXTRACT" "$RESULT"
exec > >(tee "$RESULT/run.log") 2>&1

cleanup() {
  [[ -n "${LOGCAT_PID:-}" ]] && kill "$LOGCAT_PID" >/dev/null 2>&1 || true
  [[ -n "${FRIDA_RUNNER_PID:-}" ]] && kill "$FRIDA_RUNNER_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

capture() {
  local label="$1"
  adb exec-out screencap -p > "$RESULT/${label}.png" || true
  adb shell uiautomator dump /sdcard/window.xml >/dev/null 2>&1 || true
  adb pull /sdcard/window.xml "$RESULT/${label}-ui.xml" >/dev/null 2>&1 || true
  adb shell dumpsys activity activities > "$RESULT/${label}-activities.txt" || true
  adb shell cat /proc/net/unix | grep -E 'webview_devtools_remote|chrome_devtools_remote' > "$RESULT/${label}-devtools.txt" || true
}

download_app() {
  docker run --rm -v "$DOWNLOAD:/output" ghcr.io/efforg/apkeep:stable \
    -a "aptip.app@${VERSION}" -d apk-pure /output || true
  if ! find "$DOWNLOAD" -maxdepth 1 -type f -print -quit | grep -q .; then
    docker run --rm -v "$DOWNLOAD:/output" ghcr.io/efforg/apkeep:stable \
      -a aptip.app -d apk-pure /output
  fi
}

adb wait-for-device
adb shell getprop ro.build.version.release | tee "$RESULT/android-release.txt"
adb shell getprop ro.product.cpu.abilist | tee "$RESULT/abilist.txt"

download_app
ARCHIVE="$(find "$DOWNLOAD" -maxdepth 1 -type f \( -iname '*.xapk' -o -iname '*.apks' -o -iname '*.zip' \) -print -quit)"
if [[ -n "${ARCHIVE:-}" ]]; then
  unzip -q "$ARCHIVE" -d "$EXTRACT"
else
  APK="$(find "$DOWNLOAD" -maxdepth 1 -type f -iname '*.apk' -print -quit)"
  [[ -n "${APK:-}" ]] || { echo 'No APK/XAPK downloaded'; exit 2; }
  cp "$APK" "$EXTRACT/base.apk"
fi
mapfile -t APKS < <(find "$EXTRACT" -type f -iname '*.apk' -print | sort)
printf '%s\n' "${APKS[@]}" > "$RESULT/install-apks.txt"
adb install-multiple -r -g "${APKS[@]}" | tee "$RESULT/install.txt"

AAPT="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" -type f -name aapt 2>/dev/null | sort -V | tail -1 || true)"
BASE_APK="$(find "$EXTRACT" -type f \( -iname 'base.apk' -o -iname 'aptip.app.apk' \) -print -quit)"
if [[ -x "$AAPT" && -n "${BASE_APK:-}" ]]; then
  "$AAPT" dump badging "$BASE_APK" > "$RESULT/aapt-badging.txt" 2>&1 || true
fi

python3 -m pip install --disable-pip-version-check -q frida-tools
FRIDA_VERSION="$(python3 - <<'PY'
import frida
print(frida.__version__)
PY
)"
curl -fL --retry 3 \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" \
  -o "$WORK/frida-server.xz"
xz -df "$WORK/frida-server.xz"
adb root >/dev/null 2>&1 || true
adb wait-for-device
adb push "$WORK/frida-server" /data/local/tmp/frida-server >/dev/null
adb shell chmod 755 /data/local/tmp/frida-server
adb shell 'killall frida-server 2>/dev/null || true'
adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida-server.log 2>&1 &' || true
sleep 2

adb logcat -c
adb logcat -v threadtime > "$RESULT/logcat.txt" 2>&1 &
LOGCAT_PID=$!

python3 "$ROOT/scripts/apti-frida-runner.py" \
  "$ROOT/scripts/apti-version-spoof.js" "$RESULT/frida.jsonl" 150 &
FRIDA_RUNNER_PID=$!

sleep 5
capture '01-spawn-5s'
sleep 10
capture '02-spawn-15s'
sleep 15
capture '03-spawn-30s'
sleep 20
capture '04-spawn-50s'

adb shell am start -W -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE -d "$DIRECT_LINK" \
  > "$RESULT/deeplink-start.txt" 2>&1 || true
sleep 5
capture '05-deeplink-5s'
sleep 10
capture '06-deeplink-15s'
sleep 15
capture '07-deeplink-30s'

{
  echo '== package =='
  cat "$RESULT/aapt-badging.txt" 2>/dev/null | grep -E "^package:|^sdkVersion:|^targetSdkVersion:|^application-label:|^launchable-activity:" || true
  echo
  echo '== Frida version events =='
  grep -E 'version_spoof|webview_load_url|webview_add_js_interface|cookie_' "$RESULT/frida.jsonl" 2>/dev/null | head -2000 || true
  echo
  echo '== visible texts after spoof =='
  python3 - "$RESULT" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
root = Path(sys.argv[1])
for path in sorted(root.glob('*-ui.xml')):
    print(f'--- {path.name} ---')
    try:
        tree = ET.parse(path)
    except Exception as exc:
        print(exc)
        continue
    seen = set()
    for node in tree.iter('node'):
        value = (node.attrib.get('text') or node.attrib.get('content-desc') or '').strip()
        if value and value not in seen:
            seen.add(value)
            print(value)
PY
} | tee "$RESULT/SUMMARY.txt"

rm -rf "$DOWNLOAD" "$EXTRACT" "$WORK/frida-server" 2>/dev/null || true
