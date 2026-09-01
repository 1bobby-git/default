#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mkdir -p .apti-sensitive-results

if ! adb shell pm path com.android.chrome 2>/dev/null | grep -q '^package:'; then
  chrome_work="$(mktemp -d)"
  cleanup_chrome() { rm -rf "$chrome_work"; }
  trap cleanup_chrome RETURN
  curl -fL --retry 5 'https://d.apkpure.net/b/XAPK/com.android.chrome?version=latest' -o "$chrome_work/chrome.xapk"
  mkdir -p "$chrome_work/xapk"
  unzip -q "$chrome_work/chrome.xapk" -d "$chrome_work/xapk"
  mapfile -t chrome_apks < <(find "$chrome_work/xapk" -type f -name '*.apk' -print | sort)
  if ((${#chrome_apks[@]})); then
    adb install-multiple -r -g "${chrome_apks[@]}" > .apti-sensitive-results/chrome-install.txt 2>&1 || true
  fi
  rm -rf "$chrome_work"
  trap - RETURN
fi

set +e
python3 scripts/apti_v4_probe.py
probe_rc=$?
set -e

exit "$probe_rc"
