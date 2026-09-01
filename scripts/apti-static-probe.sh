#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
WORK="$ROOT/.apti-probe"
DOWNLOAD="$WORK/download"
EXTRACT="$WORK/xapk"
REPORT="$ROOT/apti-analysis"
mkdir -p "$DOWNLOAD" "$EXTRACT" "$REPORT"

exec > >(tee "$REPORT/static-probe.log") 2>&1

echo "== environment =="
date -u +'%Y-%m-%dT%H:%M:%SZ'
uname -a
java -version || true
python3 --version || true

echo "== download aptip.app =="
if command -v apkeep >/dev/null 2>&1; then
  apkeep -a aptip.app -d apk-pure "$DOWNLOAD"
else
  docker run --rm -v "$DOWNLOAD:/output" ghcr.io/efforg/apkeep:stable -a aptip.app -d apk-pure /output || {
    cargo install apkeep --locked
    "$HOME/.cargo/bin/apkeep" -a aptip.app -d apk-pure "$DOWNLOAD"
  }
fi

find "$DOWNLOAD" -maxdepth 2 -type f -printf '%p\t%s bytes\n' | tee "$REPORT/download-files.txt"
sha256sum "$DOWNLOAD"/* 2>/dev/null | tee "$REPORT/download-sha256.txt" || true

ARCHIVE="$(find "$DOWNLOAD" -maxdepth 1 -type f \( -iname '*.xapk' -o -iname '*.apks' -o -iname '*.zip' \) -print -quit)"
if [[ -n "${ARCHIVE:-}" ]]; then
  unzip -q "$ARCHIVE" -d "$EXTRACT"
else
  APK="$(find "$DOWNLOAD" -maxdepth 1 -type f -iname '*.apk' -print -quit)"
  [[ -n "${APK:-}" ]] || { echo 'No APK/XAPK downloaded'; exit 2; }
  cp "$APK" "$EXTRACT/base.apk"
fi

find "$EXTRACT" -type f -printf '%P\t%s bytes\n' | sort | tee "$REPORT/xapk-files.txt"

BASE_APK="$(find "$EXTRACT" -type f -iname 'base.apk' -print -quit)"
if [[ -z "${BASE_APK:-}" ]]; then
  BASE_APK="$(find "$EXTRACT" -type f -iname '*.apk' -printf '%s\t%p\n' | sort -nr | head -1 | cut -f2-)"
fi
[[ -n "${BASE_APK:-}" ]] || { echo 'Base APK not found'; exit 3; }
echo "$BASE_APK" | tee "$REPORT/base-apk-path.txt"
sha256sum "$BASE_APK" | tee "$REPORT/base-apk-sha256.txt"

AAPT="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" -type f -name aapt 2>/dev/null | sort -V | tail -1 || true)"
AAPT2="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" -type f -name aapt2 2>/dev/null | sort -V | tail -1 || true)"
if [[ -x "$AAPT" ]]; then
  "$AAPT" dump badging "$BASE_APK" > "$REPORT/aapt-badging.txt" 2>&1 || true
  "$AAPT" dump permissions "$BASE_APK" > "$REPORT/aapt-permissions.txt" 2>&1 || true
  "$AAPT" dump configurations "$BASE_APK" > "$REPORT/aapt-configurations.txt" 2>&1 || true
  "$AAPT" dump xmltree "$BASE_APK" AndroidManifest.xml > "$REPORT/aapt-manifest-tree.txt" 2>&1 || true
fi
if command -v apkanalyzer >/dev/null 2>&1; then
  apkanalyzer manifest print "$BASE_APK" > "$REPORT/manifest.xml" 2>&1 || true
  apkanalyzer manifest min-sdk "$BASE_APK" > "$REPORT/min-sdk.txt" 2>&1 || true
  apkanalyzer manifest target-sdk "$BASE_APK" > "$REPORT/target-sdk.txt" 2>&1 || true
fi

zipinfo -1 "$BASE_APK" | sort > "$REPORT/base-apk-files.txt"
grep -E '^lib/[^/]+/.*\.so$' "$REPORT/base-apk-files.txt" > "$REPORT/native-libraries.txt" || true
cut -d/ -f2 "$REPORT/native-libraries.txt" | sort -u > "$REPORT/native-abis.txt" || true

mkdir -p "$WORK/dex"
while IFS= read -r dex; do
  unzip -p "$BASE_APK" "$dex" > "$WORK/dex/$(basename "$dex")"
done < <(zipinfo -1 "$BASE_APK" | grep -E '^classes[0-9]*\.dex$' || true)

PATTERN='APTI000574|v2notice\.apti\.co\.kr|app_event|aptip://|aptip\.app|deeplink_custom_path|addJavascriptInterface|setWebContentsDebuggingEnabled|WebViewClient|shouldOverrideUrlLoading|shouldInterceptRequest|CustomTabsIntent|androidx\.browser\.customtabs|CookieManager|setCookie|getCookie|Authorization|Bearer|accessToken|refreshToken|JSESSIONID|localStorage|sessionStorage|postMessage|JavascriptInterface|loadUrl'
: > "$REPORT/dex-string-hits.txt"
for dex in "$WORK"/dex/*.dex; do
  [[ -f "$dex" ]] || continue
  echo "### $(basename "$dex")" >> "$REPORT/dex-string-hits.txt"
  strings -a -n 4 "$dex" | grep -Ei "$PATTERN" | sort -u | head -3000 >> "$REPORT/dex-string-hits.txt" || true
done

sudo apt-get update -qq
sudo apt-get install -y -qq apktool jq unzip xz-utils >/dev/null
apktool d -f -r -s "$BASE_APK" -o "$WORK/apktool" >/dev/null 2>&1 || true
if [[ -f "$WORK/apktool/AndroidManifest.xml" ]]; then
  cp "$WORK/apktool/AndroidManifest.xml" "$REPORT/apktool-manifest.xml"
  grep -nEi 'aptip|scheme|host|BROWSABLE|VIEW|exported|WebView|customtab' "$WORK/apktool/AndroidManifest.xml" > "$REPORT/manifest-deeplink-hits.txt" || true
fi

JADX_ZIP="$WORK/jadx.zip"
JADX_URL="$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest | jq -r '.assets[] | select(.name | test("jadx-[0-9.]+\\.zip$")) | .browser_download_url' | head -1)"
if [[ -n "${JADX_URL:-}" && "$JADX_URL" != null ]]; then
  curl -fL --retry 3 "$JADX_URL" -o "$JADX_ZIP"
  mkdir -p "$WORK/jadx-bin" "$WORK/jadx-out"
  unzip -q "$JADX_ZIP" -d "$WORK/jadx-bin"
  "$WORK/jadx-bin/bin/jadx" --no-res --deobf -d "$WORK/jadx-out" "$BASE_APK" > "$REPORT/jadx.log" 2>&1 || true
  if [[ -d "$WORK/jadx-out/sources" ]]; then
    grep -RInE --include='*.java' --include='*.kt' "$PATTERN" "$WORK/jadx-out/sources" | head -10000 > "$REPORT/jadx-target-hits.txt" || true
    grep -RIlE --include='*.java' --include='*.kt' 'addJavascriptInterface|CustomTabsIntent|shouldOverrideUrlLoading|shouldInterceptRequest|setWebContentsDebuggingEnabled|aptip://|v2notice\.apti\.co\.kr' "$WORK/jadx-out/sources" | sort > "$REPORT/jadx-relevant-files.txt" || true
    : > "$REPORT/jadx-relevant-context.txt"
    while IFS= read -r source; do
      [[ -f "$source" ]] || continue
      echo "===== ${source#$WORK/jadx-out/sources/} =====" >> "$REPORT/jadx-relevant-context.txt"
      grep -nE -B12 -A24 'addJavascriptInterface|CustomTabsIntent|shouldOverrideUrlLoading|shouldInterceptRequest|setWebContentsDebuggingEnabled|aptip://|v2notice\.apti\.co\.kr|CookieManager|loadUrl\(' "$source" | head -800 >> "$REPORT/jadx-relevant-context.txt" || true
    done < "$REPORT/jadx-relevant-files.txt"
  fi
fi

{
  echo '== package =='
  grep -E "^package:|^sdkVersion:|^targetSdkVersion:|^application-label:|^launchable-activity:" "$REPORT/aapt-badging.txt" 2>/dev/null || true
  echo
  echo '== native ABIs =='
  cat "$REPORT/native-abis.txt" 2>/dev/null || true
  echo
  echo '== manifest deep-link hits =='
  head -300 "$REPORT/manifest-deeplink-hits.txt" 2>/dev/null || true
  echo
  echo '== high-value JADX hits =='
  grep -Ei 'aptip://|v2notice\.apti\.co\.kr|addJavascriptInterface|setWebContentsDebuggingEnabled|CustomTabsIntent|shouldOverrideUrlLoading|shouldInterceptRequest' "$REPORT/jadx-target-hits.txt" 2>/dev/null | head -1000 || true
} | tee "$REPORT/SUMMARY.txt"

rm -rf "$DOWNLOAD" "$EXTRACT" "$WORK/dex" "$WORK/apktool" "$WORK/jadx-out" "$JADX_ZIP" 2>/dev/null || true
