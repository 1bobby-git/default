#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
WORK="$ROOT/.apti-probe"
DOWNLOAD="$WORK/download"
EXTRACT="$WORK/xapk"
ALL="$WORK/all-apks"
REPORT="$ROOT/apti-analysis"
VERSION="${APTI_VERSION:-3.3.59}"
mkdir -p "$DOWNLOAD" "$EXTRACT" "$ALL" "$REPORT"

exec > >(tee "$REPORT/static-probe.log") 2>&1

download_apti() {
  local app_spec="aptip.app@${VERSION}"
  if command -v apkeep >/dev/null 2>&1; then
    apkeep -a "$app_spec" -d apk-pure "$DOWNLOAD" ||
      apkeep -a aptip.app -d apk-pure "$DOWNLOAD"
    return
  fi
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

echo "== environment =="
date -u +'%Y-%m-%dT%H:%M:%SZ'
uname -a
java -version || true
python3 --version || true

echo "== download aptip.app =="
download_apti
find "$DOWNLOAD" -maxdepth 2 -type f -printf '%p\t%s bytes\n' |
  tee "$REPORT/download-files.txt"
sha256sum "$DOWNLOAD"/* 2>/dev/null |
  tee "$REPORT/download-sha256.txt" || true

ARCHIVE="$(find "$DOWNLOAD" -maxdepth 1 -type f \
  \( -iname '*.xapk' -o -iname '*.apks' -o -iname '*.zip' \) -print -quit)"
if [[ -n "${ARCHIVE:-}" ]]; then
  unzip -q "$ARCHIVE" -d "$EXTRACT"
else
  APK="$(find "$DOWNLOAD" -maxdepth 1 -type f -iname '*.apk' -print -quit)"
  [[ -n "${APK:-}" ]] || { echo 'No APK/XAPK downloaded'; exit 2; }
  cp "$APK" "$EXTRACT/base.apk"
fi

find "$EXTRACT" -type f -printf '%P\t%s bytes\n' | sort |
  tee "$REPORT/xapk-files.txt"
if [[ -f "$EXTRACT/manifest.json" ]]; then
  cp "$EXTRACT/manifest.json" "$REPORT/xapk-manifest.json"
fi

BASE_APK="$(find "$EXTRACT" -type f \
  \( -iname 'base.apk' -o -iname 'aptip.app.apk' \) -print -quit)"
if [[ -z "${BASE_APK:-}" ]]; then
  BASE_APK="$(find "$EXTRACT" -type f -iname '*.apk' -printf '%s\t%p\n' |
    sort -nr | head -1 | cut -f2-)"
fi
[[ -n "${BASE_APK:-}" ]] || { echo 'Base APK not found'; exit 3; }
echo "$BASE_APK" | tee "$REPORT/base-apk-path.txt"
sha256sum "$BASE_APK" | tee "$REPORT/base-apk-sha256.txt"

AAPT="$(find "${ANDROID_HOME:-/usr/local/lib/android/sdk}/build-tools" \
  -type f -name aapt 2>/dev/null | sort -V | tail -1 || true)"
if [[ -x "$AAPT" ]]; then
  "$AAPT" dump badging "$BASE_APK" > "$REPORT/aapt-badging.txt" 2>&1 || true
  "$AAPT" dump permissions "$BASE_APK" > "$REPORT/aapt-permissions.txt" 2>&1 || true
  "$AAPT" dump configurations "$BASE_APK" > "$REPORT/aapt-configurations.txt" 2>&1 || true
  "$AAPT" dump xmltree "$BASE_APK" AndroidManifest.xml > "$REPORT/aapt-manifest-tree.txt" 2>&1 || true
fi

zipinfo -1 "$BASE_APK" | sort > "$REPORT/base-apk-files.txt"

echo "== extract and scan every split APK =="
: > "$REPORT/all-apk-sha256.txt"
: > "$REPORT/all-native-libraries.txt"
: > "$REPORT/all-native-abis.txt"
: > "$REPORT/all-binary-target-hits.txt"
PATTERN='APTI000574|v2notice\.apti\.co\.kr|app_event|isShare|aptip://|aptip\.app|deeplink_custom_path|app\.apti\.co\.kr|api[-a-z0-9.]*\.apti\.co\.kr|azapi\.apti\.co\.kr|addJavascriptInterface|setWebContentsDebuggingEnabled|WebViewClient|shouldOverrideUrlLoading|shouldInterceptRequest|CustomTabsIntent|androidx\.browser\.customtabs|CookieManager|setCookie|getCookie|Authorization|Bearer|accessToken|refreshToken|JSESSIONID|localStorage|sessionStorage|postMessage|JavascriptInterface|loadUrl|login|memberNo|memberId|userNo'

while IFS= read -r apk; do
  name="$(basename "$apk" .apk)"
  dest="$ALL/$name"
  mkdir -p "$dest"
  sha256sum "$apk" >> "$REPORT/all-apk-sha256.txt"
  unzip -q "$apk" -d "$dest" || true
  find "$dest" -type f -path '*/lib/*/*.so' -printf "${name}\t%P\n" \
    >> "$REPORT/all-native-libraries.txt" || true
  find "$dest" -type f -path '*/lib/*/*.so' -printf '%h\n' |
    awk -F/ '{print $NF}' >> "$REPORT/all-native-abis.txt" || true

  while IFS= read -r binary; do
    rel="${binary#$dest/}"
    {
      echo "===== ${name}/${rel} ====="
      strings -a -n 4 "$binary" |
        grep -Ei "$PATTERN" | sort -u | head -12000 || true
    } >> "$REPORT/all-binary-target-hits.txt"
  done < <(find "$dest" -type f \
    \( -name '*.so' -o -name 'classes*.dex' \) -print)
done < <(find "$EXTRACT" -type f -iname '*.apk' -print | sort)

sort -u "$REPORT/all-native-abis.txt" -o "$REPORT/all-native-abis.txt"

echo "== sanitized Flutter environment files =="
python3 - "$ALL" "$REPORT/flutter-env-sanitized.txt" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
out = Path(sys.argv[2])
secret = re.compile(r"(secret|password|passwd|token|api[_-]?key|client[_-]?key)", re.I)
lines = []
for p in root.rglob(".env.*"):
    lines.append(f"===== {p.relative_to(root)} =====")
    text = p.read_text("utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            lines.append(raw)
            continue
        key, value = raw.split("=", 1)
        if secret.search(key):
            value = "<redacted>"
        lines.append(f"{key}={value}")
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "== selected Flutter assets =="
python3 - "$ALL" "$REPORT/flutter-selected-assets.txt" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
out = Path(sys.argv[2])
patterns = (
    "AssetManifest.json", "NativeAssetsManifest.json",
    "network_security_config.xml", "fingeWebInerface.js",
)
url_re = re.compile(r"https?://[^\s\"'<>]+|(?:[A-Za-z0-9-]+\.)+apti\.co\.kr", re.I)
lines = []
for p in root.rglob("*"):
    if not p.is_file():
        continue
    if p.name not in patterns:
        continue
    lines.append(f"===== {p.relative_to(root)} =====")
    text = p.read_text("utf-8", errors="replace")
    hits = sorted(set(url_re.findall(text)))
    lines.extend(hits[:5000])
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

sudo apt-get update -qq
sudo apt-get install -y -qq apktool jq unzip xz-utils >/dev/null

echo "== JADX base APK analysis =="
JADX_ZIP="$WORK/jadx.zip"
JADX_URL="$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest |
  jq -r '.assets[] | select(.name | test("jadx-[0-9.]+\\.zip$")) | .browser_download_url' |
  head -1)"
if [[ -n "${JADX_URL:-}" && "$JADX_URL" != null ]]; then
  curl -fL --retry 3 "$JADX_URL" -o "$JADX_ZIP"
  mkdir -p "$WORK/jadx-bin" "$WORK/jadx-out"
  unzip -q "$JADX_ZIP" -d "$WORK/jadx-bin"
  "$WORK/jadx-bin/bin/jadx" --no-res --deobf -d "$WORK/jadx-out" \
    "$BASE_APK" > "$REPORT/jadx.log" 2>&1 || true
  if [[ -d "$WORK/jadx-out/sources" ]]; then
    grep -RInE --include='*.java' --include='*.kt' "$PATTERN" \
      "$WORK/jadx-out/sources" | head -16000 > "$REPORT/jadx-target-hits.txt" || true
    for source in \
      "$WORK/jadx-out/sources/aptip/app/MainActivity.java" \
      "$WORK/jadx-out/sources/aptip/app/App.java"; do
      [[ -f "$source" ]] || continue
      cp "$source" "$REPORT/$(basename "$source")"
    done
  fi
fi

{
  echo '== package =='
  grep -E "^package:|^sdkVersion:|^targetSdkVersion:|^application-label:|^launchable-activity:" \
    "$REPORT/aapt-badging.txt" 2>/dev/null || true
  echo
  echo '== APK splits =='
  cat "$REPORT/xapk-files.txt" 2>/dev/null || true
  echo
  echo '== native ABIs =='
  cat "$REPORT/all-native-abis.txt" 2>/dev/null || true
  echo
  echo '== MainActivity deep-link manifest =='
  grep -nE -B12 -A18 'aptip\.app\.MainActivity|flutter_deeplinking_enabled|android:scheme.*aptip|android:host.*aptip\.app' \
    "$REPORT/aapt-manifest-tree.txt" 2>/dev/null | head -600 || true
  echo
  echo '== environment URLs =='
  grep -Ei 'https?://|apti\.co\.kr' "$REPORT/flutter-env-sanitized.txt" 2>/dev/null || true
  echo
  echo '== Flutter/native high-value strings =='
  grep -Ei 'v2notice\.apti\.co\.kr|app_event|APTI000574|isShare|aptip://|deeplink_custom_path|api[-a-z0-9.]*\.apti\.co\.kr|azapi\.apti\.co\.kr' \
    "$REPORT/all-binary-target-hits.txt" 2>/dev/null | head -4000 || true
  echo
  echo '== app-owned Java channel hits =='
  grep -E '/sources/aptip/app/' "$REPORT/jadx-target-hits.txt" 2>/dev/null | head -1000 || true
} | tee "$REPORT/SUMMARY.txt"

rm -rf "$DOWNLOAD" "$EXTRACT" "$ALL" "$WORK/jadx-out" "$JADX_ZIP" 2>/dev/null || true
