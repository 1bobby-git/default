#!/usr/bin/env bash
set -Eeuo pipefail

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
  if [[ -n "${tmp_dir:-}" ]]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
exact_dir="$APTI_SECURE_RESULT_DIR/exact-original-https"
mkdir -p "$exact_dir"
tmp_dir="$(mktemp -d -t apti-serial-probe-XXXXXX)"

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

prep_old = '''        labels = current_labels(root)
        write_json(result_dir / f"login-prep-{attempt:02d}-labels.json", labels)

        if any("아이디" in label for label in labels) and any("비밀번호" in label for label in labels):'''
prep_new = '''        labels = current_labels(root)
        write_json(result_dir / f"login-prep-{attempt:02d}-labels.json", labels)
        screenshot(result_dir, f"login-prep-{attempt:02d}")

        if any("아이디" in label for label in labels) and any("비밀번호" in label for label in labels):'''
if prep_old not in text:
    raise SystemExit("exact probe login preparation block was not found")
text = text.replace(prep_old, prep_new, 1)

submit_old = '''    login_candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):'''
submit_new = '''    adb_shell("input", "keyevent", "111", quiet=True)
    time.sleep(0.8)
    root = dump_ui(result_dir, "login-ready-to-submit", credentials)
    screenshot(result_dir, "login-ready-to-submit")

    login_candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):'''
if submit_old not in text:
    raise SystemExit("exact probe login submit preparation block was not found")
text = text.replace(submit_old, submit_new, 1)

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

cat > "$tmp_dir/ui_action.py" <<'PY'
#!/usr/bin/env python3
from __future__ import annotations
import sys
import xml.etree.ElementTree as ET

path = sys.argv[1]
try:
    root = ET.parse(path).getroot()
except Exception:
    print("none 0 0 0")
    raise SystemExit(0)

def label(node):
    return (node.attrib.get("text") or node.attrib.get("content-desc") or "").replace("\n", "").replace(" ", "")

def center(node):
    raw = node.attrib.get("bounds", "")
    try:
        a, b = raw.split("][")
        x1, y1 = [int(v) for v in a.strip("[").split(",")]
        x2, y2 = [int(v) for v in b.strip("]").split(",")]
        return (x1 + x2) // 2, (y1 + y2) // 2
    except Exception:
        return None

nodes = list(root.iter("node"))
editable = [n for n in nodes if "EditText" in n.attrib.get("class", "") or n.attrib.get("editable") == "true"]
if len(editable) >= 2:
    print(f"ready 0 0 {len(editable)}")
    raise SystemExit(0)

for wanted, action in (("시작하기", "start"), ("로그인", "login")):
    candidates = []
    for node in nodes:
        xy = center(node)
        if not xy or label(node) != wanted:
            continue
        score = (100000 if node.attrib.get("clickable") == "true" else 0) + xy[1]
        candidates.append((score, xy))
    if candidates:
        candidates.sort(reverse=True)
        x, y = candidates[0][1]
        print(f"{action} {x} {y} {len(editable)}")
        raise SystemExit(0)

labels = {label(n) for n in nodes if label(n)}
if "이용하기" in labels and any("커뮤니티" in item for item in labels):
    print(f"community 0 0 {len(editable)}")
else:
    print(f"none 0 0 {len(editable)}")
PY
chmod 700 "$tmp_dir/ui_action.py"

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

adb shell am force-stop com.android.chrome >/dev/null 2>&1 || true
adb shell am start -W \
  -n com.android.chrome/com.google.android.apps.chrome.Main \
  -a android.intent.action.VIEW \
  -d about:blank \
  > "$exact_dir/chrome-prime-start.txt" 2>&1 || true

for index in $(seq 0 20); do
  adb shell uiautomator dump /sdcard/chrome-prime.xml >/dev/null 2>&1 || true
  chrome_xml="$(adb shell cat /sdcard/chrome-prime.xml 2>/dev/null || true)"
  printf '%s' "$chrome_xml" > "$exact_dir/chrome-prime-${index}.xml"

  if grep -q 'com.android.chrome:id/signin_fre_dismiss_button' <<<"$chrome_xml"; then
    adb shell input tap 540 1977
    sleep 2
    continue
  fi
  if grep -q 'com.android.chrome:id/negative_button' <<<"$chrome_xml" || grep -q 'text="No thanks"' <<<"$chrome_xml"; then
    adb shell input tap 567 1745
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

adb shell am force-stop aptip.app >/dev/null 2>&1 || true
adb shell monkey -p aptip.app -c android.intent.category.LAUNCHER 1 > "$exact_dir/app-launch.txt" 2>&1 || true

login_ready=0
for index in $(seq 0 24); do
  sleep 1.5
  adb shell uiautomator dump /sdcard/apti-serial-nav.xml >/dev/null 2>&1 || true
  adb shell cat /sdcard/apti-serial-nav.xml > "$exact_dir/serial-nav-${index}.xml" 2>/dev/null || true
  if [[ "$index" -le 8 || "$index" == "12" || "$index" == "18" || "$index" == "24" ]]; then
    adb exec-out screencap -p > "$exact_dir/serial-nav-${index}.png" 2>/dev/null || true
  fi

  read -r action x y editable_count < <(python3 "$tmp_dir/ui_action.py" "$exact_dir/serial-nav-${index}.xml")
  printf '%s\t%s\t%s\t%s\t%s\n' "$index" "$action" "$x" "$y" "$editable_count" >> "$exact_dir/serial-navigation.tsv"
  case "$action" in
    ready)
      login_ready=1
      break
      ;;
    start|login)
      adb shell input tap "$x" "$y"
      sleep 2.5
      ;;
    community)
      adb shell input keyevent 4
      sleep 2
      adb shell input tap 540 2180
      sleep 2
      ;;
    none)
      ;;
  esac
done
printf '%s\n' "$login_ready" > "$exact_dir/login-page-ready.txt"
adb exec-out screencap -p > "$exact_dir/manual-login-page.png" 2>/dev/null || true
adb shell uiautomator dump /sdcard/apti-manual-login.xml >/dev/null 2>&1 || true
adb shell cat /sdcard/apti-manual-login.xml > "$exact_dir/manual-login-page.xml" 2>/dev/null || true

sudo apt-get install -y -qq tcpdump >/dev/null
adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
adb shell logcat -c >/dev/null 2>&1 || true
adb logcat -v threadtime > "$exact_dir/login-and-launch-logcat.txt" 2>&1 &
login_logcat_pid=$!
sudo tcpdump -i any -nn -s160 -U -w "$exact_dir/login-and-launch.pcap" '(udp port 53 or tcp port 53 or tcp port 443)' >/dev/null 2>&1 &
tcpdump_pid=$!
sudo tcpdump -i any -nn -l -A '(udp port 53 or tcp port 53)' > "$exact_dir/login-dns.txt" 2>&1 &
dnsdump_pid=$!

set +e
python3 scripts/apti_exact_https_probe.py --credentials "${APTI_CREDENTIALS_FILE:-/dev/shm/apti-creds.json}" --result-dir "$APTI_SECURE_RESULT_DIR"
exact_probe_rc=$?
set -e
printf '%s\n' "$exact_probe_rc" > "$APTI_SECURE_RESULT_DIR/exact-https-probe-return-code.txt"
printf '%s\n' 'manual-serialized-install' > "$APTI_SECURE_RESULT_DIR/legacy-probe-return-code.txt"

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
