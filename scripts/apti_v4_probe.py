#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd()))
OUT = ROOT / ".apti-sensitive-results"
OUT.mkdir(parents=True, exist_ok=True)
WORK = Path(tempfile.mkdtemp(prefix="apti-v4-"))
CREDENTIALS_FILE = Path(os.environ.get("APTI_CREDENTIALS_FILE", "/dev/shm/apti-creds.json"))
XAPK_URL = os.environ.get("APTI_XAPK_URL", "https://d.apkpure.net/b/XAPK/aptip.app?version=latest")
XAPK_SHA256 = os.environ.get("APTI_XAPK_SHA256", "")
PACKAGE = "aptip.app"
MAIN_ACTIVITY = "aptip.app/.MainActivity"
ORIGINAL_URL = (
    "https://app.apti.co.kr/api/v1/click/St0R8GzQi0yXMdVxcboKLA"
    "?deeplink_custom_path=aptip%3A%2F%2Faptip.app%3Flink%3Dhttps%253A%252F%252F"
    "v2notice.apti.co.kr%252Fresource%252Fpages%252Fevent%252FAPTI000574%252F"
    "app_event.html%253FisShare%253DY&abx_tracker_id=St0R8GzQi0yXMdVxcboKLA"
)
TARGET_HOST = "v2notice.apti.co.kr"
TARGET_PATH = "/resource/pages/event/APTI000574/app_event.html"
LOG = OUT / "probe.log"
SECRET_VALUES: list[str] = []
PROCESSES: list[subprocess.Popen[Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def redact(text: str) -> str:
    value = str(text)
    for secret in SECRET_VALUES:
        if secret:
            value = value.replace(secret, "<credential-redacted>")
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 <redacted>", value)
    value = re.sub(
        r"(?i)((?:authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|password|passwd|session(?:id)?|jwt|secret)\s*[:=]\s*)([^\s,;}\]\"']+|\"[^\"]*\"|'[^']*')",
        r"\1<redacted>",
        value,
    )
    return value


def log(message: str) -> None:
    row = f"[{now()}] {redact(message)}"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(row + "\n")
    print(row, flush=True)


def run(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    timeout: float | None = 120,
    sensitive: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if not sensitive:
        log("$ " + " ".join(shlex.quote(redact(part)) for part in args))
    result = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        timeout=timeout,
        env=env,
    )
    if capture and result.stdout and not sensitive:
        text = redact(result.stdout)
        with LOG.open("a", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {args[0]}")
    return result


def adb(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["adb", *args], **kwargs)


def adb_shell(command: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["adb", "shell", command], **kwargs)


def wait_for_device(timeout: int = 240) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = run(["adb", "get-state"], check=False, timeout=10)
        if result.returncode == 0 and "device" in (result.stdout or ""):
            boot = adb_shell("getprop sys.boot_completed", check=False, timeout=10)
            if (boot.stdout or "").strip() == "1":
                return
        time.sleep(2)
    raise TimeoutError("Android emulator did not become ready")


def screen_size() -> tuple[int, int]:
    result = adb_shell("wm size", check=False)
    match = re.search(r"(\d+)x(\d+)", result.stdout or "")
    return (int(match.group(1)), int(match.group(2))) if match else (1080, 2340)


def screenshot(name: str) -> None:
    path = OUT / f"{name}.png"
    with path.open("wb") as handle:
        subprocess.run(["adb", "exec-out", "screencap", "-p"], stdout=handle, stderr=subprocess.DEVNULL, check=False)


def sanitize_xml(xml: str) -> str:
    value = redact(xml)
    # 입력 필드에 남은 텍스트는 값 대신 길이만 남깁니다.
    def repl(match: re.Match[str]) -> str:
        text = match.group(1)
        if not text:
            return match.group(0)
        return 'text="<input-redacted>"'
    value = re.sub(r'text="([^"]+)"(?=[^>]*(?:class="android\.widget\.EditText"|password="true"))', repl, value)
    return value


def dump_ui(name: str, attempts: int = 5) -> tuple[str, list[dict[str, Any]]]:
    xml = ""
    for _ in range(attempts):
        adb_shell("uiautomator dump /sdcard/apti-window.xml", check=False, timeout=20)
        result = adb_shell("cat /sdcard/apti-window.xml", check=False, timeout=20, sensitive=True)
        xml = result.stdout or ""
        if "<hierarchy" in xml:
            break
        time.sleep(1)
    (OUT / f"{name}-ui.xml").write_text(sanitize_xml(xml), encoding="utf-8")
    nodes: list[dict[str, Any]] = []
    if "<hierarchy" not in xml:
        return xml, nodes
    try:
        root = ET.fromstring(xml)
        for node in root.iter("node"):
            attrs = dict(node.attrib)
            bounds = attrs.get("bounds", "")
            match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
            if not match:
                continue
            x1, y1, x2, y2 = map(int, match.groups())
            label = (attrs.get("content-desc") or attrs.get("text") or "").replace("\n", " ").strip()
            nodes.append(
                {
                    "label": label,
                    "text": attrs.get("text", ""),
                    "desc": attrs.get("content-desc", ""),
                    "class": attrs.get("class", ""),
                    "clickable": attrs.get("clickable") == "true",
                    "focusable": attrs.get("focusable") == "true",
                    "focused": attrs.get("focused") == "true",
                    "password": attrs.get("password") == "true",
                    "bounds": (x1, y1, x2, y2),
                    "center": ((x1 + x2) // 2, (y1 + y2) // 2),
                    "area": max(0, x2 - x1) * max(0, y2 - y1),
                }
            )
    except Exception as exc:
        log(f"UI parse failed: {exc}")
    return xml, nodes


def labels(nodes: Iterable[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    for node in nodes:
        label = re.sub(r"\s+", " ", str(node.get("label", ""))).strip()
        if label and label not in result:
            result.append(redact(label))
    return result


def tap_xy(x: int, y: int) -> None:
    adb_shell(f"input tap {int(x)} {int(y)}", check=False, timeout=20)


def tap_matching(
    nodes: list[dict[str, Any]],
    pattern: str,
    *,
    min_y: int = 0,
    max_y: int = 100000,
    prefer_lowest: bool = False,
    exact: bool = False,
) -> bool:
    regex = re.compile(pattern, re.I)
    candidates = []
    for node in nodes:
        label = re.sub(r"\s+", " ", str(node.get("label", ""))).strip()
        y = node["center"][1]
        matched = label == pattern if exact else bool(regex.search(label))
        if matched and min_y <= y <= max_y:
            candidates.append(node)
    if not candidates:
        return False
    candidates.sort(
        key=lambda item: (
            0 if item.get("clickable") else 1,
            -item["center"][1] if prefer_lowest else item["center"][1],
            item.get("area", 0),
        )
    )
    x, y = candidates[0]["center"]
    tap_xy(x, y)
    return True


def wait_ui(predicate, timeout: float, prefix: str) -> tuple[str, list[dict[str, Any]]]:
    deadline = time.time() + timeout
    index = 0
    last = ("", [])
    while time.time() < deadline:
        last = dump_ui(f"{prefix}-{index:02d}")
        if predicate(last[1]):
            return last
        index += 1
        time.sleep(1)
    return last


def has_label(nodes: list[dict[str, Any]], pattern: str) -> bool:
    regex = re.compile(pattern, re.I)
    return any(regex.search(re.sub(r"\s+", " ", str(node.get("label", ""))).strip()) for node in nodes)


def handle_common_dialogs(duration: float = 20) -> None:
    deadline = time.time() + duration
    while time.time() < deadline:
        _, nodes = dump_ui("dialog-scan")
        acted = False
        for pattern in [
            r"^시작하기$",
            r"^앱 사용 중에만 허용$",
            r"^사용 중에만 허용$",
            r"^허용$",
            r"^확인$",
            r"^동의$",
            r"^나중에$",
            r"^건너뛰기$",
            r"^닫기$",
            r"^오늘 그만보기$",
        ]:
            if tap_matching(nodes, pattern, min_y=200, prefer_lowest=True):
                acted = True
                time.sleep(1)
                break
        if not acted:
            time.sleep(1)


def download_and_install_app() -> None:
    xapk = WORK / "apti.xapk"
    run(["curl", "-fL", "--retry", "5", XAPK_URL, "-o", str(xapk)], timeout=300)
    if XAPK_SHA256:
        result = run(["sha256sum", str(xapk)])
        actual = (result.stdout or "").split()[0].lower()
        if actual != XAPK_SHA256.lower():
            raise RuntimeError(f"XAPK SHA256 mismatch: {actual}")
    extract = WORK / "xapk"
    extract.mkdir()
    run(["unzip", "-q", str(xapk), "-d", str(extract)])
    apks = sorted(str(path) for path in extract.rglob("*.apk"))
    if not apks:
        raise RuntimeError("No APK files in XAPK")
    result = adb("install-multiple", "-r", "-g", *apks, check=False, timeout=300)
    if result.returncode != 0:
        base = next((path for path in apks if path.endswith("aptip.app.apk") or path.endswith("base.apk")), apks[0])
        adb("install", "-r", "-g", base, timeout=300)
    adb_shell(f"dumpsys package {PACKAGE}", check=False, timeout=60).stdout
    (OUT / "installed-apks.txt").write_text("\n".join(Path(item).name for item in apks) + "\n", encoding="utf-8")


def start_mitm_and_install_ca() -> subprocess.Popen[Any] | None:
    mitm_jsonl = OUT / "mitm-network.jsonl"
    env = os.environ.copy()
    env["APTI_MITM_JSONL"] = str(mitm_jsonl)
    process = subprocess.Popen(
        [
            "mitmdump",
            "--listen-host",
            "0.0.0.0",
            "--listen-port",
            "8080",
            "--set",
            "block_global=false",
            "--set",
            "connection_strategy=lazy",
            "-s",
            str(ROOT / "scripts/apti_v4_mitm.py"),
        ],
        stdout=(OUT / "mitm.log").open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        env=env,
    )
    PROCESSES.append(process)
    cert = Path.home() / ".mitmproxy/mitmproxy-ca-cert.cer"
    deadline = time.time() + 30
    while time.time() < deadline and not cert.exists():
        time.sleep(0.5)
    if not cert.exists():
        log("mitmproxy CA was not generated")
        return process

    # Android 15 writable-system 이미지는 verity 해제 뒤 재부팅이 필요합니다.
    adb("root", check=False, timeout=30)
    disable = adb("disable-verity", check=False, timeout=60)
    if "reboot" in (disable.stdout or "").lower() or "disabled" in (disable.stdout or "").lower():
        adb("reboot", check=False, timeout=20)
        wait_for_device(300)
        adb("root", check=False, timeout=30)
    adb("remount", check=False, timeout=120)
    hash_result = run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert)], timeout=30)
    cert_hash = (hash_result.stdout or "").splitlines()[0].strip()
    remote = f"/system/etc/security/cacerts/{cert_hash}.0"
    push = adb("push", str(cert), remote, check=False, timeout=60)
    if push.returncode == 0:
        adb_shell(f"chmod 644 {shlex.quote(remote)}", check=False)
        (OUT / "system-ca-installed.txt").write_text("yes\n", encoding="utf-8")
    else:
        (OUT / "system-ca-installed.txt").write_text("no\n", encoding="utf-8")
    adb_shell("settings put global http_proxy 10.0.2.2:8080", check=False)
    return process


def launch_app() -> None:
    for permission in [
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.CAMERA",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
    ]:
        adb_shell(f"pm grant {PACKAGE} {permission}", check=False)
    adb_shell(f"am force-stop {PACKAGE}", check=False)
    adb_shell(f"monkey -p {PACKAGE} -c android.intent.category.LAUNCHER 1", check=False, timeout=30)
    time.sleep(8)
    handle_common_dialogs(25)
    screenshot("01-app-initial")
    dump_ui("01-app-initial")


def start_logcat() -> None:
    adb("logcat", "-c", check=False)
    handle = (OUT / "logcat.txt").open("w", encoding="utf-8")
    process = subprocess.Popen(["adb", "logcat", "-v", "threadtime"], stdout=handle, stderr=subprocess.STDOUT)
    PROCESSES.append(process)


def start_frida() -> subprocess.Popen[Any] | None:
    try:
        version = run([sys.executable, "-c", "import frida; print(frida.__version__)"], timeout=30).stdout.strip()
        abi = (adb_shell("getprop ro.product.cpu.abi", check=False).stdout or "x86_64").strip()
        frida_abi = "x86_64" if "x86_64" in abi else ("arm64" if "arm64" in abi else abi)
        archive = WORK / "frida-server.xz"
        binary = WORK / "frida-server"
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{frida_abi}.xz"
        run(["curl", "-fL", "--retry", "5", url, "-o", str(archive)], timeout=300)
        run(["xz", "-df", str(archive)], timeout=120)
        adb("root", check=False, timeout=30)
        adb("push", str(binary), "/data/local/tmp/frida-server", timeout=120)
        adb_shell("chmod 755 /data/local/tmp/frida-server", check=False)
        adb_shell("pkill -f /data/local/tmp/frida-server || true", check=False)
        adb_shell("nohup /data/local/tmp/frida-server >/data/local/tmp/frida-server.log 2>&1 &", check=False)
        time.sleep(2)
        pid = (adb_shell(f"pidof {PACKAGE}", check=False).stdout or "").strip().split()
        if not pid:
            return None
        log_handle = (OUT / "frida.txt").open("w", encoding="utf-8")
        process = subprocess.Popen(
            ["frida", "-U", "-p", pid[0], "-l", str(ROOT / "scripts/apti_v4_frida.js"), "--runtime=v8"],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        PROCESSES.append(process)
        time.sleep(4)
        return process
    except Exception as exc:
        log(f"Frida startup failed: {exc}")
        return None


def input_text_secret(value: str) -> None:
    # subprocess 목록 인수로 전달하여 호스트 셸의 !, &, %, 공백 확장을 피합니다.
    subprocess.run(
        ["adb", "shell", "input", "text", value.replace(" ", "%s")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )


def clear_focused_field() -> None:
    adb_shell("input keyevent KEYCODE_MOVE_END", check=False)
    adb("shell", "input", "keyevent", *("KEYCODE_DEL" for _ in range(96)), check=False, timeout=30, sensitive=True)


def locate_fields(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = [node for node in nodes if "EditText" in node.get("class", "")]
    if len(fields) >= 2:
        return sorted(fields, key=lambda item: item["center"][1])[:2]
    semantic = [
        node
        for node in nodes
        if re.search(r"아이디|비밀번호|ID|password", str(node.get("label", "")), re.I)
        and node["center"][1] > 350
        and (node.get("focusable") or node.get("clickable"))
    ]
    semantic.sort(key=lambda item: item["center"][1])
    unique: list[dict[str, Any]] = []
    for node in semantic:
        if not any(abs(node["center"][1] - old["center"][1]) < 80 for old in unique):
            unique.append(node)
    return unique[:2]


def login(username: str, password: str) -> dict[str, Any]:
    result: dict[str, Any] = {"attempted": False, "success": False, "reason": "unknown"}
    _, nodes = dump_ui("02-before-login-navigation")
    current_labels = labels(nodes)
    if has_label(nodes, r"로그아웃|마이페이지|내 아파트|회원정보") and not has_label(nodes, r"비밀번호"):
        result.update({"success": True, "reason": "already_logged_in", "labels": current_labels[:100]})
        return result

    # 홈 상단의 로그인 버튼으로 진입합니다.
    if not has_label(nodes, r"비밀번호"):
        tap_matching(nodes, r"^로그인$", min_y=100, max_y=800)
        time.sleep(3)
        _, nodes = dump_ui("03-login-screen")

    # 기본 휴대폰 번호 탭이면 아이디 탭으로 전환합니다.
    id_candidates = [
        node for node in nodes
        if re.fullmatch(r"\s*아이디\s*", re.sub(r"\s+", " ", str(node.get("label", ""))), re.I)
        and node["center"][1] > 250
    ]
    if id_candidates:
        id_candidates.sort(key=lambda item: (0 if item.get("clickable") else 1, item["center"][1]))
        tap_xy(*id_candidates[0]["center"])
        time.sleep(2)
        _, nodes = dump_ui("04-id-login-tab")
    elif has_label(nodes, r"휴대폰\s*번호"):
        # 탭 문구가 하나의 합성 노드로만 잡히는 경우 화면 우측 탭을 선택합니다.
        width, _height = screen_size()
        tap_xy(int(width * 0.72), 390)
        time.sleep(2)
        _, nodes = dump_ui("04-id-login-tab-fallback")

    fields = locate_fields(nodes)
    width, height = screen_size()
    if len(fields) >= 2:
        user_xy = fields[0]["center"]
        pass_xy = fields[1]["center"]
    else:
        # Flutter semantics가 편집 필드를 숨기는 버전에 대한 마지막 좌표 대체입니다.
        user_xy = (width // 2, int(height * 0.285))
        pass_xy = (width // 2, int(height * 0.385))

    result["attempted"] = True
    tap_xy(*user_xy)
    time.sleep(0.5)
    clear_focused_field()
    input_text_secret(username)
    time.sleep(0.8)
    tap_xy(*pass_xy)
    time.sleep(0.5)
    clear_focused_field()
    input_text_secret(password)
    time.sleep(1)
    screenshot("05-login-filled-redacted")
    # 실제 스크린샷에는 입력값이 보일 수 있으므로 암호화 결과에만 포함되고 공개 보고서에는 넣지 않습니다.

    _, nodes = dump_ui("05-login-filled")
    submit_candidates = [
        node for node in nodes
        if re.fullmatch(r"\s*로그인\s*", re.sub(r"\s+", " ", str(node.get("label", ""))), re.I)
        and node["center"][1] > pass_xy[1]
    ]
    if submit_candidates:
        submit_candidates.sort(key=lambda item: item["center"][1])
        tap_xy(*submit_candidates[0]["center"])
    else:
        adb_shell("input keyevent KEYCODE_ENTER", check=False)
        time.sleep(1)
        tap_xy(width // 2, int(height * 0.51))

    deadline = time.time() + 40
    last_nodes: list[dict[str, Any]] = []
    index = 0
    while time.time() < deadline:
        time.sleep(2)
        _, last_nodes = dump_ui(f"06-login-result-{index:02d}")
        current = labels(last_nodes)
        if not has_label(last_nodes, r"비밀번호") and not (
            has_label(last_nodes, r"휴대폰\s*번호") and has_label(last_nodes, r"^로그인$")
        ):
            result.update({"success": True, "reason": "login_screen_disappeared", "labels": current[:120]})
            break
        if has_label(last_nodes, r"일치하지|확인해|실패|오류|잠시 후|잠겼|제한"):
            result.update({"reason": "visible_login_error", "labels": current[:120]})
            break
        index += 1
    else:
        result.update({"reason": "login_screen_remained", "labels": labels(last_nodes)[:120]})

    screenshot("06-login-result")
    return result


def chrome_package() -> str | None:
    for package in ["com.android.chrome", "org.chromium.chrome"]:
        result = adb_shell(f"pm path {package}", check=False)
        if "package:" in (result.stdout or ""):
            return package
    return None


def handle_chrome_fre(package: str, duration: float = 20) -> None:
    deadline = time.time() + duration
    while time.time() < deadline:
        _, nodes = dump_ui("chrome-fre-scan")
        acted = False
        for pattern in [
            r"Accept & continue|동의하고 계속",
            r"Use without an account|계정 없이 사용",
            r"No thanks|사용 안함|아니요",
            r"Got it|확인",
        ]:
            if tap_matching(nodes, pattern, min_y=200, prefer_lowest=True):
                acted = True
                time.sleep(2)
                break
        if not acted:
            if any(node.get("class") == "android.widget.EditText" for node in nodes) or has_label(nodes, r"검색 또는 URL 입력"):
                return
            time.sleep(1)


def devtools_sockets() -> list[str]:
    result = adb_shell("cat /proc/net/unix", check=False, sensitive=True)
    names = []
    for line in (result.stdout or "").splitlines():
        match = re.search(r"@(\S*(?:chrome|webview)_devtools_remote\S*)", line)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    (OUT / "devtools-sockets.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
    return names


def start_cdp_for_socket(socket: str, port: int, label: str, duration: int) -> subprocess.Popen[Any] | None:
    adb("forward", "--remove", f"tcp:{port}", check=False)
    result = adb("forward", f"tcp:{port}", f"localabstract:{socket}", check=False)
    if result.returncode != 0:
        return None
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts/apti_v4_cdp.py"),
            "--port",
            str(port),
            "--output",
            str(OUT / f"cdp-{label}.jsonl"),
            "--duration",
            str(duration),
            "--wait",
            "20",
            "--label",
            label,
        ],
        stdout=(OUT / f"cdp-{label}.log").open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    PROCESSES.append(process)
    return process


def launch_original_url() -> dict[str, Any]:
    result: dict[str, Any] = {
        "exact_original_url": ORIGINAL_URL,
        "browser_package": None,
        "launch_return_code": None,
    }
    (OUT / "exact-original-url.txt").write_text(ORIGINAL_URL + "\n", encoding="utf-8")
    package = chrome_package()
    result["browser_package"] = package

    chrome_cdp: subprocess.Popen[Any] | None = None
    if package:
        adb_shell(f"am force-stop {package}", check=False)
        adb_shell(
            "echo 'chrome --disable-fre --no-default-browser-check --disable-first-run-experience --remote-debugging-port=9222' > /data/local/tmp/chrome-command-line",
            check=False,
        )
        adb_shell(f"am start -n {package}/com.google.android.apps.chrome.Main -d about:blank", check=False)
        time.sleep(5)
        handle_chrome_fre(package, 25)
        time.sleep(2)
        sockets = devtools_sockets()
        chrome_socket = next((item for item in sockets if "chrome_devtools_remote" in item), None)
        if chrome_socket:
            chrome_cdp = start_cdp_for_socket(chrome_socket, 9222, "chrome", 55)
            time.sleep(2)

    log("Launching the exact original HTTPS tracking URL without decoding")
    if package:
        command = (
            "am start -W -a android.intent.action.VIEW "
            "-c android.intent.category.BROWSABLE "
            f"-d {shlex.quote(ORIGINAL_URL)} {shlex.quote(package)}"
        )
    else:
        command = (
            "am start -W -a android.intent.action.VIEW "
            "-c android.intent.category.BROWSABLE "
            f"-d {shlex.quote(ORIGINAL_URL)}"
        )
    launch = adb_shell(command, check=False, timeout=60)
    result["launch_return_code"] = launch.returncode
    result["launch_output"] = redact(launch.stdout or "")[:5000]

    milestones = [0, 2, 5, 10, 20, 30, 45]
    started = time.time()
    for index, second in enumerate(milestones):
        delay = second - (time.time() - started)
        if delay > 0:
            time.sleep(delay)
        screenshot(f"10-url-{second:02d}s")
        _xml, nodes = dump_ui(f"10-url-{second:02d}s")
        activity = adb_shell("dumpsys activity activities | head -n 180", check=False, sensitive=True).stdout or ""
        (OUT / f"10-url-{second:02d}s-activity.txt").write_text(redact(activity), encoding="utf-8")
        result[f"labels_{second}s"] = labels(nodes)[:120]

    # Frida로 WebView 디버깅이 활성화된 뒤 생긴 소켓을 모두 수집합니다.
    sockets = devtools_sockets()
    cdp_processes = []
    port = 9300
    for socket in sockets:
        if "chrome_devtools_remote" in socket:
            continue
        process = start_cdp_for_socket(socket, port, f"webview-{port}", 20)
        if process:
            cdp_processes.append(process)
        port += 1
    for process in cdp_processes:
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
    if chrome_cdp:
        try:
            chrome_cdp.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
    screenshot("11-final")
    dump_ui("11-final")
    return result


def storage_inventory() -> None:
    inventory: dict[str, Any] = {"files": [], "shared_preferences": {}, "cookies": []}
    listing = adb_shell(f"find /data/user/0/{PACKAGE} -maxdepth 4 -type f 2>/dev/null", check=False, sensitive=True)
    for line in (listing.stdout or "").splitlines():
        path = line.strip()
        if path:
            inventory["files"].append(path.replace(f"/data/user/0/{PACKAGE}", "<app-data>"))
    prefs_dir = WORK / "prefs"
    prefs_dir.mkdir(exist_ok=True)
    adb("pull", f"/data/user/0/{PACKAGE}/shared_prefs", str(prefs_dir), check=False, timeout=120, sensitive=True)
    for path in prefs_dir.rglob("*.xml"):
        try:
            root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
            keys = []
            for child in root:
                name = child.attrib.get("name")
                if name:
                    keys.append({"name": name, "type": child.tag, "value_length": len(child.text or "")})
            inventory["shared_preferences"][path.name] = keys
        except Exception:
            continue

    cookie_candidates = [
        f"/data/user/0/{PACKAGE}/app_webview/Default/Cookies",
        f"/data/user/0/{PACKAGE}/app_webview/Cookies",
    ]
    for index, remote in enumerate(cookie_candidates):
        local = WORK / f"Cookies-{index}"
        adb_shell(f"cp {shlex.quote(remote)} /sdcard/apti-cookies-{index} 2>/dev/null || true", check=False, sensitive=True)
        adb("pull", f"/sdcard/apti-cookies-{index}", str(local), check=False, timeout=60, sensitive=True)
        if not local.exists():
            continue
        try:
            connection = sqlite3.connect(local)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(cookies)")}
            wanted = [name for name in ["host_key", "name", "path", "is_secure", "is_httponly", "samesite"] if name in columns]
            if wanted:
                for row in connection.execute(f"SELECT {','.join(wanted)} FROM cookies"):
                    inventory["cookies"].append(dict(zip(wanted, row)))
            connection.close()
        except Exception:
            continue
    (OUT / "storage-inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")


def all_text_files() -> list[Path]:
    return [path for path in OUT.rglob("*") if path.is_file() and path.suffix.lower() in {".txt", ".log", ".json", ".jsonl", ".xml"}]


def summarize(login_result: dict[str, Any], launch_result: dict[str, Any]) -> None:
    combined = ""
    for path in all_text_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        combined += "\n" + redact(text[:8_000_000])
    lower = combined.lower()
    exact_seen = "app.apti.co.kr/api/v1/click/st0r8gzqi0yxmdvxcbo kla".replace(" ", "") in lower.replace(" ", "")
    target_seen = TARGET_HOST in lower and (TARGET_PATH.lower() in lower or "apti000574" in lower)
    aptip_seen = "aptip://aptip.app" in lower
    app_activity_seen = "aptip.app/.mainactivity" in lower
    event_ui = bool(re.search(r"관리비\s*리포트|동일\s*면적|이웃\s*평균|평균대비|단지에서", combined, re.I))
    status_codes = Counter(re.findall(r'"status"\s*:\s*(\d{3})', combined))
    summary = {
        "generated_at": now(),
        "login": login_result,
        "launch": launch_result,
        "evidence": {
            "exact_original_https_seen": exact_seen,
            "aptip_scheme_seen": aptip_seen,
            "aptip_main_activity_seen": app_activity_seen,
            "target_event_url_seen": target_seen,
            "target_event_ui_seen": event_ui,
            "http_status_counts": dict(status_codes),
        },
    }
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown = [
        "# APTI 원본 HTTPS 로그인·리디렉션 실행 결과",
        "",
        f"- 로그인 시도: {'예' if login_result.get('attempted') else '아니오'}",
        f"- 로그인 성공 판정: {'예' if login_result.get('success') else '아니오'}",
        f"- 로그인 판정 근거: `{login_result.get('reason')}`",
        f"- 최초 HTTPS 요청 흔적: {'예' if exact_seen else '아니오'}",
        f"- `aptip://aptip.app` 전환 흔적: {'예' if aptip_seen else '아니오'}",
        f"- `aptip.app/.MainActivity` 수신 흔적: {'예' if app_activity_seen else '아니오'}",
        f"- 최종 `APTI000574/app_event.html` 흔적: {'예' if target_seen else '아니오'}",
        f"- 관리비 리포트 UI 흔적: {'예' if event_ui else '아니오'}",
        "",
        "관리비 금액, 계정값, 쿠키값, 토큰값은 이 요약에 포함하지 않았습니다.",
    ]
    (OUT / "SUMMARY.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")


def cleanup() -> None:
    try:
        adb_shell("settings put global http_proxy :0", check=False, timeout=20)
    except Exception:
        pass
    for process in reversed(PROCESSES):
        try:
            process.terminate()
        except Exception:
            pass
    for process in reversed(PROCESSES):
        try:
            process.wait(timeout=3)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
    shutil.rmtree(WORK, ignore_errors=True)


def main() -> int:
    credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    username = str(credentials["username"])
    password = str(credentials["password"])
    SECRET_VALUES.extend([username, password])
    os.environ["APTI_USERNAME"] = ""
    os.environ["APTI_PASSWORD"] = ""
    (OUT / "run-metadata.json").write_text(
        json.dumps(
            {
                "started_at": now(),
                "android_release": (adb_shell("getprop ro.build.version.release", check=False).stdout or "").strip(),
                "android_sdk": (adb_shell("getprop ro.build.version.sdk", check=False).stdout or "").strip(),
                "abi_list": (adb_shell("getprop ro.product.cpu.abilist", check=False).stdout or "").strip(),
                "original_url_sha256": __import__("hashlib").sha256(ORIGINAL_URL.encode()).hexdigest(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    start_logcat()
    start_mitm_and_install_ca()
    download_and_install_app()
    launch_app()
    start_frida()
    login_result = login(username, password)
    launch_result = launch_original_url()
    storage_inventory()
    summarize(login_result, launch_result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        log(f"fatal: {type(exc).__name__}: {exc}")
        (OUT / "FATAL.txt").write_text(redact(f"{type(exc).__name__}: {exc}\n"), encoding="utf-8")
        raise
    finally:
        cleanup()
