#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

ORIGINAL_URL = (
    "https://app.apti.co.kr/api/v1/click/St0R8GzQi0yXMdVxcboKLA?"
    "deeplink_custom_path=aptip%3A%2F%2Faptip.app%3Flink%3D"
    "https%253A%252F%252Fv2notice.apti.co.kr%252Fresource%252Fpages%252F"
    "event%252FAPTI000574%252Fapp_event.html%253FisShare%253DY&"
    "abx_tracker_id=St0R8GzQi0yXMdVxcboKLA"
)
EXPECTED_SHA256 = "19b343f8ebf3e5ada48ab4d42e7e42661339d80d861ef5cab756aaee0ed5b75a"
SENSITIVE_QUERY_RE = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|token|authorization|auth|session|sid|"
    r"jsessionid|password|passwd|secret|api[_-]?key)",
    re.I,
)
SENSITIVE_HEADER_RE = re.compile(
    r"^(?:authorization|proxy-authorization|cookie|set-cookie|x-auth-token|x-api-key)$",
    re.I,
)
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def run(
    args: list[str],
    *,
    timeout: int = 30,
    check: bool = False,
    quiet: bool = False,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed: {args[0]} rc={completed.returncode}")
    if not quiet and completed.returncode != 0:
        print(f"[probe] command {args[0]!r} returned {completed.returncode}", file=sys.stderr)
    return completed


def adb_shell(*args: str, timeout: int = 30, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["adb", "shell", *args], timeout=timeout, quiet=quiet)


def adb_shell_command(command: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(["adb", "shell", command], timeout=timeout)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def redact_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        query = []
        for key, item in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "<redacted>" if SENSITIVE_QUERY_RE.search(key) else item))
        fragment = "<redacted>" if SENSITIVE_QUERY_RE.search(parts.fragment) else parts.fragment
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), fragment)
        )
    except Exception:
        return value[:4000]


def norm(value: str | None) -> str:
    return re.sub(r"\s+", "", value or "").strip()


def parse_bounds(value: str | None) -> tuple[int, int, int, int] | None:
    match = BOUNDS_RE.fullmatch(value or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def node_label(node: ET.Element) -> str:
    return norm(node.attrib.get("text")) or norm(node.attrib.get("content-desc"))


def node_center(node: ET.Element) -> tuple[int, int] | None:
    bounds = parse_bounds(node.attrib.get("bounds"))
    if not bounds:
        return None
    x1, y1, x2, y2 = bounds
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def dump_ui(result_dir: Path, tag: str, credentials: dict[str, str]) -> ET.Element | None:
    adb_shell("uiautomator", "dump", "/sdcard/apti-exact.xml", timeout=20, quiet=True)
    raw = adb_shell("cat", "/sdcard/apti-exact.xml", timeout=20, quiet=True).stdout or ""
    if not raw.lstrip().startswith("<?xml"):
        write_text(result_dir / f"{tag}-ui-error.txt", "uiautomator XML unavailable\n")
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        write_text(result_dir / f"{tag}-ui-error.txt", f"XML parse failure: {exc}\n")
        return None

    sanitized = ET.fromstring(raw)
    for node in sanitized.iter("node"):
        cls = node.attrib.get("class", "")
        is_editable = (
            "EditText" in cls
            or node.attrib.get("password") == "true"
            or node.attrib.get("editable") == "true"
        )
        if is_editable:
            if node.attrib.get("text"):
                node.attrib["text"] = "<redacted-editable>"
            if node.attrib.get("content-desc"):
                node.attrib["content-desc"] = "<redacted-editable>"
    safe = ET.tostring(sanitized, encoding="unicode")
    for secret in credentials.values():
        if secret:
            safe = safe.replace(secret, "<redacted>")
    write_text(result_dir / f"{tag}-ui.xml", safe)
    return root


def screenshot(result_dir: Path, tag: str) -> None:
    completed = run(["adb", "exec-out", "screencap", "-p"], timeout=30, text=False, quiet=True)
    if completed.returncode == 0 and completed.stdout:
        (result_dir / f"{tag}.png").write_bytes(completed.stdout)  # type: ignore[arg-type]


def capture_activity(result_dir: Path, tag: str) -> dict[str, Any]:
    activities = adb_shell("dumpsys", "activity", "activities", timeout=25, quiet=True).stdout or ""
    windows = adb_shell("dumpsys", "window", "windows", timeout=25, quiet=True).stdout or ""
    write_text(result_dir / f"{tag}-activities.txt", activities)
    write_text(result_dir / f"{tag}-windows.txt", windows)
    resumed = []
    for line in activities.splitlines():
        if any(key in line for key in ("mResumedActivity", "topResumedActivity", "ResumedActivity")):
            resumed.append(line.strip())
    return {"tag": tag, "resumed": resumed[:10]}


def find_nodes(root: ET.Element | None, predicate) -> list[ET.Element]:
    if root is None:
        return []
    return [node for node in root.iter("node") if predicate(node)]


def tap_node(node: ET.Element) -> bool:
    center = node_center(node)
    if not center:
        return False
    adb_shell("input", "tap", str(center[0]), str(center[1]), quiet=True)
    time.sleep(1.2)
    return True


def tap_label(root: ET.Element | None, labels: Iterable[str], *, min_y: int = 0) -> bool:
    wanted = [norm(label) for label in labels]
    candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):
        label = node_label(node)
        center = node_center(node)
        if not label or not center or center[1] < min_y:
            continue
        if any(label == item or item in label for item in wanted):
            score = (100 if node.attrib.get("clickable") == "true" else 0) + center[1]
            candidates.append((score, node))
    if not candidates:
        return False
    candidates.sort(key=lambda item: item[0], reverse=True)
    return tap_node(candidates[0][1])


def current_labels(root: ET.Element | None) -> list[str]:
    labels: list[str] = []
    if root is None:
        return labels
    for node in root.iter("node"):
        label = node_label(node)
        if not label:
            continue
        if any(
            keyword in label
            for keyword in (
                "로그인", "아이디", "휴대폰", "비밀번호", "시작하기", "닫기",
                "건너뛰기", "계정", "Chrome", "크롬", "동의", "계속", "오류",
                "일치하지", "관리비",
            )
        ):
            labels.append(label[:160])
    return list(dict.fromkeys(labels))[:100]


def prepare_login_page(result_dir: Path, credentials: dict[str, str]) -> ET.Element | None:
    for attempt in range(12):
        root = dump_ui(result_dir, f"login-prep-{attempt:02d}", credentials)
        labels = current_labels(root)
        write_json(result_dir / f"login-prep-{attempt:02d}-labels.json", labels)

        if any("아이디" in label for label in labels) and any("비밀번호" in label for label in labels):
            if tap_label(root, ["아이디"], min_y=250):
                time.sleep(1)
                return dump_ui(result_dir, "login-id-tab", credentials)
            return root

        for candidate in (["시작하기"], ["닫기"], ["건너뛰기"], ["로그인"]):
            if tap_label(root, candidate, min_y=300):
                break
        time.sleep(1.5)
    return dump_ui(result_dir, "login-page-final", credentials)


def resolve_adb_keyboard() -> str | None:
    outputs = [
        adb_shell("ime", "list", "-a", quiet=True).stdout or "",
        adb_shell("dumpsys", "package", "com.android.adbkeyboard", quiet=True).stdout or "",
    ]
    pattern = re.compile(r"com\.android\.adbkeyboard/[A-Za-z0-9_.$]+")
    for output in outputs:
        matches = pattern.findall(output)
        if matches:
            return matches[0]
    return "com.android.adbkeyboard/.AdbIME"


def enable_adb_keyboard(component: str) -> bool:
    adb_shell("pm", "enable", "com.android.adbkeyboard", quiet=True)
    existing = (adb_shell("settings", "get", "secure", "enabled_input_methods", quiet=True).stdout or "").strip()
    values = [item for item in existing.split(":") if item and item != "null"]
    if component not in values:
        values.append(component)
    adb_shell("settings", "put", "secure", "enabled_input_methods", ":".join(values), quiet=True)
    adb_shell("settings", "put", "secure", "default_input_method", component, quiet=True)
    adb_shell("ime", "enable", component, quiet=True)
    selected = adb_shell("ime", "set", component, quiet=True)
    time.sleep(1)
    current = (adb_shell("settings", "get", "secure", "default_input_method", quiet=True).stdout or "").strip()
    return selected.returncode == 0 or current == component


def clear_focused_field() -> None:
    adb_shell("input", "keycombination", "113", "29", quiet=True)
    adb_shell("input", "keyevent", "67", quiet=True)
    for _ in range(80):
        adb_shell("input", "keyevent", "67", quiet=True)


def send_via_adb_keyboard(value: str) -> bool:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    completed = adb_shell(
        "am", "broadcast", "-a", "ADB_INPUT_B64", "--es", "msg", encoded,
        timeout=20, quiet=True,
    )
    return completed.returncode == 0


def send_fallback(value: str) -> bool:
    keycodes = {
        "!": (59, 8), "@": (59, 9), "#": (59, 10), "$": (59, 11),
        "%": (59, 12), "^": (59, 13), "&": (59, 14), "*": (59, 15),
        "(": (59, 16), ")": (59, 7),
    }
    buffer = ""

    def flush() -> None:
        nonlocal buffer
        if buffer:
            adb_shell("input", "text", buffer, quiet=True)
            buffer = ""

    for char in value:
        if char.isalnum() or char in "._-":
            buffer += char
            continue
        flush()
        if char in keycodes:
            adb_shell("input", "keycombination", *(str(item) for item in keycodes[char]), quiet=True)
        else:
            return False
    flush()
    return True


def editable_nodes(root: ET.Element | None) -> list[ET.Element]:
    nodes = find_nodes(
        root,
        lambda node: (
            "EditText" in node.attrib.get("class", "")
            or node.attrib.get("editable") == "true"
        ),
    )
    nodes = [node for node in nodes if node_center(node)]
    nodes.sort(key=lambda node: node_center(node)[1] if node_center(node) else 99999)
    return nodes


def field_observation(root: ET.Element | None) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for node in editable_nodes(root):
        value = node.attrib.get("text", "")
        observations.append(
            {
                "class": node.attrib.get("class"),
                "bounds": node.attrib.get("bounds"),
                "password": node.attrib.get("password") == "true",
                "has_value": bool(value),
                "visible_length": len(value),
            }
        )
    return observations


def fill_login_once(result_dir: Path, credentials: dict[str, str]) -> dict[str, Any]:
    root = prepare_login_page(result_dir, credentials)
    fields = editable_nodes(root)
    result: dict[str, Any] = {
        "fields_before": field_observation(root),
        "input_method": None,
        "input_verified": False,
        "login_clicked": False,
        "login_success": False,
        "login_error_detected": False,
    }

    if len(fields) < 2:
        result["failure"] = "two editable login fields were not found"
        return result

    username_field, password_field = fields[0], fields[1]
    component = resolve_adb_keyboard()
    keyboard_ready = bool(component and enable_adb_keyboard(component))
    result["input_method"] = "ADBKeyboard/base64" if keyboard_ready else "Android key events"

    if not tap_node(username_field):
        result["failure"] = "username field could not be focused"
        return result
    clear_focused_field()
    username_ok = send_via_adb_keyboard(credentials["username"]) if keyboard_ready else send_fallback(credentials["username"])

    root = dump_ui(result_dir, "login-after-username", credentials)
    fields = editable_nodes(root)
    if len(fields) < 2 or not tap_node(fields[1]):
        result["failure"] = "password field could not be focused"
        return result
    clear_focused_field()
    password_ok = send_via_adb_keyboard(credentials["password"]) if keyboard_ready else send_fallback(credentials["password"])
    time.sleep(1.2)

    root = dump_ui(result_dir, "login-filled", credentials)
    screenshot(result_dir, "login-filled")
    after = field_observation(root)
    result["fields_after"] = after

    nonempty = len(after) >= 2 and all(item.get("has_value") for item in after[:2])
    result["input_verified"] = bool(username_ok and password_ok and nonempty)
    if not result["input_verified"]:
        result["failure"] = "input was not visibly present; login was not submitted"
        return result

    login_candidates: list[tuple[int, ET.Element]] = []
    for node in find_nodes(root, lambda _: True):
        label = node_label(node)
        center = node_center(node)
        if label == "로그인" and center and center[1] > 500:
            score = (100000 if node.attrib.get("clickable") == "true" else 0) + center[1]
            login_candidates.append((score, node))
    if not login_candidates:
        result["failure"] = "login submit button not found"
        return result

    login_candidates.sort(key=lambda item: item[0], reverse=True)
    tap_node(login_candidates[0][1])
    result["login_clicked"] = True
    time.sleep(2)

    observations: list[dict[str, Any]] = []
    for index in range(20):
        state_root = dump_ui(result_dir, f"login-result-{index:02d}", credentials)
        labels = current_labels(state_root)
        activity = capture_activity(result_dir, f"login-result-{index:02d}") if index in {0, 4, 10, 19} else None
        observations.append({"second": index * 1.5, "labels": labels, "activity": activity})

        lowered = " ".join(labels)
        if any(term in lowered for term in ("일치하지", "로그인정보", "오류", "다시확인")):
            result["login_error_detected"] = True
            break
        has_login_form = any("비밀번호" in item for item in labels) and any("아이디" in item for item in labels)
        if not has_login_form and index >= 2:
            result["login_success"] = True
            break
        time.sleep(1.5)

    result["observations"] = observations
    screenshot(result_dir, "login-result-final")
    return result


def browser_packages() -> list[str]:
    output = adb_shell("pm", "list", "packages", quiet=True).stdout or ""
    candidates = []
    for line in output.splitlines():
        package = line.removeprefix("package:").strip()
        if re.search(r"chrome|browser|webview", package, re.I):
            candidates.append(package)
    return sorted(set(candidates))


def handle_chrome_first_run(result_dir: Path, credentials: dict[str, str]) -> None:
    packages = browser_packages()
    if "com.android.chrome" not in packages:
        return
    adb_shell_command(
        "am start -W -n com.android.chrome/com.google.android.apps.chrome.Main "
        "-a android.intent.action.VIEW -d 'about:blank'",
        timeout=30,
    )
    time.sleep(3)
    for index in range(8):
        root = dump_ui(result_dir, f"chrome-first-run-{index:02d}", credentials)
        labels = current_labels(root)
        write_json(result_dir / f"chrome-first-run-{index:02d}-labels.json", labels)
        clicked = False
        for options in (
            ["동의하고 계속", "Accept & continue"],
            ["계정 없이 사용", "Use without an account"],
            ["아니요", "No thanks"],
            ["계속", "Continue"],
            ["Chrome", "크롬"],
            ["한 번만", "Just once"],
        ):
            if tap_label(root, options, min_y=300):
                clicked = True
                break
        if not clicked:
            break
        time.sleep(1.5)


def resolve_https_handler() -> str:
    command = (
        "cmd package resolve-activity --brief -a android.intent.action.VIEW "
        "-c android.intent.category.BROWSABLE -d https://example.com"
    )
    return (adb_shell_command(command, timeout=20).stdout or "").strip()


def top_activity_line() -> str:
    output = adb_shell("dumpsys", "activity", "activities", timeout=20, quiet=True).stdout or ""
    for line in output.splitlines():
        if any(key in line for key in ("mResumedActivity", "topResumedActivity", "ResumedActivity")):
            return line.strip()
    return ""


def devtools_sockets() -> list[str]:
    output = adb_shell("cat", "/proc/net/unix", timeout=20, quiet=True).stdout or ""
    values = []
    for line in output.splitlines():
        match = re.search(r"@(webview_devtools_remote_[^\s]+|chrome_devtools_remote[^\s]*)", line)
        if match:
            values.append(match.group(1))
    return list(dict.fromkeys(values))


def cdp_evaluate(ws, expression: str, seq: int) -> tuple[int, Any]:
    ws.send(json.dumps({"id": seq, "method": "Runtime.evaluate", "params": {"expression": expression, "returnByValue": True}}))
    deadline = time.time() + 10
    while time.time() < deadline:
        message = json.loads(ws.recv())
        if message.get("id") == seq:
            value = message.get("result", {}).get("result", {}).get("value")
            return seq + 1, value
    return seq + 1, None


def inspect_cdp(result_dir: Path) -> list[dict[str, Any]]:
    try:
        import websocket  # type: ignore
    except Exception as exc:
        return [{"error": f"websocket-client unavailable: {exc}"}]

    records: list[dict[str, Any]] = []
    for index, socket in enumerate(devtools_sockets()):
        forwarded = run(["adb", "forward", "tcp:0", f"localabstract:{socket}"], timeout=20, quiet=True)
        port = (forwarded.stdout or "").strip()
        if not port.isdigit():
            records.append({"socket": socket, "error": "forward failed"})
            continue
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as response:
                targets = json.load(response)
        except Exception as exc:
            records.append({"socket": socket, "error": f"target list failed: {exc}"})
            continue

        safe_targets = []
        for target in targets:
            safe_targets.append({"id": target.get("id"), "type": target.get("type"), "title": target.get("title"), "url": redact_url(target.get("url"))})
            ws_url = target.get("webSocketDebuggerUrl")
            if target.get("type") != "page" or not ws_url:
                continue
            try:
                ws = websocket.create_connection(ws_url, timeout=10, suppress_origin=True)
                seq = 1
                expressions = {
                    "href": "location.href",
                    "title": "document.title",
                    "user_agent": "navigator.userAgent",
                    "cookie_names": "document.cookie.split(';').map(v=>v.split('=')[0].trim()).filter(Boolean)",
                    "local_storage_keys": "Object.keys(localStorage)",
                    "session_storage_keys": "Object.keys(sessionStorage)",
                    "bridge_keys": "Object.getOwnPropertyNames(window).filter(v=>/apti|android|native|bridge|reactnative|webkit/i.test(v))",
                    "resources": "performance.getEntriesByType('resource').map(v=>({name:v.name,initiatorType:v.initiatorType}))",
                    "page_state": "(()=>{const t=document.body?document.body.innerText:'';return {readyState:document.readyState,bodyLength:t.length,hasPlaceholder:t.includes('???'),hasManagementFee:t.includes('관리비'),hasLogin:t.includes('로그인')}})()",
                }
                values: dict[str, Any] = {}
                for name, expression in expressions.items():
                    seq, value = cdp_evaluate(ws, expression, seq)
                    if name == "href":
                        value = redact_url(value)
                    elif name == "resources" and isinstance(value, list):
                        value = [
                            {"name": redact_url(str(item.get("name", ""))), "initiatorType": item.get("initiatorType")}
                            for item in value[:2000] if isinstance(item, dict)
                        ]
                    values[name] = value
                ws.close()
                records.append({"socket": socket, "target": safe_targets[-1], "runtime": values})
            except Exception as exc:
                records.append({"socket": socket, "target": safe_targets[-1], "error": f"CDP attach failed: {exc}"})
        write_json(result_dir / f"cdp-{index:02d}-targets.json", safe_targets)
    return records


def launch_exact_url(result_dir: Path, credentials: dict[str, str]) -> dict[str, Any]:
    adb_shell("settings", "put", "global", "http_proxy", ":0", quiet=True)
    adb_shell("settings", "delete", "global", "global_http_proxy_host", quiet=True)
    adb_shell("settings", "delete", "global", "global_http_proxy_port", quiet=True)

    handle_chrome_first_run(result_dir, credentials)
    packages = browser_packages()
    handler = resolve_https_handler()
    write_json(result_dir / "browser-environment.json", {"packages": packages, "https_handler": handler})

    mobile_ua = (
        "Mozilla/5.0 (Linux; Android 15; Pixel 5 Build/AP3A.241105.008; wv) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/152.0.0.0 "
        "Mobile Safari/537.36"
    )
    curl = run(["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-redirs", "0", "-A", mobile_ua, ORIGINAL_URL], timeout=30, quiet=True)
    headers = curl.stdout or ""
    safe_header_lines = []
    for line in headers.splitlines():
        key = line.split(":", 1)[0].strip()
        safe_header_lines.append(f"{key}: <redacted>" if SENSITIVE_HEADER_RE.search(key) else line)
    write_text(result_dir / "original-url-first-response-headers.txt", "\n".join(safe_header_lines) + "\n")

    adb_shell("logcat", "-c", quiet=True)
    log_handle = (result_dir / "exact-url-logcat.txt").open("w", encoding="utf-8")
    logcat = subprocess.Popen(["adb", "logcat", "-v", "threadtime"], stdout=log_handle, stderr=subprocess.STDOUT, text=True)

    start_command = (
        "am start -W -a android.intent.action.VIEW "
        "-c android.intent.category.BROWSABLE -d " + shlex.quote(ORIGINAL_URL)
    )
    started_at = time.time()
    start = adb_shell_command(start_command, timeout=45)
    write_text(result_dir / "exact-url-am-start.txt", (start.stdout or "") + (start.stderr or ""))

    sequence = []
    try:
        for index in range(50):
            elapsed = round(time.time() - started_at, 3)
            line = top_activity_line()
            sequence.append({"elapsed_seconds": elapsed, "top_activity": line})

            if index in {0, 2, 5, 10, 20, 35, 49}:
                tag = f"exact-url-{index:02d}"
                screenshot(result_dir, tag)
                dump_ui(result_dir, tag, credentials)
                capture_activity(result_dir, tag)

            root = dump_ui(result_dir, "resolver-current", credentials) if index in {2, 5, 8} else None
            if root is not None:
                for options in (
                    ["Chrome", "크롬"], ["한 번만", "Just once"],
                    ["동의하고 계속", "Accept & continue"],
                    ["계정 없이 사용", "Use without an account"],
                    ["아니요", "No thanks"], ["계속", "Continue"],
                ):
                    if tap_label(root, options, min_y=250):
                        break
            time.sleep(0.45)
    finally:
        logcat.terminate()
        try:
            logcat.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logcat.kill()
        log_handle.close()

    write_json(result_dir / "exact-url-activity-sequence.json", sequence)
    cdp = inspect_cdp(result_dir)
    write_json(result_dir / "exact-url-cdp.json", cdp)

    final_urls = []
    auth_present = False
    cookie_names: list[str] = []
    placeholder: bool | None = None
    for record in cdp:
        runtime = record.get("runtime") if isinstance(record, dict) else None
        if not isinstance(runtime, dict):
            continue
        href = runtime.get("href")
        if href:
            final_urls.append(href)
        cookie_names.extend(runtime.get("cookie_names") or [])
        state = runtime.get("page_state")
        if isinstance(state, dict) and "hasPlaceholder" in state:
            placeholder = bool(state["hasPlaceholder"])
        if runtime.get("local_storage_keys") or runtime.get("session_storage_keys"):
            auth_present = auth_present or any(
                SENSITIVE_QUERY_RE.search(str(key))
                for key in (runtime.get("local_storage_keys") or []) + (runtime.get("session_storage_keys") or [])
            )

    sequence_text = "\n".join(item["top_activity"] for item in sequence)
    actual_sha = hashlib.sha256(ORIGINAL_URL.encode()).hexdigest()
    return {
        "entry_url": ORIGINAL_URL,
        "entry_url_sha256": actual_sha,
        "entry_url_matches_expected_sha256": actual_sha == EXPECTED_SHA256,
        "launch_used_android_action_view": True,
        "forced_app_package": False,
        "am_start_return_code": start.returncode,
        "browser_packages": packages,
        "https_handler": handler,
        "observed_chrome_activity": bool(re.search(r"chrome", sequence_text, re.I)),
        "observed_apti_activity": "aptip.app" in sequence_text,
        "final_urls": list(dict.fromkeys(final_urls)),
        "cookie_names": sorted(set(cookie_names)),
        "storage_auth_key_present": auth_present,
        "placeholder_visible": placeholder,
        "devtools_sockets": devtools_sockets(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", default=os.environ.get("APTI_CREDENTIALS_FILE", "/dev/shm/apti-creds.json"))
    parser.add_argument("--result-dir", default=os.environ.get("APTI_SECURE_RESULT_DIR", ".apti-sensitive-results"))
    args = parser.parse_args()

    result_dir = Path(args.result_dir).resolve() / "exact-original-https"
    result_dir.mkdir(parents=True, exist_ok=True)
    credentials_path = Path(args.credentials)
    credentials_raw = json.loads(credentials_path.read_text(encoding="utf-8"))
    credentials = {"username": str(credentials_raw.get("username", "")), "password": str(credentials_raw.get("password", ""))}
    if not credentials["username"] or not credentials["password"]:
        write_json(result_dir / "summary.json", {"error": "credential fields unavailable"})
        return 2

    actual_sha = hashlib.sha256(ORIGINAL_URL.encode()).hexdigest()
    write_text(result_dir / "entry-url.txt", ORIGINAL_URL + "\n")
    write_text(result_dir / "entry-url-sha256.txt", actual_sha + "\n")

    summary: dict[str, Any] = {
        "probe": "exact-original-https-entry",
        "credentials_logged": False,
        "entry_url_sha256": actual_sha,
        "entry_url_matches_expected_sha256": actual_sha == EXPECTED_SHA256,
    }
    try:
        summary["login"] = fill_login_once(result_dir, credentials)
    except Exception as exc:
        summary["login"] = {"failure": f"login automation exception: {type(exc).__name__}: {exc}"}

    try:
        summary["exact_url_launch"] = launch_exact_url(result_dir, credentials)
    except Exception as exc:
        summary["exact_url_launch"] = {"failure": f"exact URL launch exception: {type(exc).__name__}: {exc}"}

    for path in result_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bin"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for secret in credentials.values():
            if secret:
                text = text.replace(secret, "<redacted>")
        path.write_text(text, encoding="utf-8")

    write_json(result_dir / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
