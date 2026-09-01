from __future__ import annotations

import json
import os
import re
import stat
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from mitmproxy import http

OUT_DIR = Path(os.environ.get("APTI_MITM_OUT_DIR", "apti-mitm-root"))
OUT_DIR.mkdir(parents=True, exist_ok=True)
EVENTS = OUT_DIR / "flows-sanitized.jsonl"
TOKEN_FILE = Path(os.environ.get("APTI_MBL_TOKEN_FILE", "/dev/shm/apti-mbl-token.txt"))
LOCK = threading.Lock()
SENSITIVE_HEADER = re.compile(r"authorization|cookie|token|secret|password|session|credential", re.I)
SENSITIVE_KEY = re.compile(
    r"password|passwd|pwd|token|secret|cookie|session|credential|login.?account|"
    r"user.?id|member|phone|mobile|name|address|email|birth|dong|ho|apt|erp|uuid|device.?id",
    re.I,
)
MESSAGE_KEY = re.compile(r"^(?:message|msg|errorMessage|error_message|detail|reason)$", re.I)
MBL_TOKEN_KEY = re.compile(r"^(?:mbl[_-]?token|mobile[_-]?token)$", re.I)
LOGIN_PATH = re.compile(r"/(?:api/)?(?:v2/)?user/mobile/?$", re.I)


def clean_headers(headers) -> dict[str, str]:
    data: dict[str, str] = {}
    for key, value in headers.items(multi=True):
        data[key] = "<redacted>" if SENSITIVE_HEADER.search(key) else value[:1000]
    return data


def clean_url(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(value)
        clean_query = []
        for key, val in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            clean_query.append((key, "<redacted>" if SENSITIVE_KEY.search(key) else val[:300]))
        fragment = "<redacted>" if SENSITIVE_KEY.search(parts.fragment) else parts.fragment[:300]
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(clean_query), fragment)
        )
    except Exception:
        return value[:4000]


def request_shape(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(k): request_shape(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return {"type": "array", "length": len(value), "items": [request_shape(v, key) for v in value[:10]]}
    if isinstance(value, str):
        return {"type": "string", "length": len(value), "value": "<redacted>"}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if isinstance(value, (int, float)):
        return {"type": type(value).__name__, "value": value}
    return {"type": type(value).__name__}


def response_sanitized(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(k): response_sanitized(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [response_sanitized(v, key) for v in value[:50]]
    if isinstance(value, str):
        if MESSAGE_KEY.match(key) and len(value) <= 1000:
            return value
        if SENSITIVE_KEY.search(key):
            return {"redacted": True, "type": "string", "length": len(value)}
        return value[:1000] if len(value) <= 1000 else {"type": "string", "length": len(value)}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:1000]


def parse_body(raw: bytes, content_type: str) -> tuple[str, Any]:
    if not raw:
        return "empty", None
    text = raw.decode("utf-8", errors="replace")
    lowered = content_type.lower()
    if "json" in lowered or text.lstrip().startswith(("{", "[")):
        try:
            return "json", json.loads(text)
        except Exception:
            pass
    if "application/x-www-form-urlencoded" in lowered:
        try:
            parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
            return "form", {k: v if len(v) > 1 else v[0] for k, v in parsed.items()}
        except Exception:
            pass
    return "text", {"type": "text", "length": len(text)}


def find_mbl_token(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if MBL_TOKEN_KEY.match(str(key)) and isinstance(item, str) and item:
                return item
            found = find_mbl_token(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_mbl_token(item)
            if found:
                return found
    return None


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def append_event(row: dict[str, Any]) -> None:
    with LOCK:
        with EVENTS.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def request(flow: http.HTTPFlow) -> None:
    content_type = flow.request.headers.get("content-type", "")
    kind, parsed = parse_body(flow.request.raw_content or b"", content_type)
    row = {
        "phase": "request",
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path.split("?", 1)[0],
        "url": clean_url(flow.request.pretty_url),
        "headers": clean_headers(flow.request.headers),
        "content_type": content_type,
        "body_bytes": len(flow.request.raw_content or b""),
        "body_kind": kind,
    }
    append_event(row)
    if LOGIN_PATH.search(flow.request.path.split("?", 1)[0]):
        write_json(
            OUT_DIR / "login-request-sanitized.json",
            {**row, "body_shape": request_shape(parsed)},
        )


def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "") if flow.response else ""
    raw = flow.response.raw_content if flow.response and flow.response.raw_content else b""
    kind, parsed = parse_body(raw, content_type)
    row = {
        "phase": "response",
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path.split("?", 1)[0],
        "url": clean_url(flow.request.pretty_url),
        "status": flow.response.status_code if flow.response else None,
        "headers": clean_headers(flow.response.headers) if flow.response else {},
        "content_type": content_type,
        "body_bytes": len(raw),
        "body_kind": kind,
    }
    append_event(row)

    if LOGIN_PATH.search(flow.request.path.split("?", 1)[0]):
        sanitized = {**row, "body": response_sanitized(parsed)}
        write_json(OUT_DIR / "login-response-sanitized.json", sanitized)
        token = find_mbl_token(parsed)
        if not token and flow.response:
            token = flow.response.headers.get("mbl-token") or flow.response.headers.get("mbl_token")
        if token:
            TOKEN_FILE.write_text(token, encoding="utf-8")
            TOKEN_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
            write_json(
                OUT_DIR / "login-token-presence.json",
                {"mbl_token_present": True, "length": len(token)},
            )
        else:
            write_json(OUT_DIR / "login-token-presence.json", {"mbl_token_present": False})


def error(flow: http.HTTPFlow) -> None:
    append_event(
        {
            "phase": "error",
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "path": flow.request.path.split("?", 1)[0],
            "url": clean_url(flow.request.pretty_url),
            "error": str(flow.error)[:2000],
        }
    )
