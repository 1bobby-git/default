from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from mitmproxy import http

OUT = Path(os.environ.get("APTI_MITM_JSONL", "/tmp/apti-mitm.jsonl"))
OUT.parent.mkdir(parents=True, exist_ok=True)
LOCK = threading.Lock()
SENSITIVE = re.compile(
    r"authorization|cookie|token|secret|password|passwd|session|jwt|bearer|member.?id|user.?id",
    re.I,
)
KEEP_HEADER_VALUE = {
    "accept",
    "content-type",
    "origin",
    "referer",
    "user-agent",
    "location",
    "x-requested-with",
}


def clean_url(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(value)
        query = []
        for key, val in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "<redacted>" if SENSITIVE.search(key) else val[:512]))
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), "")
        )
    except Exception:
        return value[:2000]


def header_inventory(headers: Any) -> dict[str, Any]:
    names: list[str] = []
    selected: dict[str, str] = {}
    for key, value in headers.items(multi=True):
        lower = str(key).lower()
        if lower not in names:
            names.append(lower)
        if lower in KEEP_HEADER_VALUE and not SENSITIVE.search(lower):
            selected[lower] = clean_url(str(value)) if lower in {"referer", "location"} else str(value)[:1000]
    return {"names": sorted(names), "selected": selected}


def body_shape(flow: http.HTTPFlow) -> dict[str, Any]:
    request = flow.request
    content_type = request.headers.get("content-type", "").lower()
    raw = request.raw_content or b""
    result: dict[str, Any] = {"bytes": len(raw), "content_type": content_type[:300]}
    if not raw or len(raw) > 2_000_000:
        return result
    try:
        if "application/json" in content_type:
            data = json.loads(raw.decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                result["json_keys"] = sorted(str(key) for key in data.keys())[:300]
            elif isinstance(data, list):
                result["json_type"] = "list"
                result["json_length"] = len(data)
                if data and isinstance(data[0], dict):
                    result["first_item_keys"] = sorted(str(key) for key in data[0].keys())[:300]
        elif "application/x-www-form-urlencoded" in content_type:
            pairs = urllib.parse.parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
            result["form_keys"] = sorted({key for key, _ in pairs})[:300]
        elif "multipart/form-data" in content_type:
            text = raw[:200_000].decode("utf-8", errors="replace")
            result["multipart_names"] = sorted(set(re.findall(r'name="([^"]+)"', text)))[:300]
    except Exception:
        pass
    return result


def emit(row: dict[str, Any]) -> None:
    row = {"ts": time.time(), **row}
    with LOCK:
        with OUT.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def request(flow: http.HTTPFlow) -> None:
    emit(
        {
            "kind": "request",
            "flow_id": flow.id,
            "method": flow.request.method,
            "url": clean_url(flow.request.pretty_url),
            "headers": header_inventory(flow.request.headers),
            "body": body_shape(flow),
        }
    )


def response(flow: http.HTTPFlow) -> None:
    emit(
        {
            "kind": "response",
            "flow_id": flow.id,
            "method": flow.request.method,
            "url": clean_url(flow.request.pretty_url),
            "status": flow.response.status_code,
            "headers": header_inventory(flow.response.headers),
            "response_bytes": len(flow.response.raw_content or b""),
        }
    )


def error(flow: http.HTTPFlow) -> None:
    emit(
        {
            "kind": "error",
            "flow_id": flow.id,
            "method": flow.request.method,
            "url": clean_url(flow.request.pretty_url),
            "error": str(flow.error)[:1000],
        }
    )
