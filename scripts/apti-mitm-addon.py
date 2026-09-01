from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
from pathlib import Path

from mitmproxy import http

OUT = Path(os.environ.get("APTI_MITM_JSONL", "apti-mitm.jsonl"))
OUT.parent.mkdir(parents=True, exist_ok=True)
LOCK = threading.Lock()
SENSITIVE = re.compile(r"authorization|cookie|token|secret|password|session", re.I)


def clean_headers(headers) -> dict[str, str]:
    data: dict[str, str] = {}
    for key, value in headers.items(multi=True):
        data[key] = "<redacted>" if SENSITIVE.search(key) else value
    return data


def clean_url(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(value)
        clean_query = [
            (key, "<redacted>" if SENSITIVE.search(key) else val)
            for key, val in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        ]
        fragment = "<redacted>" if SENSITIVE.search(parts.fragment) else parts.fragment
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(clean_query), fragment)
        )
    except Exception:
        return value[:4000]


def response(flow: http.HTTPFlow) -> None:
    row = {
        "method": flow.request.method,
        "url": clean_url(flow.request.pretty_url),
        "request_headers": clean_headers(flow.request.headers),
        "status": flow.response.status_code if flow.response else None,
        "response_headers": clean_headers(flow.response.headers) if flow.response else {},
        "response_mime": flow.response.headers.get("content-type") if flow.response else None,
    }
    with LOCK:
        with OUT.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def error(flow: http.HTTPFlow) -> None:
    row = {
        "method": flow.request.method,
        "url": clean_url(flow.request.pretty_url),
        "error": str(flow.error),
    }
    with LOCK:
        with OUT.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")
