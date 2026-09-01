#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import websocket

SENSITIVE = re.compile(r"authorization|cookie|token|secret|password|session", re.I)


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        result[str(key)] = "<redacted>" if SENSITIVE.search(str(key)) else value
    return result


def redact_url(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    try:
        parts = urllib.parse.urlsplit(text)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        clean = [
            (key, "<redacted>" if SENSITIVE.search(key) else val)
            for key, val in query
        ]
        fragment = "<redacted>" if SENSITIVE.search(parts.fragment) else parts.fragment
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(clean), fragment)
        )
    except Exception:
        return text[:4000]


def emit(fp, kind: str, data: dict[str, Any]) -> None:
    fp.write(json.dumps({"ts": time.time(), "kind": kind, **data}, ensure_ascii=False) + "\n")
    fp.flush()


def command(ws, seq: int, method: str, params: dict[str, Any] | None = None) -> int:
    ws.send(json.dumps({"id": seq, "method": method, "params": params or {}}))
    return seq + 1


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: apti-cdp-capture.py <port> <output-dir>", file=sys.stderr)
        return 2

    port = int(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as response:
        targets = json.load(response)
    (out / "cdp-targets.json").write_text(
        json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    pages = [item for item in targets if item.get("type") in {"page", "webview"}]
    if not pages:
        return 3

    target = pages[0]
    ws_url = target["webSocketDebuggerUrl"].replace(
        "localhost", "127.0.0.1"
    )
    ws = websocket.create_connection(ws_url, timeout=2, origin=f"http://127.0.0.1:{port}")
    seq = 1
    seq = command(ws, seq, "Network.enable")
    seq = command(ws, seq, "Page.enable")
    seq = command(ws, seq, "Runtime.enable")
    seq = command(ws, seq, "Log.enable")

    expressions = {
        "runtime-location.json": "JSON.stringify({href:location.href,title:document.title,ua:navigator.userAgent,readyState:document.readyState})",
        "storage-keys.json": "JSON.stringify({local:Object.keys(localStorage),session:Object.keys(sessionStorage),cookieNames:document.cookie.split(';').map(v=>v.split('=')[0].trim()).filter(Boolean)})",
        "bridge-keys.json": "JSON.stringify(Object.getOwnPropertyNames(window).filter(v=>/apti|android|native|bridge|reactnative|webkit/i.test(v)))",
        "performance-resources.json": "JSON.stringify(performance.getEntriesByType('resource').map(v=>({name:v.name,initiatorType:v.initiatorType})))",
        "page-text.txt": "document.body ? document.body.innerText.slice(0,200000) : ''",
        "page-html.html": "document.documentElement ? document.documentElement.outerHTML.slice(0,1000000) : ''",
    }

    events_path = out / "cdp-network.jsonl"
    pending: dict[int, str] = {}
    with events_path.open("w", encoding="utf-8") as fp:
        for name, expression in expressions.items():
            pending[seq] = name
            seq = command(
                ws,
                seq,
                "Runtime.evaluate",
                {"expression": expression, "returnByValue": True},
            )

        reload_id = seq
        seq = command(ws, seq, "Page.reload", {"ignoreCache": True})
        emit(fp, "reload_sent", {"id": reload_id})

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                raw = ws.recv()
            except Exception:
                continue
            message = json.loads(raw)

            msg_id = message.get("id")
            if msg_id in pending:
                name = pending.pop(msg_id)
                value = (
                    message.get("result", {})
                    .get("result", {})
                    .get("value", "")
                )
                if name.endswith(".json"):
                    try:
                        parsed = json.loads(value)
                        value = json.dumps(parsed, ensure_ascii=False, indent=2)
                    except Exception:
                        pass
                (out / name).write_text(str(value), encoding="utf-8")
                continue

            method = message.get("method")
            params = message.get("params", {})
            if method == "Network.requestWillBeSent":
                req = params.get("request", {})
                emit(
                    fp,
                    "request",
                    {
                        "request_id": params.get("requestId"),
                        "document_url": redact_url(params.get("documentURL")),
                        "url": redact_url(req.get("url")),
                        "method": req.get("method"),
                        "type": params.get("type"),
                        "headers": redact_headers(req.get("headers")),
                        "initiator": params.get("initiator", {}).get("type"),
                    },
                )
            elif method == "Network.responseReceived":
                response = params.get("response", {})
                emit(
                    fp,
                    "response",
                    {
                        "request_id": params.get("requestId"),
                        "url": redact_url(response.get("url")),
                        "status": response.get("status"),
                        "mime_type": response.get("mimeType"),
                        "from_disk_cache": response.get("fromDiskCache"),
                        "from_service_worker": response.get("fromServiceWorker"),
                        "headers": redact_headers(response.get("headers")),
                    },
                )
            elif method == "Network.loadingFailed":
                emit(
                    fp,
                    "loading_failed",
                    {
                        "request_id": params.get("requestId"),
                        "error": params.get("errorText"),
                        "blocked_reason": params.get("blockedReason"),
                    },
                )
            elif method in {"Runtime.consoleAPICalled", "Log.entryAdded"}:
                emit(fp, method, {"params": params})

    ws.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
