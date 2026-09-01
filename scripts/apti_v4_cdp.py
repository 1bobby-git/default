#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import websocket

SENSITIVE = re.compile(
    r"authorization|cookie|token|secret|password|passwd|session|jwt|bearer|member.?id|user.?id",
    re.I,
)


def clean_url(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    try:
        parts = urllib.parse.urlsplit(text)
        query = []
        for key, val in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "<redacted>" if SENSITIVE.search(key) else val[:500]))
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), "")
        )
    except Exception:
        return text[:5000]


def header_inventory(headers: Any) -> dict[str, Any]:
    if not isinstance(headers, dict):
        return {"names": [], "selected": {}}
    names = sorted({str(key).lower() for key in headers})
    selected: dict[str, str] = {}
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in {"accept", "content-type", "origin", "referer", "user-agent", "location", "x-requested-with"}:
            selected[lower] = clean_url(value) if lower in {"referer", "location"} else str(value)[:1000]
    return {"names": names, "selected": selected}


def emit(handle, label: str, kind: str, data: dict[str, Any]) -> None:
    handle.write(
        json.dumps(
            {"ts": time.time(), "label": label, "kind": kind, **data},
            ensure_ascii=False,
        )
        + "\n"
    )
    handle.flush()


def get_targets(port: int) -> list[dict[str, Any]]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=3) as response:
        data = json.load(response)
    return data if isinstance(data, list) else []


def send(ws, counter: list[int], method: str, params: dict[str, Any] | None = None) -> int:
    request_id = counter[0]
    counter[0] += 1
    ws.send(json.dumps({"id": request_id, "method": method, "params": params or {}}))
    return request_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--duration", type=float, default=45.0)
    parser.add_argument("--label", default="cdp")
    parser.add_argument("--wait", type=float, default=30.0)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + args.wait
    target: dict[str, Any] | None = None
    last_error = ""
    while time.time() < deadline and target is None:
        try:
            targets = get_targets(args.port)
            pages = [item for item in targets if item.get("type") in {"page", "webview"} and item.get("webSocketDebuggerUrl")]
            if pages:
                target = pages[0]
                break
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)

    with output.open("w", encoding="utf-8") as handle:
        if target is None:
            emit(handle, args.label, "attach_failed", {"error": last_error[:1000]})
            return 2

        emit(
            handle,
            args.label,
            "target",
            {
                "id": target.get("id"),
                "type": target.get("type"),
                "title": str(target.get("title", ""))[:1000],
                "url": clean_url(target.get("url")),
            },
        )
        ws_url = str(target["webSocketDebuggerUrl"]).replace("localhost", "127.0.0.1")
        ws = websocket.create_connection(ws_url, timeout=1.0, suppress_origin=True)
        counter = [1]
        send(ws, counter, "Network.enable", {"maxTotalBufferSize": 10000000, "maxResourceBufferSize": 2000000})
        send(ws, counter, "Page.enable")
        send(ws, counter, "Runtime.enable")
        send(ws, counter, "Log.enable")

        end_at = time.time() + args.duration
        while time.time() < end_at:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as exc:
                emit(handle, args.label, "socket_error", {"error": str(exc)[:1000]})
                break
            try:
                message = json.loads(raw)
            except Exception:
                continue
            method = message.get("method")
            params = message.get("params", {})
            if method == "Network.requestWillBeSent":
                request = params.get("request", {})
                row = {
                    "request_id": params.get("requestId"),
                    "document_url": clean_url(params.get("documentURL")),
                    "url": clean_url(request.get("url")),
                    "method": request.get("method"),
                    "type": params.get("type"),
                    "headers": header_inventory(request.get("headers")),
                    "has_post_data": bool(request.get("hasPostData")),
                    "initiator_type": (params.get("initiator") or {}).get("type"),
                }
                redirect = params.get("redirectResponse")
                if isinstance(redirect, dict):
                    row["redirect_response"] = {
                        "url": clean_url(redirect.get("url")),
                        "status": redirect.get("status"),
                        "status_text": str(redirect.get("statusText", ""))[:500],
                        "headers": header_inventory(redirect.get("headers")),
                    }
                emit(handle, args.label, "request", row)
            elif method == "Network.responseReceived":
                response = params.get("response", {})
                emit(
                    handle,
                    args.label,
                    "response",
                    {
                        "request_id": params.get("requestId"),
                        "url": clean_url(response.get("url")),
                        "status": response.get("status"),
                        "status_text": str(response.get("statusText", ""))[:500],
                        "mime_type": response.get("mimeType"),
                        "from_disk_cache": response.get("fromDiskCache"),
                        "from_service_worker": response.get("fromServiceWorker"),
                        "headers": header_inventory(response.get("headers")),
                    },
                )
            elif method == "Network.loadingFailed":
                emit(
                    handle,
                    args.label,
                    "loading_failed",
                    {
                        "request_id": params.get("requestId"),
                        "error": str(params.get("errorText", ""))[:1000],
                        "blocked_reason": params.get("blockedReason"),
                        "canceled": params.get("canceled"),
                    },
                )
            elif method == "Page.frameNavigated":
                frame = params.get("frame", {})
                emit(
                    handle,
                    args.label,
                    "frame_navigated",
                    {
                        "frame_id": frame.get("id"),
                        "parent_id": frame.get("parentId"),
                        "name": str(frame.get("name", ""))[:500],
                        "url": clean_url(frame.get("url")),
                    },
                )
            elif method == "Runtime.consoleAPICalled":
                values = []
                for item in params.get("args", [])[:20]:
                    value = item.get("value")
                    if value is not None:
                        values.append(str(value)[:1000])
                emit(handle, args.label, "console", {"type": params.get("type"), "values": values})
            elif method == "Log.entryAdded":
                entry = params.get("entry", {})
                emit(
                    handle,
                    args.label,
                    "log",
                    {
                        "source": entry.get("source"),
                        "level": entry.get("level"),
                        "text": str(entry.get("text", ""))[:2000],
                        "url": clean_url(entry.get("url")),
                    },
                )

        expressions = {
            "page_state": "JSON.stringify({href:location.href,title:document.title,readyState:document.readyState,userAgent:navigator.userAgent,text:(document.body?document.body.innerText.slice(0,20000):'')})",
            "storage_keys": "JSON.stringify({local:Object.keys(localStorage),session:Object.keys(sessionStorage),cookieNames:document.cookie.split(';').map(v=>v.split('=')[0].trim()).filter(Boolean),bridgeNames:Object.getOwnPropertyNames(window).filter(v=>/apti|android|native|bridge|reactnative|webkit/i.test(v))})",
            "resources": "JSON.stringify(performance.getEntriesByType('resource').map(v=>({name:v.name,initiatorType:v.initiatorType})).slice(-1000))",
        }
        pending: dict[int, str] = {}
        for name, expression in expressions.items():
            pending[send(ws, counter, "Runtime.evaluate", {"expression": expression, "returnByValue": True})] = name
        pending[send(ws, counter, "Network.getAllCookies")] = "cookies"
        finish = time.time() + 5
        while pending and time.time() < finish:
            try:
                message = json.loads(ws.recv())
            except Exception:
                continue
            response_id = message.get("id")
            if response_id not in pending:
                continue
            name = pending.pop(response_id)
            result = message.get("result", {})
            if name == "cookies":
                cookies = result.get("cookies", [])
                inventory = [
                    {"name": item.get("name"), "domain": item.get("domain"), "path": item.get("path"), "secure": item.get("secure"), "httpOnly": item.get("httpOnly"), "sameSite": item.get("sameSite")}
                    for item in cookies
                ]
                emit(handle, args.label, "cookie_inventory", {"cookies": inventory})
            else:
                value = ((result.get("result") or {}).get("value"))
                try:
                    parsed = json.loads(value) if isinstance(value, str) else value
                except Exception:
                    parsed = value
                if name == "page_state" and isinstance(parsed, dict):
                    parsed["href"] = clean_url(parsed.get("href"))
                    parsed["text"] = str(parsed.get("text", ""))[:20000]
                elif name == "resources" and isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            item["name"] = clean_url(item.get("name"))
                emit(handle, args.label, name, {"value": parsed})
        ws.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
