#!/usr/bin/env python3
from __future__ import annotations

import json
import signal
import sys
import time
from pathlib import Path

import frida


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: apti-frida-runner.py <hook.js> <output.jsonl> <seconds>", file=sys.stderr)
        return 2

    hook_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    seconds = int(sys.argv[3])
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stopping = False

    def stop_handler(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    device = frida.get_usb_device(timeout=20)
    pid = device.spawn(["aptip.app"])
    session = device.attach(pid)

    with output_path.open("a", encoding="utf-8") as fp:
        def write_row(row: dict) -> None:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")
            fp.flush()

        def on_message(message, data) -> None:
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict):
                    write_row(payload)
                else:
                    write_row({"kind": "send", "payload": str(payload)[:4000]})
            else:
                clean = dict(message)
                if "stack" in clean:
                    clean["stack"] = str(clean["stack"])[:8000]
                write_row({"kind": "frida_message", "message": clean})

        script = session.create_script(hook_path.read_text(encoding="utf-8"))
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        write_row({"kind": "runner_started", "pid": pid})

        deadline = time.monotonic() + seconds
        while not stopping and time.monotonic() < deadline:
            time.sleep(0.5)

        write_row({"kind": "runner_stopping"})
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
