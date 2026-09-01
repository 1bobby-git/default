#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
PORT = int(os.environ.get("APTI_EXCHANGE_PORT", "8765"))
NONCE = os.environ["APTI_EXCHANGE_NONCE"]
RUN_ID = os.environ["GITHUB_RUN_ID"]
PRIVATE_KEY = Path(os.environ.get("APTI_EXCHANGE_PRIVATE_KEY", "/dev/shm/apti-v4/private.pem"))
CREDENTIALS_FILE = Path(os.environ.get("APTI_CREDENTIALS_FILE", "/dev/shm/apti-creds.json"))
RESULT_KEY_FILE = Path(os.environ.get("APTI_RESULT_KEY_FILE", "/dev/shm/apti-result-key.bin"))
DONE_FILE = Path(os.environ.get("APTI_EXCHANGE_DONE_FILE", "/dev/shm/apti-v4/exchange.done"))


def decrypt_payload(ciphertext: bytes) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="apti-v4-exchange-") as temp_dir:
        temp = Path(temp_dir)
        encrypted = temp / "payload.bin"
        clear = temp / "payload.json"
        encrypted.write_bytes(ciphertext)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-inkey",
                str(PRIVATE_KEY),
                "-in",
                str(encrypted),
                "-out",
                str(clear),
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return json.loads(clear.read_text(encoding="utf-8"))


def validate_payload(data: dict[str, object]) -> tuple[str, str, bytes]:
    if str(data.get("run_id")) != RUN_ID:
        raise ValueError("run_id mismatch")
    if str(data.get("nonce")) != NONCE:
        raise ValueError("nonce mismatch")
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not username or len(username) > 256:
        raise ValueError("invalid username")
    if not isinstance(password, str) or not password or len(password) > 256:
        raise ValueError("invalid password")
    key = base64.b64decode(str(data.get("result_key_b64", "")), validate=True)
    if len(key) != 32:
        raise ValueError("invalid result key")
    return username, password, key


class Handler(BaseHTTPRequestHandler):
    server_version = "AptiExchange/1"

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_response(204)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != f"/submit/{NONCE}":
            self.send_error(404)
            return
        if DONE_FILE.exists():
            self.send_error(409)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                raise ValueError("invalid content length")
            body = self.rfile.read(length)
            ciphertext = base64.b64decode(body, validate=True)
            data = decrypt_payload(ciphertext)
            username, password, key = validate_payload(data)

            CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
            CREDENTIALS_FILE.write_text(
                json.dumps({"username": username, "password": password}, ensure_ascii=False),
                encoding="utf-8",
            )
            CREDENTIALS_FILE.chmod(0o600)
            RESULT_KEY_FILE.write_bytes(key)
            RESULT_KEY_FILE.chmod(0o600)
            DONE_FILE.parent.mkdir(parents=True, exist_ok=True)
            DONE_FILE.write_text("ok\n", encoding="utf-8")
            DONE_FILE.chmod(0o600)
            self.send_response(204)
            self.end_headers()
        except Exception:
            self.send_error(400)


if __name__ == "__main__":
    PRIVATE_KEY.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever(poll_interval=0.2)
