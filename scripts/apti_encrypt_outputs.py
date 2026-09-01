#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

root = Path(os.environ["GITHUB_WORKSPACE"])
source = root / ".apti-sensitive-results"
out_dir = root / "apti-encrypted-output"
out_dir.mkdir(parents=True, exist_ok=True)
out_file = out_dir / f"apti-results-{os.environ['GITHUB_RUN_ID']}.bin"

if not source.exists():
    source.mkdir(parents=True)
    (source / "probe-status.txt").write_text(
        "Probe produced no result directory.\n", encoding="utf-8"
    )

with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
    archive = Path(handle.name)

try:
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(source, arcname="apti-results")

    key = Path("/dev/shm/apti-result-key.bin").read_bytes()
    if len(key) != 32:
        raise RuntimeError("invalid encrypted-result key length")

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, archive.read_bytes(), b"APTI-RESULTS-v1"
    )
    out_file.write_bytes(b"APTIR1" + nonce + ciphertext)
finally:
    archive.unlink(missing_ok=True)
    shutil.rmtree(source, ignore_errors=True)

credentials = Path(os.environ.get("APTI_CREDENTIALS_FILE", "/dev/shm/apti-creds.json"))
for secret_path in (credentials, Path("/dev/shm/apti-result-key.bin")):
    try:
        secret_path.write_bytes(b"\0" * secret_path.stat().st_size)
        secret_path.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
