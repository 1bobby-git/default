#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

root = Path(os.environ["GITHUB_WORKSPACE"])
run_id = os.environ["GITHUB_RUN_ID"]
source = root / ".apti-sensitive-results"
result_dir = root / "apti-results-v4"
result_dir.mkdir(parents=True, exist_ok=True)
out_file = result_dir / f"result-{run_id}.bin"
meta_file = result_dir / f"result-{run_id}.json"
key_file = Path(os.environ.get("APTI_RESULT_KEY_FILE", "/dev/shm/apti-result-key.bin"))
credentials_file = Path(os.environ.get("APTI_CREDENTIALS_FILE", "/dev/shm/apti-creds.json"))

if not source.exists():
    source.mkdir(parents=True)
    (source / "probe-status.txt").write_text("Probe produced no result directory.\n", encoding="utf-8")

with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
    archive = Path(handle.name)

try:
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(source, arcname="apti-results")
    key = key_file.read_bytes()
    if len(key) != 32:
        raise RuntimeError("invalid encrypted-result key length")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, archive.read_bytes(), b"APTI-RESULTS-v1")
    out_file.write_bytes(b"APTIR1" + nonce + ciphertext)
    meta_file.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "format": "APTIR1",
                "aad": "APTI-RESULTS-v1",
                "size": out_file.stat().st_size,
                "sha256": hashlib.sha256(out_file.read_bytes()).hexdigest(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
finally:
    archive.unlink(missing_ok=True)
    shutil.rmtree(source, ignore_errors=True)

# 공개 브랜치에는 암호화 결과와 무해한 메타데이터만 남깁니다.
subprocess.run(["git", "config", "user.name", "github-actions[bot]"], cwd=root, check=True)
subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=root, check=True)
subprocess.run(["git", "pull", "--rebase", "origin", "analysis/apti-emulator-20260901"], cwd=root, check=True)
shutil.rmtree(root / "apti-handshake-v4", ignore_errors=True)
subprocess.run(["git", "add", "apti-results-v4", "apti-handshake-v4"], cwd=root, check=False)
subprocess.run(["git", "commit", "-m", f"Store encrypted Apti v4 result {run_id}"], cwd=root, check=False)
subprocess.run(["git", "push", "origin", "HEAD:analysis/apti-emulator-20260901"], cwd=root, check=True)

for secret_path in (credentials_file, key_file, Path("/dev/shm/apti-v4/private.pem")):
    try:
        size = secret_path.stat().st_size
        secret_path.write_bytes(b"\0" * size)
        secret_path.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
