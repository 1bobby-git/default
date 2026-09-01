#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mkdir -p /dev/shm/apti-handshake apti-handshake-public
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out /dev/shm/apti-handshake/private.pem
openssl pkey -in /dev/shm/apti-handshake/private.pem -pubout \
  -out apti-handshake-public/public.pem
printf '%s\n' "$GITHUB_RUN_ID" > apti-handshake-public/run-id.txt
printf '%s\n' "$GITHUB_SHA" > apti-handshake-public/commit-sha.txt
python3 - <<'PY'
import secrets
from pathlib import Path
Path('apti-handshake-public/nonce.txt').write_text(
    secrets.token_hex(24) + '\n', encoding='utf-8'
)
PY
