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

if [[ -n "${APTI_EXCHANGE_BASE_URL:-}" ]]; then
  exchange_base="${APTI_EXCHANGE_BASE_URL%/}"
  run_base="${exchange_base}/${GITHUB_RUN_ID}"

  for file_name in public.pem run-id.txt commit-sha.txt nonce.txt; do
    curl -fsS \
      --retry 8 \
      --retry-delay 2 \
      --retry-all-errors \
      -H 'Content-Type: application/octet-stream' \
      --data-binary "@apti-handshake-public/${file_name}" \
      "${run_base}/${file_name}" >/dev/null
  done

  printf '%s\n' "$GITHUB_RUN_ID" > /dev/shm/apti-handshake/latest-run-id.txt
  curl -fsS \
    --retry 8 \
    --retry-delay 2 \
    --retry-all-errors \
    -H 'Content-Type: application/octet-stream' \
    --data-binary '@/dev/shm/apti-handshake/latest-run-id.txt' \
    "${exchange_base}/latest-run-id.txt" >/dev/null

  echo 'One-time public key published to the encrypted exchange channel.'
fi
