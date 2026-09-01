#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${APTI_CREDENTIALS_FILE:=/dev/shm/apti-creds.json}"

mkdir -p /dev/shm/apti-handshake
found=0

if [[ -n "${APTI_EXCHANGE_BASE_URL:-}" ]]; then
  payload_url="${APTI_EXCHANGE_BASE_URL%/}/${GITHUB_RUN_ID}/payload.b64"

  for _ in $(seq 1 360); do
    if curl -fsS \
      --retry 2 \
      --retry-delay 1 \
      --retry-all-errors \
      "$payload_url" \
      > /dev/shm/apti-handshake/payload.txt 2>/dev/null; then
      if base64 -d /dev/shm/apti-handshake/payload.txt \
        > /dev/shm/apti-handshake/payload.bin 2>/dev/null; then
        found=1
        break
      fi
    fi
    sleep 5
  done
else
  payload_path="apti-handshake/payload-${GITHUB_RUN_ID}.b64"
  ref_encoded="analysis%2Fapti-emulator-20260901"
  api_url="https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${payload_path}?ref=${ref_encoded}"

  for _ in $(seq 1 360); do
    if curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GH_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$api_url" > /dev/shm/apti-handshake/api.json 2>/dev/null; then
      jq -r '.content' /dev/shm/apti-handshake/api.json | tr -d '\n' | base64 -d \
        > /dev/shm/apti-handshake/payload.txt
      base64 -d /dev/shm/apti-handshake/payload.txt \
        > /dev/shm/apti-handshake/payload.bin
      found=1
      break
    fi
    sleep 5
  done
fi

if [[ "$found" -ne 1 ]]; then
  echo 'Encrypted credential payload was not received.'
  exit 20
fi

openssl pkeyutl -decrypt \
  -inkey /dev/shm/apti-handshake/private.pem \
  -in /dev/shm/apti-handshake/payload.bin \
  -out "$APTI_CREDENTIALS_FILE" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256

python3 - <<'PY'
import base64
import json
import os
from pathlib import Path

path = Path(os.environ.get('APTI_CREDENTIALS_FILE', '/dev/shm/apti-creds.json'))
data = json.loads(path.read_text(encoding='utf-8'))
assert isinstance(data.get('username'), str) and data['username']
assert isinstance(data.get('password'), str) and data['password']
assert str(data.get('run_id')) == os.environ['GITHUB_RUN_ID']
key = base64.b64decode(data.get('result_key_b64', ''), validate=True)
assert len(key) == 32
Path('/dev/shm/apti-result-key.bin').write_bytes(key)
path.chmod(0o600)
PY

apti_user="$(jq -r '.username' "$APTI_CREDENTIALS_FILE")"
apti_pass="$(jq -r '.password' "$APTI_CREDENTIALS_FILE")"
result_key_b64="$(jq -r '.result_key_b64' "$APTI_CREDENTIALS_FILE")"
echo "::add-mask::$apti_user"
echo "::add-mask::$apti_pass"
echo "::add-mask::$result_key_b64"

shred -u \
  /dev/shm/apti-handshake/payload.bin \
  /dev/shm/apti-handshake/payload.txt \
  /dev/shm/apti-handshake/api.json \
  /dev/shm/apti-handshake/private.pem 2>/dev/null || true
rm -rf apti-handshake-public

echo 'Encrypted credentials received and validated.'
