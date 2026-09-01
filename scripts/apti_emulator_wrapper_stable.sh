#!/usr/bin/env bash
set -Eeuo pipefail

export APTI_SECURE_RESULT_DIR="${GITHUB_WORKSPACE}/.apti-sensitive-results"
mkdir -p "$APTI_SECURE_RESULT_DIR/exact-original-https"
preflight="$APTI_SECURE_RESULT_DIR/exact-original-https/gms-stabilization.txt"

adb wait-for-device
for _ in $(seq 1 120); do
  [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
  sleep 2
done

adb shell logcat -c >/dev/null 2>&1 || true
{
  echo "stabilization_started_utc=$(date -u +%FT%TZ)"
  echo "boot_completed=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
  echo "gms_version_before=$(adb shell dumpsys package com.google.android.gms 2>/dev/null | grep -m1 'versionCode=' || true)"
} > "$preflight"

# Google Play system images update GMS/Chronet modules shortly after first boot.
# Starting Apti during that window causes DynamiteLoader to SIGKILL the app process.
# Keep Play Store enabled because the original HTTPS click URL uses its market deep-link handoff.
for index in $(seq 1 12); do
  sleep 15
  {
    echo "sample=${index} utc=$(date -u +%FT%TZ)"
    echo "gms_pid=$(adb shell pidof com.google.android.gms 2>/dev/null | tr -d '\r' || true)"
    echo "gms_version=$(adb shell dumpsys package com.google.android.gms 2>/dev/null | grep -m1 'versionCode=' || true)"
  } >> "$preflight"
done

adb logcat -d -v threadtime > "$APTI_SECURE_RESULT_DIR/exact-original-https/gms-stabilization-logcat.txt" 2>&1 || true
echo "stabilization_finished_utc=$(date -u +%FT%TZ)" >> "$preflight"

exec bash scripts/apti_emulator_wrapper.sh
