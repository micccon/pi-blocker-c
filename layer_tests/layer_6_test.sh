#!/usr/bin/env bash
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
    echo "Missing required command: openssl"
    exit 1
fi

TARGET_HOST="${1:-example.com}"

echo "[TEST][L6] Sending a TLS 1.0 ClientHello to $TARGET_HOST:443"
timeout 8 openssl s_client -connect "${TARGET_HOST}:443" -tls1 -servername "$TARGET_HOST" </dev/null >/dev/null 2>&1 || true
sleep 1
