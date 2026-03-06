#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BLOCKLIST_FILE="$ROOT_DIR/hostnames/blocklist.txt"

if [[ ! -f "$BLOCKLIST_FILE" ]]; then
    echo "Missing blocklist file: $BLOCKLIST_FILE"
    exit 1
fi

BLOCKED_DOMAIN="$(awk '!/^[[:space:]]*(#|$)/ {print $1; exit}' "$BLOCKLIST_FILE")"
if [[ -z "$BLOCKED_DOMAIN" ]]; then
    echo "Could not find a test domain in $BLOCKLIST_FILE"
    exit 1
fi

echo "[TEST][L7] Using blocked domain: $BLOCKED_DOMAIN"

if command -v dig >/dev/null 2>&1; then
    echo "[TEST][L7] Querying local DNS filter"
    dig @127.0.0.1 "$BLOCKED_DOMAIN" >/dev/null 2>&1 || true
elif command -v nslookup >/dev/null 2>&1; then
    echo "[TEST][L7] Querying local DNS filter"
    nslookup "$BLOCKED_DOMAIN" 127.0.0.1 >/dev/null 2>&1 || true
else
    echo "[TEST][L7] Skipping DNS test (missing dig/nslookup)"
fi

if command -v curl >/dev/null 2>&1; then
    echo "[TEST][L7] Querying local HTTP proxy"
    curl -x http://127.0.0.1:8080 "http://$BLOCKED_DOMAIN/" -m 5 -sS -o /dev/null || true
else
    echo "[TEST][L7] Skipping HTTP proxy test (missing curl)"
fi

sleep 1
