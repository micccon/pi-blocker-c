#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REP_FILE="$ROOT_DIR/reputation/reputation.txt"

if [[ ! -f "$REP_FILE" ]]; then
    echo "Missing reputation file: $REP_FILE"
    exit 1
fi

LOCAL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')"
if [[ -z "$LOCAL_IP" ]]; then
    LOCAL_IP="$(hostname -I | awk '{print $1}')"
fi
if [[ -z "$LOCAL_IP" ]]; then
    echo "Could not determine local IPv4 address"
    exit 1
fi

TARGET_IP="$(ip route | awk '/default/ {print $3; exit}')"
if [[ -z "$TARGET_IP" ]]; then
    TARGET_IP="1.1.1.1"
fi

BACKUP_FILE="$(mktemp)"
cp "$REP_FILE" "$BACKUP_FILE"

cleanup() {
    cp "$BACKUP_FILE" "$REP_FILE"
    rm -f "$BACKUP_FILE"
}

trap cleanup EXIT

echo "[TEST][L3] Temporarily adding $LOCAL_IP to reputation feed"
printf '\n%s\n' "$LOCAL_IP" >> "$REP_FILE"
echo "[TEST][L3] Restart Layer 3 before running this test if it is already loaded"

echo "[TEST][L3] Generating traffic from source $LOCAL_IP to $TARGET_IP"
ping -c 3 -W 1 "$TARGET_IP" >/dev/null 2>&1 || true
sleep 1
