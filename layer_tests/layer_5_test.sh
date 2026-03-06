#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="$(ip route | awk '/default/ {print $3; exit}')"
if [[ -z "$TARGET_IP" ]]; then
    TARGET_IP="1.1.1.1"
fi

TARGET_PORT="${1:-443}"

echo "[TEST][L5] Sending repeated SYN attempts to $TARGET_IP:$TARGET_PORT"
for _ in $(seq 1 20); do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET_IP/$TARGET_PORT" >/dev/null 2>&1 || true
done
sleep 1
