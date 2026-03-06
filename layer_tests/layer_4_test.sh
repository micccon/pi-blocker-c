#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="$(ip route | awk '/default/ {print $3; exit}')"
if [[ -z "$TARGET_IP" ]]; then
    TARGET_IP="1.1.1.1"
fi

if command -v nmap >/dev/null 2>&1; then
    echo "[TEST][L4] Running SYN scan against $TARGET_IP with nmap"
    nmap -sS -Pn -p 30000-30020 "$TARGET_IP" >/dev/null 2>&1 || true
else
    echo "[TEST][L4] nmap not found, falling back to TCP connection attempts on $TARGET_IP"
    for port in $(seq 30000 30020); do
        timeout 1 bash -c "echo >/dev/tcp/$TARGET_IP/$port" >/dev/null 2>&1 || true
    done
fi

sleep 1
