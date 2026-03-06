#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_1_test.sh"
    exit 1
fi

cleanup() {
    ip link del dummy0 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L1] Creating dummy interface"
ip link add dummy0 type dummy
sleep 1

echo "[TEST][L1] Bringing dummy0 up"
ip link set dummy0 up
sleep 1

echo "[TEST][L1] Bringing dummy0 down"
ip link set dummy0 down
sleep 1

echo "[TEST][L1] Cleaning up dummy0"
