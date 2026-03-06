#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_5_test.sh"
    exit 1
fi

TARGET_PORT="${1:-443}"
NS_NAME="l5syn"
HOST_IF="veth-l5-host"
NS_IF="veth-l5-ns"
HOST_IP="198.51.101.1"
NS_IP="198.51.101.2"

cleanup() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L5] Creating namespace path to the Pi"
ip netns add "$NS_NAME"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip link set "$NS_IF" netns "$NS_NAME"
ip -n "$NS_NAME" link set lo up
ip -n "$NS_NAME" addr add "$NS_IP/24" dev "$NS_IF"
ip -n "$NS_NAME" link set "$NS_IF" up

echo "[TEST][L5] Sending repeated SYN attempts from namespace to $HOST_IP:$TARGET_PORT"
for _ in $(seq 1 20); do
    ip netns exec "$NS_NAME" timeout 1 bash -c "echo >/dev/tcp/$HOST_IP/$TARGET_PORT" >/dev/null 2>&1 || true
done
sleep 1
