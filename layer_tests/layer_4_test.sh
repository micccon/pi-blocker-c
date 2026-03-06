#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_4_test.sh"
    exit 1
fi

NS_NAME="l4scan"
HOST_IF="veth-l4-host"
NS_IF="veth-l4-ns"
HOST_IP="198.51.100.1"
NS_IP="198.51.100.2"

cleanup() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L4] Creating namespace path to the Pi"
ip netns add "$NS_NAME"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip link set "$NS_IF" netns "$NS_NAME"
ip -n "$NS_NAME" link set lo up
ip -n "$NS_NAME" addr add "$NS_IP/24" dev "$NS_IF"
ip -n "$NS_NAME" link set "$NS_IF" up

if command -v nmap >/dev/null 2>&1; then
    echo "[TEST][L4] Running SYN scan from namespace to $HOST_IP"
    ip netns exec "$NS_NAME" nmap -sS -Pn -p 30000-30020 "$HOST_IP" >/dev/null 2>&1 || true
else
    echo "[TEST][L4] nmap not found, falling back to TCP connection attempts on $HOST_IP"
    for port in $(seq 30000 30020); do
        ip netns exec "$NS_NAME" timeout 1 bash -c "echo >/dev/tcp/$HOST_IP/$port" >/dev/null 2>&1 || true
    done
fi

sleep 1
