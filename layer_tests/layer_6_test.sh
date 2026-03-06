#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_6_test.sh"
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "Missing required command: openssl"
    exit 1
fi

NS_NAME="l6tls"
HOST_IF="veth-l6-host"
NS_IF="veth-l6-ns"
HOST_IP="198.51.102.1"
NS_IP="198.51.102.2"
TLS_SNI="${1:-example.com}"

cleanup() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L6] Creating namespace path to the Pi"
ip netns add "$NS_NAME"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip link set "$NS_IF" netns "$NS_NAME"
ip -n "$NS_NAME" link set lo up
ip -n "$NS_NAME" addr add "$NS_IP/24" dev "$NS_IF"
ip -n "$NS_NAME" link set "$NS_IF" up

TARGET_PORT=""
if ss -ltn '( sport = :8080 )' 2>/dev/null | rg -q ':8080'; then
    TARGET_PORT="8080"
elif ss -ltn '( sport = :443 )' 2>/dev/null | rg -q ':443'; then
    TARGET_PORT="443"
else
    echo "No listener on port 8080 or 443. Start Layer 7 HTTP proxy or another service first."
    exit 1
fi

echo "[TEST][L6] Sending a TLS 1.0 ClientHello from namespace to $HOST_IP:$TARGET_PORT"
ip netns exec "$NS_NAME" timeout 8 openssl s_client \
    -connect "${HOST_IP}:${TARGET_PORT}" \
    -tls1 \
    -servername "$TLS_SNI" </dev/null >/dev/null 2>&1 || true
sleep 1
