#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_2_test.sh"
    exit 1
fi

if ! command -v arping >/dev/null 2>&1; then
    echo "Missing required command: arping"
    exit 1
fi

BRIDGE="brtest0"
NS1="arpns1"
NS2="arpns2"
VETH1_HOST="veth1-host"
VETH1_NS="veth1-ns"
VETH2_HOST="veth2-host"
VETH2_NS="veth2-ns"
TEST_IP="192.0.2.50"

cleanup() {
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    ip link del "$VETH1_HOST" 2>/dev/null || true
    ip link del "$VETH2_HOST" 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L2] Creating bridge and namespaces"
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up

ip netns add "$NS1"
ip netns add "$NS2"

ip link add "$VETH1_HOST" type veth peer name "$VETH1_NS"
ip link add "$VETH2_HOST" type veth peer name "$VETH2_NS"

ip link set "$VETH1_HOST" master "$BRIDGE"
ip link set "$VETH2_HOST" master "$BRIDGE"
ip link set "$VETH1_HOST" up
ip link set "$VETH2_HOST" up

ip link set "$VETH1_NS" netns "$NS1"
ip link set "$VETH2_NS" netns "$NS2"

ip -n "$NS1" link set lo up
ip -n "$NS2" link set lo up
ip -n "$NS1" link set "$VETH1_NS" up
ip -n "$NS2" link set "$VETH2_NS" up

ip -n "$NS1" addr add "$TEST_IP/24" dev "$VETH1_NS"
echo "[TEST][L2] Sending first ARP announcement from namespace 1"
ip netns exec "$NS1" arping -A -c 1 -I "$VETH1_NS" "$TEST_IP" >/dev/null
sleep 1

ip -n "$NS2" addr add "$TEST_IP/24" dev "$VETH2_NS"
echo "[TEST][L2] Sending conflicting ARP announcement from namespace 2"
ip netns exec "$NS2" arping -A -c 1 -I "$VETH2_NS" "$TEST_IP" >/dev/null
sleep 1

echo "[TEST][L2] Cleanup complete"
