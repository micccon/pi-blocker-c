#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REP_FILE="$ROOT_DIR/reputation/reputation.txt"

NS_NAME="l3testns"
HOST_VETH="veth-l3-host"
NS_VETH="veth-l3-ns"
HOST_IP="198.51.99.1/24"
TARGET_IP="198.51.99.1"
NS_IP="198.51.99.2/24"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root:"
    echo "  sudo ./layer_tests/layer_3_test.sh"
    exit 1
fi

if [[ ! -f "$REP_FILE" ]]; then
    echo "Missing reputation file: $REP_FILE"
    exit 1
fi

if ! command -v hping3 >/dev/null 2>&1; then
    echo "Missing hping3. Install it first:"
    echo "  sudo apt update"
    echo "  sudo apt install hping3"
    exit 1
fi

BLOCKED_SRC_IP="$(
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $0 !~ /\// && $0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }
    ' "$REP_FILE"
)"

CIDR_ENTRY="$(
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ { print; exit }
    ' "$REP_FILE"
)"

if [[ -z "$BLOCKED_SRC_IP" ]]; then
    echo "Could not find an exact IPv4 entry in $REP_FILE"
    exit 1
fi

if [[ -z "$CIDR_ENTRY" ]]; then
    echo "Could not find a CIDR entry in $REP_FILE"
    exit 1
fi

cidr_network="${CIDR_ENTRY%/*}"
cidr_prefix="${CIDR_ENTRY#*/}"

IFS=. read -r o1 o2 o3 o4 <<< "$cidr_network"
cidr_ip_int=$(( (o1 << 24) | (o2 << 16) | (o3 << 8) | o4 ))

if (( cidr_prefix >= 32 )); then
    CIDR_TEST_IP="$cidr_network"
else
    CIDR_TEST_IP_INT=$(( cidr_ip_int + 1 ))
    CIDR_TEST_IP="$(
        printf '%d.%d.%d.%d' \
            $(( (CIDR_TEST_IP_INT >> 24) & 255 )) \
            $(( (CIDR_TEST_IP_INT >> 16) & 255 )) \
            $(( (CIDR_TEST_IP_INT >> 8) & 255 )) \
            $(( CIDR_TEST_IP_INT & 255 ))
    )"
fi

cleanup() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$HOST_VETH" 2>/dev/null || true
}

trap cleanup EXIT

echo "[TEST][L3] Using blocked source IP from reputation feed: $BLOCKED_SRC_IP"
echo "[TEST][L3] Using blocked CIDR from reputation feed: $CIDR_ENTRY"
echo "[TEST][L3] Using CIDR test source IP: $CIDR_TEST_IP"

echo "[TEST][L3] Creating namespace and veth pair"
ip netns add "$NS_NAME"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS_NAME"

ip addr add "$HOST_IP" dev "$HOST_VETH"
ip link set "$HOST_VETH" up

ip netns exec "$NS_NAME" ip addr add "$NS_IP" dev "$NS_VETH"
ip netns exec "$NS_NAME" ip link set lo up
ip netns exec "$NS_NAME" ip link set "$NS_VETH" up

echo "[TEST][L3] Sending spoofed TCP SYN packets from $BLOCKED_SRC_IP to $TARGET_IP"
ip netns exec "$NS_NAME" hping3 -q -c 5 -S -p 443 -a "$BLOCKED_SRC_IP" "$TARGET_IP" >/dev/null 2>&1 || true
echo "[TEST][L3] Sending spoofed TCP SYN packets from $CIDR_TEST_IP to $TARGET_IP"
ip netns exec "$NS_NAME" hping3 -q -c 5 -S -p 443 -a "$CIDR_TEST_IP" "$TARGET_IP" >/dev/null 2>&1 || true
sleep 1
