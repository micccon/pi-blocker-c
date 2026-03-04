#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAYER6_DIR="$ROOT_DIR/layer_6"
LAYER7_DIR="$ROOT_DIR/layer_7"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root so Layer 6/7 can bind required sockets:"
    echo "  sudo ./start_layer6_7.sh"
    exit 1
fi

if [[ ! -x "$LAYER6_DIR/tls-inspector" ]]; then
    echo "Missing Layer 6 binary. Build first:"
    echo "  make -C $LAYER6_DIR"
    exit 1
fi

if [[ ! -x "$LAYER7_DIR/dns/dns-filter" || ! -x "$LAYER7_DIR/http/http-proxy" ]]; then
    echo "Missing Layer 7 binaries. Build first:"
    echo "  make -C $LAYER7_DIR"
    exit 1
fi

cleanup() {
    local status=$?
    trap - INT TERM EXIT
    if [[ -n "${layer6_pid:-}" ]]; then
        kill "$layer6_pid" 2>/dev/null || true
    fi
    if [[ -n "${layer7_pid:-}" ]]; then
        kill "$layer7_pid" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    exit "$status"
}

trap cleanup INT TERM EXIT

(
    cd "$LAYER6_DIR"
    ./start_layer6.sh
) &
layer6_pid=$!

(
    cd "$LAYER7_DIR"
    ./start_layer7.sh
) &
layer7_pid=$!

echo "Layer 6 + Layer 7 started:"
echo "  Layer 6 PID=$layer6_pid"
echo "  Layer 7 PID=$layer7_pid"

wait -n "$layer6_pid" "$layer7_pid"

