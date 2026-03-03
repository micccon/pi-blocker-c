#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root so DNS can bind UDP port 53:"
    echo "  sudo ./start_layer7.sh"
    exit 1
fi

if [[ ! -x "$ROOT_DIR/dns/dns-filter" || ! -x "$ROOT_DIR/http/http-proxy" ]]; then
    echo "Missing binaries. Build first:"
    echo "  make -C $ROOT_DIR"
    exit 1
fi

cleanup() {
    local status=$?
    trap - INT TERM EXIT
    if [[ -n "${dns_pid:-}" ]]; then
        kill "$dns_pid" 2>/dev/null || true
    fi
    if [[ -n "${http_pid:-}" ]]; then
        kill "$http_pid" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    exit "$status"
}

trap cleanup INT TERM EXIT

(
    cd "$ROOT_DIR/dns"
    ./dns-filter
) &
dns_pid=$!

(
    cd "$ROOT_DIR/http"
    ./http-proxy
) &
http_pid=$!

echo "Layer 7 started:"
echo "  DNS  PID=$dns_pid  port=53/udp"
echo "  HTTP PID=$http_pid port=8080/tcp"

wait -n "$dns_pid" "$http_pid"
