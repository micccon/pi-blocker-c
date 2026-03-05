#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root so Layer 4 can open a raw socket:"
    echo "  sudo ./start_layer4.sh"
    exit 1
fi

if [[ ! -x "$ROOT_DIR/port-filter" ]]; then
    echo "Missing binary. Build first:"
    echo "  make -C $ROOT_DIR"
    exit 1
fi

cd "$ROOT_DIR"
exec stdbuf -oL -eL ./port-filter "$@"
