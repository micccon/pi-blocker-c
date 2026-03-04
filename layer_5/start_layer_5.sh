#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root so Layer 5 can open a raw socket:"
    echo "  sudo ./start_layer_5.sh"
    exit 1
fi

if [[ ! -x "$ROOT_DIR/session-inspector" ]]; then
    echo "Missing binary. Build first:"
    echo "  make -C $ROOT_DIR"
    exit 1
fi

cd "$ROOT_DIR"
exec stdbuf -oL -eL ./session-inspector "$@"
