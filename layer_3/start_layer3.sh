#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root so Layer 3 can open a raw socket:"
    echo "  sudo ./start_layer3.sh        # blocked only"
    echo "  sudo ./start_layer3.sh -v     # blocked + allowed"
    exit 1
fi

if [[ ! -x "$ROOT_DIR/ip-filter" ]]; then
    echo "Missing binary. Build first:"
    echo "  make -C $ROOT_DIR"
    exit 1
fi

cd "$ROOT_DIR"
exec stdbuf -oL -eL ./ip-filter "$@"
