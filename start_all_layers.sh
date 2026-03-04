#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Discover scripts like start_layer1.sh, start_layer_5.sh, start_layer7.sh.
# This avoids updating this script as new layers are added.
mapfile -t scripts < <(
    find "$ROOT_DIR" -mindepth 2 -maxdepth 2 -type f -name 'start_layer*.sh' \
        -printf '%P\n' | sort
)

layer_scripts=()
for script in "${scripts[@]}"; do
    base="$(basename "$script")"
    if [[ "$base" =~ ^start_layer_?[0-9]+\.sh$ ]]; then
        layer_scripts+=("$script")
    fi
done

if [[ ${#layer_scripts[@]} -eq 0 ]]; then
    echo "No layer start scripts found."
    exit 0
fi

pids=()

cleanup() {
    local status=$?
    trap - INT TERM EXIT
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    exit "$status"
}

trap cleanup INT TERM EXIT

for rel_script in "${layer_scripts[@]}"; do
    script_dir="$ROOT_DIR/$(dirname "$rel_script")"
    script_name="$(basename "$rel_script")"

    (
        cd "$script_dir"
        stdbuf -oL -eL "./$script_name"
    ) &
    pid=$!
    pids+=("$pid")
    echo "Started $rel_script (PID=$pid)"
done

wait -n "${pids[@]}"
