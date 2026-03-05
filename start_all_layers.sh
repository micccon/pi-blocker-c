#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

extract_layer_number() {
    local base="$1"
    local layer="${base#start_layer}"
    layer="${layer%.sh}"
    layer="${layer#_}"
    printf '%s\n' "$layer"
}

wants_layer() {
    local layer="$1"

    if [[ ${REQUEST_ALL:-0} -eq 1 ]]; then
        return 0
    fi

    for req in "${REQUESTED_LAYERS[@]}"; do
        if [[ "$req" == "$layer" ]]; then
            return 0
        fi
    done
    return 1
}

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

# Build run list:
# - no args: run all discovered layers
# - args: run only requested layers
selected_scripts=()
if [[ $# -eq 0 ]]; then
    REQUEST_ALL=1
    REQUESTED_LAYERS=()
else
    REQUEST_ALL=0
    REQUESTED_LAYERS=()
    for req in "$@"; do
        if [[ ! "$req" =~ ^[0-9]+$ ]]; then
            echo "Invalid layer '$req' (expected numeric layer like 1 2 4 7)"
            exit 1
        fi
        REQUESTED_LAYERS+=("$req")
    done
fi

for rel_script in "${layer_scripts[@]}"; do
    base="$(basename "$rel_script")"
    layer="$(extract_layer_number "$base")"
    if wants_layer "$layer"; then
        selected_scripts+=("$rel_script")
    fi
done

if [[ ${REQUEST_ALL:-0} -eq 0 ]]; then
    for req in "${REQUESTED_LAYERS[@]}"; do
        found=0
        for rel_script in "${selected_scripts[@]}"; do
            base="$(basename "$rel_script")"
            layer="$(extract_layer_number "$base")"
            if [[ "$layer" == "$req" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            echo "Skipping layer $req (no start script found)"
        fi
    done
fi

if [[ ${#selected_scripts[@]} -eq 0 ]]; then
    echo "No requested layers could be started."
    exit 0
fi

# --- show resolved launch plan ---
if [[ $# -eq 0 ]]; then
    echo "Requested layers: all discovered"
else
    echo "Requested layers: $*"
fi
echo "Resolved scripts:"
for rel_script in "${selected_scripts[@]}"; do
    echo "  - $rel_script"
done

# --- cleanup stale layer processes ---
# prevents old runs from continuing to print logs (e.g., lingering Layer 3)
stale_regex='ip-filter|port-filter|arp-monitor|session-inspector|tls-inspector|dns-filter|http-proxy'
pkill -TERM -f "$stale_regex" 2>/dev/null || true
sleep 0.2
pkill -KILL -f "$stale_regex" 2>/dev/null || true

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

for rel_script in "${selected_scripts[@]}"; do
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
