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

selected_scripts=()
if [[ $# -eq 0 ]]; then
    for rel_script in "${layer_scripts[@]}"; do
        selected_scripts+=("$rel_script")
    done
else
    for req in "$@"; do
        if [[ ! "$req" =~ ^[0-9]+$ ]]; then
            echo "Invalid layer '$req' (expected numeric layer like 1 2 4 7)"
            exit 1
        fi

        layer_dir="$ROOT_DIR/layer_$req"
        if [[ ! -d "$layer_dir" ]]; then
            echo "Skipping layer $req (directory not found)"
            continue
        fi

        found=0
        while IFS= read -r abs_script; do
            base="$(basename "$abs_script")"
            if [[ "$base" =~ ^start_layer_?[0-9]+\.sh$ ]]; then
                selected_scripts+=("${abs_script#$ROOT_DIR/}")
                found=1
            fi
        done < <(find "$layer_dir" -maxdepth 1 -type f -name 'start_layer*.sh' | sort)

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
