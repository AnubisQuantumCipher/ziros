#!/bin/bash
# zkf-build.sh — Adaptive resource-aware build wrapper for ZKF.
#
# Detects available system RAM and CPU cores, then sets CARGO_BUILD_JOBS
# to an appropriate value before invoking cargo build.
#
# Usage:
#   ./zkf-build.sh                  # Build workspace with adaptive jobs
#   ./zkf-build.sh --release        # Release build
#   ./zkf-build.sh -p zkf-core      # Build single crate
#   ./zkf-build.sh test             # Run tests with adaptive parallelism
#
# Or use eval to set env vars in your shell:
#   eval $(./zkf-build.sh --env-only)

set -euo pipefail

# ── Detect system resources ──────────────────────────────────────────────

detect_total_ram_gb() {
    if [[ "$(uname)" == "Darwin" ]]; then
        local bytes
        bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        echo "scale=1; $bytes / 1073741824" | bc
    elif [[ -f /proc/meminfo ]]; then
        local kb
        kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        echo "scale=1; $kb / 1048576" | bc
    else
        echo "0"
    fi
}

detect_available_ram_gb() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # Parse vm_stat for free + inactive + purgeable pages
        local pagesize
        pagesize=$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)
        local free inactive purgeable
        free=$(vm_stat 2>/dev/null | grep "Pages free" | awk '{print $3}' | tr -d '.')
        inactive=$(vm_stat 2>/dev/null | grep "Pages inactive" | awk '{print $3}' | tr -d '.')
        purgeable=$(vm_stat 2>/dev/null | grep "Pages purgeable" | awk '{print $3}' | tr -d '.')
        free=${free:-0}
        inactive=${inactive:-0}
        purgeable=${purgeable:-0}
        local bytes=$(( (free + inactive + purgeable) * pagesize ))
        echo "scale=1; $bytes / 1073741824" | bc
    elif [[ -f /proc/meminfo ]]; then
        local kb
        kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
        echo "scale=1; $kb / 1048576" | bc
    else
        echo "0"
    fi
}

detect_physical_cores() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sysctl -n hw.physicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4
    elif command -v nproc &>/dev/null; then
        nproc
    else
        echo 4
    fi
}

# ── Calculate optimal parallelism ────────────────────────────────────────

calculate_jobs() {
    local total_gb="$1"
    local available_gb="$2"
    local cores="$3"

    # Headroom: 8 GB on ≥32 GB systems, 4 GB otherwise
    local headroom
    if (( $(echo "$total_gb >= 32" | bc -l) )); then
        headroom=8
    else
        headroom=4
    fi

    # Budget = available - headroom
    local budget
    budget=$(echo "$available_gb - $headroom" | bc)
    if (( $(echo "$budget < 1" | bc -l) )); then
        budget=1
    fi

    # Each rustc instance: ~3 GB for ZKF workspace crates
    local ram_per_job=3
    local max_by_ram
    max_by_ram=$(echo "$budget / $ram_per_job" | bc)
    if (( max_by_ram < 1 )); then
        max_by_ram=1
    fi

    # Cap by core count
    local jobs=$max_by_ram
    if (( jobs > cores )); then
        jobs=$cores
    fi
    if (( jobs < 1 )); then
        jobs=1
    fi

    echo "$jobs"
}

# ── Main ─────────────────────────────────────────────────────────────────

TOTAL_GB=$(detect_total_ram_gb)
AVAILABLE_GB=$(detect_available_ram_gb)
CORES=$(detect_physical_cores)
JOBS=$(calculate_jobs "$TOTAL_GB" "$AVAILABLE_GB" "$CORES")

# --env-only: just print exports and exit
if [[ "${1:-}" == "--env-only" ]]; then
    echo "export CARGO_BUILD_JOBS=$JOBS"
    echo "export ZKF_PROVING_THREADS=$CORES"
    echo "# System: ${TOTAL_GB}GB total, ${AVAILABLE_GB}GB available, ${CORES} cores → ${JOBS} jobs"
    exit 0
fi

echo "zkf-build: ${TOTAL_GB}GB total, ${AVAILABLE_GB}GB available, ${CORES} cores → ${JOBS} parallel jobs"

export CARGO_BUILD_JOBS="$JOBS"

# On macOS, disable the Nano zone allocator to prevent "Failed to allocate
# segment from range group" errors during memory-intensive operations like
# STARK-to-Groth16 wrapping. The zkf binary uses mimalloc as global allocator,
# but this catches any transitive C allocations that bypass Rust's allocator.
if [[ "$(uname)" == "Darwin" ]]; then
    export MallocNanoZone=0
    echo "zkf-build: MallocNanoZone=0 (macOS memory safety)"
fi

# Pass through all arguments to cargo
if [[ $# -eq 0 ]]; then
    exec cargo build --workspace
else
    # If first arg looks like a cargo subcommand, prepend 'cargo'
    case "${1:-}" in
        build|test|check|clippy|doc|bench|run)
            exec cargo "$@"
            ;;
        *)
            exec cargo build "$@"
            ;;
    esac
fi
