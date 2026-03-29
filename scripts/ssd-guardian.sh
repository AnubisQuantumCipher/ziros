#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZirOS SSD Guardian
# ============================================================================
#
# Intelligent storage management for ZirOS proving workloads.
# Classifies files by retention policy, archives proofs and telemetry
# to iCloud, purges ephemeral artifacts, and reports storage health.
#
# Usage:
#   ssd-guardian.sh status          Show current storage state
#   ssd-guardian.sh archive         Archive proofs + telemetry to iCloud
#   ssd-guardian.sh purge           Purge ephemeral build/witness artifacts
#   ssd-guardian.sh sweep           Full cycle: archive then purge
#   ssd-guardian.sh watch           Continuous monitor (runs every 30 min)
#   ssd-guardian.sh restore <path>  Force-download a cloud file locally
#
# Environment:
#   ZIROS_REPO          Path to ZirOS repo (default: auto-detect)
#   ZIROS_ICLOUD_ROOT   iCloud archive root (default: auto-detect)
#   ZIROS_SSD_WARN_GB   Warn threshold in GB (default: 100)
#   ZIROS_SSD_CRIT_GB   Critical threshold in GB (default: 50)
#   ZIROS_DRY_RUN       Set to 1 for dry-run mode
#
# ============================================================================

VERSION="1.0.0"
SCRIPT_NAME="ssd-guardian"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ZIROS_REPO="${ZIROS_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
WARN_GB="${ZIROS_SSD_WARN_GB:-100}"
CRIT_GB="${ZIROS_SSD_CRIT_GB:-50}"
DRY_RUN="${ZIROS_DRY_RUN:-0}"
ZKF_HOME="${HOME}/.zkf"
DESKTOP="${HOME}/Desktop"

# Auto-detect writable iCloud Drive path
detect_icloud_root() {
    # The writable iCloud Drive root is Mobile Documents, not CloudStorage
    local mobile_docs="${HOME}/Library/Mobile Documents/com~apple~CloudDocs"
    if [ -d "$mobile_docs" ]; then
        echo "$mobile_docs"
        return 0
    fi
    echo ""
    return 1
}

ICLOUD_ROOT="${ZIROS_ICLOUD_ROOT:-$(detect_icloud_root || echo "")}"
ICLOUD_ARCHIVE="${ICLOUD_ROOT:+${ICLOUD_ROOT}/ZirOS_Archive}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo "[${SCRIPT_NAME}] $*"; }
warn() { echo "[${SCRIPT_NAME}] WARNING: $*" >&2; }
err() { echo "[${SCRIPT_NAME}] ERROR: $*" >&2; }

bytes_to_human() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(echo "scale=1; $bytes / 1073741824" | bc) GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(echo "scale=1; $bytes / 1048576" | bc) MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(echo "scale=0; $bytes / 1024" | bc) KB"
    else
        echo "${bytes} B"
    fi
}

dir_size_bytes() {
    if [ -d "$1" ]; then
        du -sk "$1" 2>/dev/null | awk '{print $1 * 1024}'
    else
        echo 0
    fi
}

free_space_gb() {
    df -g / | tail -1 | awk '{print $4}'
}

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

safe_move() {
    local src="$1" dst="$2"
    if is_dry_run; then
        log "  [dry-run] would move: $src → $dst"
    else
        mkdir -p "$(dirname "$dst")"
        mv "$src" "$dst"
    fi
}

safe_rm() {
    local target="$1"
    if is_dry_run; then
        log "  [dry-run] would delete: $target ($(bytes_to_human "$(dir_size_bytes "$target")"))"
    else
        rm -rf "$target"
    fi
}

# ---------------------------------------------------------------------------
# File Classification
# ---------------------------------------------------------------------------

# KEEP locally — small, operationally critical
is_local_critical() {
    local path="$1"
    case "$path" in
        */.zkf/swarm/*) return 0 ;;           # Live swarm state
        */.zkf/keystore/*) return 0 ;;         # Cryptographic keys
        */.zkf/tuning/*) return 0 ;;           # Adaptive thresholds
        */.zkf/security/*) return 0 ;;         # Security quarantine
        *) return 1 ;;
    esac
}

# ARCHIVE to iCloud — valuable, rarely accessed locally
is_archivable() {
    local path="$1"
    case "$path" in
        *.proof.json) return 0 ;;               # Proof artifacts (tiny, archival)
        *.execution_trace.json) return 0 ;;     # Execution traces (research)
        *.runtime_trace.json) return 0 ;;       # Runtime telemetry
        *.calldata.json) return 0 ;;            # On-chain calldata
        *.report.md) return 0 ;;                # Generated reports
        *.summary.json) return 0 ;;             # Run summaries
        *.audit.json) return 0 ;;               # Audit results
        *Verifier.sol) return 0 ;;              # Solidity verifiers
        */metal_doctor.json) return 0 ;;        # GPU diagnostics
        */machine_info.txt) return 0 ;;         # Machine details
        */.zkf/telemetry/*) return 0 ;;         # Telemetry records
        *) return 1 ;;
    esac
}

# PURGE — large, ephemeral, can be regenerated
is_purgeable() {
    local path="$1"
    case "$path" in
        */target-local/debug/*) return 0 ;;     # Debug build cache
        */target-local/kani/*) return 0 ;;      # Kani verification cache
        */target/debug/*) return 0 ;;           # Alternate target
        *.compiled.json) return 0 ;;            # Compiled programs (regenerate from source)
        *.witness.*.json) return 0 ;;           # Witness files (sensitive, ephemeral)
        *.witness.base.json) return 0 ;;        # Base witness
        *.witness.prepared.json) return 0 ;;    # Prepared witness
        *.original.program.json) return 0 ;;    # Original program (regenerate)
        *.optimized.program.json) return 0 ;;   # Optimized program (regenerate)
        *.inputs.json) return 0 ;;              # Input files (regenerate)
        *.request.json) return 0 ;;             # Request files (regenerate)
        */foundry/*) return 0 ;;                # Foundry test projects
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_status() {
    log "ZirOS SSD Guardian v${VERSION}"
    log "================================================"
    echo ""

    # Disk health
    local free_gb
    free_gb=$(free_space_gb)
    local status_icon="✓"
    local status_text="healthy"
    if [ "$free_gb" -lt "$CRIT_GB" ]; then
        status_icon="✗"
        status_text="CRITICAL"
    elif [ "$free_gb" -lt "$WARN_GB" ]; then
        status_icon="!"
        status_text="WARNING"
    fi
    log "Disk: ${free_gb} GB free [${status_icon} ${status_text}]"
    echo ""

    # Build cache
    local debug_bytes release_bytes kani_bytes
    debug_bytes=$(dir_size_bytes "${ZIROS_REPO}/target-local/debug")
    release_bytes=$(dir_size_bytes "${ZIROS_REPO}/target-local/release")
    kani_bytes=$(dir_size_bytes "${ZIROS_REPO}/target-local/kani")
    local build_total=$((debug_bytes + release_bytes + kani_bytes))

    log "Build cache:"
    log "  debug/    $(bytes_to_human "$debug_bytes")"
    log "  release/  $(bytes_to_human "$release_bytes")"
    log "  kani/     $(bytes_to_human "$kani_bytes")"
    log "  TOTAL     $(bytes_to_human "$build_total")"
    echo ""

    # ZKF home
    local telemetry_bytes swarm_bytes models_bytes
    telemetry_bytes=$(dir_size_bytes "${ZKF_HOME}/telemetry")
    swarm_bytes=$(dir_size_bytes "${ZKF_HOME}/swarm")
    models_bytes=$(dir_size_bytes "${ZKF_HOME}/models")
    log "Runtime state (~/.zkf/):"
    log "  telemetry/ $(bytes_to_human "$telemetry_bytes") ($(ls "${ZKF_HOME}/telemetry" 2>/dev/null | wc -l | tr -d ' ') files)"
    log "  swarm/     $(bytes_to_human "$swarm_bytes")"
    log "  models/    $(bytes_to_human "$models_bytes")"
    echo ""

    # Desktop showcase outputs
    local desktop_total=0
    local showcase_count=0
    if [ -d "$DESKTOP" ]; then
        for dir in "$DESKTOP"/ZirOS_* "$DESKTOP"/ziros-* ; do
            if [ -d "$dir" ]; then
                local dir_bytes
                dir_bytes=$(dir_size_bytes "$dir")
                desktop_total=$((desktop_total + dir_bytes))
                showcase_count=$((showcase_count + 1))
                log "  $(basename "$dir"): $(bytes_to_human "$dir_bytes")"
            fi
        done
    fi
    if [ "$showcase_count" -gt 0 ]; then
        log "Showcase outputs: ${showcase_count} dirs, $(bytes_to_human "$desktop_total") total"
    else
        log "Showcase outputs: none found"
    fi
    echo ""

    # iCloud archive
    if [ -n "$ICLOUD_ROOT" ] && [ -d "$ICLOUD_ARCHIVE" ]; then
        local archive_bytes
        archive_bytes=$(dir_size_bytes "$ICLOUD_ARCHIVE")
        log "iCloud archive: $(bytes_to_human "$archive_bytes") at ${ICLOUD_ARCHIVE}"
    elif [ -n "$ICLOUD_ROOT" ]; then
        log "iCloud archive: not yet created (${ICLOUD_ARCHIVE})"
    else
        log "iCloud archive: iCloud Drive not detected"
    fi
    echo ""

    # Purgeable estimate
    local purgeable=$((build_total))
    # Add purgeable files from showcase dirs
    if [ -d "$DESKTOP" ]; then
        for dir in "$DESKTOP"/ZirOS_* "$DESKTOP"/ziros-*; do
            if [ -d "$dir" ]; then
                while IFS= read -r -d '' file; do
                    if is_purgeable "$file"; then
                        local fsize
                        fsize=$(stat -f%z "$file" 2>/dev/null || echo 0)
                        purgeable=$((purgeable + fsize))
                    fi
                done < <(find "$dir" -type f -print0 2>/dev/null)
            fi
        done
    fi
    log "Estimated recoverable: $(bytes_to_human "$purgeable")"
}

cmd_archive() {
    if [ -z "$ICLOUD_ROOT" ]; then
        err "iCloud Drive not detected. Set ZIROS_ICLOUD_ROOT manually."
        exit 1
    fi

    log "Archiving to iCloud: ${ICLOUD_ARCHIVE}"
    mkdir -p "${ICLOUD_ARCHIVE}/telemetry"
    mkdir -p "${ICLOUD_ARCHIVE}/proofs"
    mkdir -p "${ICLOUD_ARCHIVE}/traces"
    mkdir -p "${ICLOUD_ARCHIVE}/verifiers"
    mkdir -p "${ICLOUD_ARCHIVE}/reports"
    mkdir -p "${ICLOUD_ARCHIVE}/audits"

    local archived=0

    # Archive telemetry
    if [ -d "${ZKF_HOME}/telemetry" ]; then
        local count
        count=$(ls "${ZKF_HOME}/telemetry" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$count" -gt 0 ]; then
            log "  Archiving ${count} telemetry records..."
            if ! is_dry_run; then
                cp -a "${ZKF_HOME}/telemetry/"*.json "${ICLOUD_ARCHIVE}/telemetry/" 2>/dev/null || true
            fi
            archived=$((archived + count))
        fi
    fi

    # Archive from showcase directories
    if [ -d "$DESKTOP" ]; then
        for dir in "$DESKTOP"/ZirOS_* "$DESKTOP"/ziros-* /tmp/swarm_* /tmp/reentry_*; do
            if [ -d "$dir" ]; then
                local dirname
                dirname=$(basename "$dir")
                log "  Scanning ${dirname}..."

                while IFS= read -r -d '' file; do
                    if is_archivable "$file"; then
                        local basename_file
                        basename_file=$(basename "$file")
                        local dest_dir

                        case "$file" in
                            *.proof.json) dest_dir="${ICLOUD_ARCHIVE}/proofs/${dirname}" ;;
                            *.execution_trace.json|*.runtime_trace.json) dest_dir="${ICLOUD_ARCHIVE}/traces/${dirname}" ;;
                            *Verifier.sol) dest_dir="${ICLOUD_ARCHIVE}/verifiers/${dirname}" ;;
                            *.report.md) dest_dir="${ICLOUD_ARCHIVE}/reports/${dirname}" ;;
                            *.audit.json) dest_dir="${ICLOUD_ARCHIVE}/audits/${dirname}" ;;
                            *) dest_dir="${ICLOUD_ARCHIVE}/misc/${dirname}" ;;
                        esac

                        safe_move "$file" "${dest_dir}/${basename_file}"
                        archived=$((archived + 1))
                    fi
                done < <(find "$dir" -type f -print0 2>/dev/null)
            fi
        done
    fi

    log "  Archived ${archived} files to iCloud"

    # Evict from local after sync settles (macOS will handle this automatically
    # with "Optimize Mac Storage" enabled, or manually via brctl)
    if [ "$archived" -gt 0 ] && ! is_dry_run; then
        log "  Files will sync to iCloud and be eligible for local eviction"
        log "  Enable 'Optimize Mac Storage' in System Settings > Apple Account > iCloud"
    fi
}

cmd_purge() {
    log "Purging ephemeral artifacts..."
    local freed=0

    # Purge debug build cache (largest single target)
    if [ -d "${ZIROS_REPO}/target-local/debug" ]; then
        local debug_bytes
        debug_bytes=$(dir_size_bytes "${ZIROS_REPO}/target-local/debug")
        log "  Purging target-local/debug/ ($(bytes_to_human "$debug_bytes"))..."
        safe_rm "${ZIROS_REPO}/target-local/debug"
        freed=$((freed + debug_bytes))
    fi

    # Purge kani cache
    if [ -d "${ZIROS_REPO}/target-local/kani" ]; then
        local kani_bytes
        kani_bytes=$(dir_size_bytes "${ZIROS_REPO}/target-local/kani")
        log "  Purging target-local/kani/ ($(bytes_to_human "$kani_bytes"))..."
        safe_rm "${ZIROS_REPO}/target-local/kani"
        freed=$((freed + kani_bytes))
    fi

    # Purge purgeable files from showcase directories
    if [ -d "$DESKTOP" ]; then
        for dir in "$DESKTOP"/ZirOS_* "$DESKTOP"/ziros-* /tmp/swarm_* /tmp/reentry_*; do
            if [ -d "$dir" ]; then
                while IFS= read -r -d '' file; do
                    if is_purgeable "$file"; then
                        local fsize
                        fsize=$(stat -f%z "$file" 2>/dev/null || echo 0)
                        safe_rm "$file"
                        freed=$((freed + fsize))
                    fi
                done < <(find "$dir" -type f -print0 2>/dev/null)
            fi
        done
    fi

    log "  Freed: $(bytes_to_human "$freed")"
    log "  Free space: $(free_space_gb) GB"
}

cmd_sweep() {
    log "Full sweep: archive → purge"
    echo ""
    cmd_archive
    echo ""
    cmd_purge
    echo ""
    log "Sweep complete. Free space: $(free_space_gb) GB"
}

cmd_watch() {
    local interval="${1:-1800}"  # Default 30 minutes
    log "Watching storage (interval: ${interval}s, warn: ${WARN_GB}GB, crit: ${CRIT_GB}GB)"
    log "Press Ctrl+C to stop"
    echo ""

    while true; do
        local free_gb
        free_gb=$(free_space_gb)

        if [ "$free_gb" -lt "$CRIT_GB" ]; then
            warn "CRITICAL: Only ${free_gb} GB free — running emergency sweep"
            cmd_sweep
        elif [ "$free_gb" -lt "$WARN_GB" ]; then
            warn "Low storage: ${free_gb} GB free — running archive"
            cmd_archive
        else
            log "$(date '+%H:%M'): ${free_gb} GB free — healthy"
        fi

        sleep "$interval"
    done
}

cmd_restore() {
    local target="$1"
    if [ -z "$target" ]; then
        err "Usage: ssd-guardian.sh restore <path>"
        exit 1
    fi

    if [ -f "$target" ]; then
        log "Force-downloading from iCloud: ${target}"
        brctl download "$target" 2>/dev/null || {
            err "brctl download failed — file may not be in iCloud Drive"
            exit 1
        }
        log "  Downloaded successfully"
    else
        err "File not found: ${target}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "${1:-status}" in
    status)   cmd_status ;;
    archive)  cmd_archive ;;
    purge)    cmd_purge ;;
    sweep)    cmd_sweep ;;
    watch)    cmd_watch "${2:-1800}" ;;
    restore)  cmd_restore "${2:-}" ;;
    version)  echo "${SCRIPT_NAME} v${VERSION}" ;;
    help|-h|--help)
        echo "Usage: ${SCRIPT_NAME} {status|archive|purge|sweep|watch|restore|version}"
        echo ""
        echo "Commands:"
        echo "  status   Show storage health and breakdown"
        echo "  archive  Move proofs, traces, telemetry to iCloud"
        echo "  purge    Delete debug builds, witnesses, compiled programs"
        echo "  sweep    Full cycle: archive then purge"
        echo "  watch    Continuous monitor (auto-sweep when low)"
        echo "  restore  Force-download a file from iCloud"
        ;;
    *)
        err "Unknown command: $1"
        echo "Run '${SCRIPT_NAME} help' for usage"
        exit 1
        ;;
esac
