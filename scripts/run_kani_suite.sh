#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

gib_bytes=$((1024 * 1024 * 1024))
tmp_root="${TMPDIR:-/tmp}"
tmp_root="${tmp_root%/}"

log() {
  printf '[kani-suite] %s\n' "$*" >&2
}

die() {
  log "$*"
  exit 1
}

require_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    die "$name must be a non-negative integer, found '$value'"
  fi
}

format_gib() {
  local bytes="$1"
  awk -v bytes="$bytes" -v gib="$gib_bytes" 'BEGIN { printf "%.1f", bytes / gib }'
}

total_ram_bytes="$(sysctl -n hw.memsize)"
require_uint "hw.memsize" "$total_ram_bytes"
total_ram_gib=$(((total_ram_bytes + gib_bytes - 1) / gib_bytes))
default_min_available_gb=$(((total_ram_gib + 3) / 4))
if (( default_min_available_gb < 8 )); then
  default_min_available_gb=8
fi

ZKF_KANI_POLL_SECONDS="${ZKF_KANI_POLL_SECONDS:-5}"
ZKF_KANI_MAX_WAIT_SEC="${ZKF_KANI_MAX_WAIT_SEC:-0}"
ZKF_KANI_MIN_AVAILABLE_GB="${ZKF_KANI_MIN_AVAILABLE_GB:-$default_min_available_gb}"
ZKF_KANI_LOCK_FILE="${ZKF_KANI_LOCK_FILE:-$tmp_root/zkf-kani-global.lock}"
ZKF_KANI_MODE="${ZKF_KANI_MODE:-current}"
ZKF_KANI_BASELINE_SCOPE="${ZKF_KANI_BASELINE_SCOPE:-full}"
ZKF_RUN_MONTGOMERY_ASSURANCE="${ZKF_RUN_MONTGOMERY_ASSURANCE:-1}"

require_uint "ZKF_KANI_POLL_SECONDS" "$ZKF_KANI_POLL_SECONDS"
require_uint "ZKF_KANI_MAX_WAIT_SEC" "$ZKF_KANI_MAX_WAIT_SEC"
require_uint "ZKF_KANI_MIN_AVAILABLE_GB" "$ZKF_KANI_MIN_AVAILABLE_GB"

case "$ZKF_KANI_MODE" in
  current|baseline|targeted|app|hybrid|distributed|residual|satellite|all)
    ;;
  *)
    die "ZKF_KANI_MODE must be one of current, baseline, targeted, app, hybrid, distributed, residual, satellite, or all"
    ;;
esac

case "$ZKF_KANI_BASELINE_SCOPE" in
  full|phase1-closure)
    ;;
  *)
    die "ZKF_KANI_BASELINE_SCOPE must be one of full or phase1-closure"
    ;;
esac

if (( ZKF_KANI_POLL_SECONDS < 1 )); then
  die "ZKF_KANI_POLL_SECONDS must be at least 1"
fi

min_available_bytes=$((ZKF_KANI_MIN_AVAILABLE_GB * gib_bytes))

available_memory_bytes() {
  local vm_output page_size free_pages inactive_pages speculative_pages
  vm_output="$(vm_stat)"
  page_size="$(printf '%s\n' "$vm_output" | sed -nE '1 s/.*page size of ([0-9]+) bytes.*/\1/p')"
  free_pages="$(printf '%s\n' "$vm_output" | sed -nE 's/^Pages free:[[:space:]]*([0-9.]+).*/\1/p' | tr -d '.')"
  inactive_pages="$(printf '%s\n' "$vm_output" | sed -nE 's/^Pages inactive:[[:space:]]*([0-9.]+).*/\1/p' | tr -d '.')"
  speculative_pages="$(printf '%s\n' "$vm_output" | sed -nE 's/^Pages speculative:[[:space:]]*([0-9.]+).*/\1/p' | tr -d '.')"

  require_uint "vm_stat page size" "$page_size"
  require_uint "vm_stat free pages" "$free_pages"
  require_uint "vm_stat inactive pages" "$inactive_pages"
  require_uint "vm_stat speculative pages" "$speculative_pages"

  printf '%s\n' $((page_size * (free_pages + inactive_pages + speculative_pages)))
}

enforce_wait_budget() {
  local wait_started_at="$1"
  local waiting_for="$2"
  local elapsed=$((SECONDS - wait_started_at))

  if (( ZKF_KANI_MAX_WAIT_SEC > 0 && elapsed >= ZKF_KANI_MAX_WAIT_SEC )); then
    log "Timed out after ${elapsed}s while waiting for ${waiting_for}"
    exit 124
  fi
}

sleep_for_wait_interval() {
  local wait_started_at="$1"
  local remaining="$ZKF_KANI_POLL_SECONDS"

  if (( ZKF_KANI_MAX_WAIT_SEC > 0 )); then
    local elapsed=$((SECONDS - wait_started_at))
    local budget_left=$((ZKF_KANI_MAX_WAIT_SEC - elapsed))
    if (( budget_left <= 0 )); then
      return 0
    fi
    if (( remaining > budget_left )); then
      remaining="$budget_left"
    fi
  fi

  sleep "$remaining"
}

wait_for_memory_headroom() {
  local label="$1"
  local wait_started_at="$SECONDS"

  while true; do
    local available_bytes
    available_bytes="$(available_memory_bytes)"
    if (( available_bytes >= min_available_bytes )); then
      return 0
    fi

    log "Waiting for memory headroom before ${label}: available $(format_gib "$available_bytes") GiB, need at least ${ZKF_KANI_MIN_AVAILABLE_GB} GiB"
    enforce_wait_budget "$wait_started_at" "memory headroom"
    sleep_for_wait_interval "$wait_started_at"
  done
}

acquire_suite_lock() {
  local wait_started_at="$SECONDS"

  while true; do
    local rc=0
    if /usr/bin/lockf -t 0 "$ZKF_KANI_LOCK_FILE" \
      env \
        ZKF_KANI_LOCK_HELD=1 \
        ZKF_KANI_LOCK_FILE="$ZKF_KANI_LOCK_FILE" \
        ZKF_KANI_POLL_SECONDS="$ZKF_KANI_POLL_SECONDS" \
        ZKF_KANI_MAX_WAIT_SEC="$ZKF_KANI_MAX_WAIT_SEC" \
        ZKF_KANI_MIN_AVAILABLE_GB="$ZKF_KANI_MIN_AVAILABLE_GB" \
        ZKF_KANI_MODE="$ZKF_KANI_MODE" \
        ZKF_KANI_BASELINE_SCOPE="$ZKF_KANI_BASELINE_SCOPE" \
        ZKF_KANI_INCLUDE_RESIDUAL="${ZKF_KANI_INCLUDE_RESIDUAL:-0}" \
      bash "$0" 2>/dev/null; then
      rc=0
    else
      rc=$?
    fi

    if (( rc == 0 )); then
      exit 0
    fi
    if (( rc != 75 )); then
      exit "$rc"
    fi

    log "Another Kani suite is already running; waiting for global lock at ${ZKF_KANI_LOCK_FILE}"
    enforce_wait_budget "$wait_started_at" "global Kani lock"
    sleep_for_wait_interval "$wait_started_at"
  done
}

if [[ "${ZKF_KANI_LOCK_HELD:-0}" != "1" ]]; then
  acquire_suite_lock
fi

if ! cargo kani --version >/dev/null 2>&1; then
  echo "cargo-kani is required. Install it first, then run cargo kani setup." >&2
  exit 1
fi

run_kani() {
  local crate="$1"
  shift
  local cargo_flags=()
  local kani_flags=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-default-features|--all-features)
        cargo_flags+=("$1")
        shift
        ;;
      --features)
        cargo_flags+=("$1" "$2")
        shift 2
        ;;
      --ignore-global-asm)
        kani_flags+=("-Z" "unstable-options" "--ignore-global-asm")
        shift
        ;;
      *)
        break
        ;;
    esac
  done

  local harness
  for harness in "$@"; do
    local label="${crate}::${harness}"
    wait_for_memory_headroom "$label"
    log "Running ${label} with $(format_gib "$(available_memory_bytes)") GiB available"

    local cmd=(cargo kani -j 1)
    if [[ ${#kani_flags[@]} -gt 0 ]]; then
      cmd+=("${kani_flags[@]}")
    fi
    cmd+=(-p "$crate")
    if [[ ${#cargo_flags[@]} -gt 0 ]]; then
      cmd+=("${cargo_flags[@]}")
    fi
    cmd+=(--lib --exact --harness "$harness")
    "${cmd[@]}"
  done
}

run_montgomery_assurance() {
  if [[ "$ZKF_RUN_MONTGOMERY_ASSURANCE" != "1" ]]; then
    return
  fi

  log "Running Montgomery regression backstops before baseline Kani harnesses"
  bash ./scripts/run_montgomery_assurance.sh
}

run_baseline_full() {
  run_kani zkf-core --no-default-features \
    verification_kani::field_element_le_bytes_roundtrip_for_small_values

  run_kani zkf-runtime --no-default-features --features kani-minimal \
    verification_kani::typed_views_reject_misaligned_lengths_and_preserve_u64_words \
    verification_kani::spill_and_reload_preserves_small_cpu_buffers \
    verification_kani::buffer_read_write_guards_and_mutable_typed_views_roundtrip \
    verification_kani::buffer_residency_transitions_reject_stale_reads_after_eviction \
    verification_kani::distinct_slots_preserve_alias_separation_under_mutation_and_free

  run_kani zkf-backends --ignore-global-asm \
    verification_kani::cached_shape_debug_gate_stays_off_without_matrices \
    verification_kani::matrix_free_satisfaction_check_is_rejected \
    verification_kani::groth16_materialized_matrices_match_streaming_rows_in_setup_mode \
    verification_kani::groth16_materialized_matrices_match_streaming_rows_in_prove_mode \
    verification_kani::halo2_ipa_binding_accepts_complete_small_batches \
    verification_kani::halo2_ipa_binding_rejects_missing_hashes_points_or_malformed_entries
}

run_baseline_phase1_closure() {
  run_kani zkf-core --no-default-features \
    verification_kani::field_element_le_bytes_roundtrip_for_small_values

  run_kani zkf-runtime --no-default-features --features kani-minimal \
    verification_kani::typed_views_reject_misaligned_lengths_and_preserve_u64_words \
    verification_kani::spill_and_reload_preserves_small_cpu_buffers \
    verification_kani::buffer_read_write_guards_and_mutable_typed_views_roundtrip \
    verification_kani::buffer_residency_transitions_reject_stale_reads_after_eviction \
    verification_kani::distinct_slots_preserve_alias_separation_under_mutation_and_free

  run_kani zkf-backends --ignore-global-asm \
    verification_kani::halo2_ipa_binding_accepts_complete_small_batches \
    verification_kani::halo2_ipa_binding_rejects_missing_hashes_points_or_malformed_entries
}

run_baseline() {
  run_montgomery_assurance
  case "$ZKF_KANI_BASELINE_SCOPE" in
    full)
      run_baseline_full
      ;;
    phase1-closure)
      run_baseline_phase1_closure
      ;;
  esac
}

run_targeted_app() {
  run_kani zkf-lib --ignore-global-asm \
    verification_kani::app_alias_resolution_maps_external_key_to_canonical_signal \
    verification_kani::app_digest_mismatch_is_rejected_before_proving \
    verification_kani::app_digest_mismatch_preserves_expected_and_found_digests \
    verification_kani::default_backend_mapping_is_valid_for_all_fields \
    verification_kani::satellite_burn_selector_is_unique_and_exact \
    verification_kani::satellite_running_min_reduction_is_correct \
    verification_kani::satellite_threshold_checks_fail_closed_when_separation_is_too_small \
    verification_kani::satellite_budget_checks_fail_closed_when_delta_v_is_too_large \
    verification_kani::satellite_commitment_binding_detects_state_and_plan_tampering
}

run_satellite() {
  run_kani zkf-lib --ignore-global-asm \
    verification_kani::satellite_burn_selector_is_unique_and_exact \
    verification_kani::satellite_running_min_reduction_is_correct \
    verification_kani::satellite_threshold_checks_fail_closed_when_separation_is_too_small \
    verification_kani::satellite_budget_checks_fail_closed_when_delta_v_is_too_large \
    verification_kani::satellite_commitment_binding_detects_state_and_plan_tampering
}

run_targeted_hybrid() {
  run_kani zkf-runtime --ignore-global-asm --features kani-minimal,full \
    verification_kani::hybrid_verify_requires_both_legs \
    verification_kani::hybrid_transcript_hash_binding_detects_public_input_mismatch \
    verification_kani::hybrid_hardware_probe_policy_rejects_any_mismatch \
    verification_kani::hybrid_primary_leg_binding_rejects_outer_artifact_tampering \
    verification_kani::hybrid_replay_manifest_identity_is_deterministic
}

run_targeted_distributed() {
  run_kani zkf-distributed --ignore-global-asm \
    verification_kani::distributed_attestation_digest_mismatch_is_rejected \
    verification_kani::distributed_requires_quorum_for_low_reputation_anomaly_or_low_trust \
    verification_kani::distributed_two_party_quorum_rejects_mismatched_remote_digest \
    verification_kani::distributed_signed_message_bundle_surface_rejects_partial_hybrid_metadata \
    verification_kani::hybrid_bundle_material_gate_requires_both_signature_systems \
    verification_kani::hybrid_admission_pow_identity_bytes_prefer_hybrid_bundle_encoding
}

run_residual() {
  run_kani zkf-core --features kani-residual,full \
    verification_kani::constant_time_eval_matches_standard_eval

  run_kani zkf-runtime --ignore-global-asm --features kani-minimal,full \
    verification_kani::controller_delegates_to_pure_artifact_path \
    verification_kani::swarm_controller_has_no_artifact_mutation_surface \
    verification_kani::jitter_z_score_bounded

  run_kani zkf-distributed --ignore-global-asm \
    verification_kani::distributed_queen_consensus_cannot_be_suppressed_by_single_node \
    verification_kani::sybil_peers_cannot_reach_quorum_threshold_within_cap \
    verification_kani::admission_pow_cost_scales_linearly
}

run_targeted() {
  run_targeted_app
  run_targeted_hybrid
  run_targeted_distributed
}

case "$ZKF_KANI_MODE" in
  current)
    run_baseline
    run_targeted
    if [[ "${ZKF_KANI_INCLUDE_RESIDUAL:-0}" == "1" ]]; then
      run_residual
      log "Configured baseline, targeted current-phase, and residual Kani harnesses completed."
    else
      log "Configured baseline and targeted current-phase Kani harnesses completed. Residual heavyweight Kani checks remain opt-in via ZKF_KANI_MODE=residual or ZKF_KANI_INCLUDE_RESIDUAL=1."
    fi
    ;;
  baseline)
    run_baseline
    log "Configured baseline Kani harnesses completed."
    ;;
  targeted)
    run_targeted
    log "Configured targeted current-phase Kani harnesses completed."
    ;;
  app)
    run_targeted_app
    log "Configured targeted embedded-app Kani harnesses completed."
    ;;
  satellite)
    run_satellite
    log "Configured targeted satellite Kani harnesses completed."
    ;;
  hybrid)
    run_targeted_hybrid
    log "Configured targeted hybrid-runtime Kani harnesses completed."
    ;;
  distributed)
    run_targeted_distributed
    log "Configured targeted distributed-identity Kani harnesses completed."
    ;;
  residual)
    run_residual
    log "Configured residual heavyweight Kani harnesses completed."
    ;;
  all)
    run_baseline
    run_targeted
    run_residual
    log "Configured baseline, targeted current-phase, and residual Kani harnesses completed."
    ;;
esac
