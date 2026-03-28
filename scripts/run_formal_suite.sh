#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

FORMAL_KANI_BASELINE_SCOPE="${FORMAL_KANI_BASELINE_SCOPE:-phase1-closure}"
FORMAL_KANI_INCLUDE_RESIDUAL="${FORMAL_KANI_INCLUDE_RESIDUAL:-0}"
FORMAL_KANI_MIN_AVAILABLE_GB="${FORMAL_KANI_MIN_AVAILABLE_GB:-8}"
FORMAL_AUDIT_MODE="${FORMAL_AUDIT_MODE:-standard}"

log() {
  printf '[formal-suite] %s\n' "$*" >&2
}

run_step() {
  local label="$1"
  shift
  log "Running ${label}"
  "$@"
}

run_step "Fiat-Crypto freshness check" bash ./scripts/regenerate_fiat_fields.sh --check
run_step "Montgomery regression backstops" bash ./scripts/run_montgomery_assurance.sh
run_step "Lean proofs" ./scripts/run_lean_proofs.sh
run_step "Rocq proofs" ./scripts/run_rocq_proofs.sh
run_step "F* proofs" ./scripts/run_fstar_proofs.sh
proof_audit_cmd=(python3 ./scripts/proof_audit.py)
if [[ "$FORMAL_AUDIT_MODE" == "release-grade" ]]; then
  proof_audit_cmd+=(--release-grade)
fi
run_step "proof audit" "${proof_audit_cmd[@]}"
run_step "Protocol Lean proofs" ./scripts/run_protocol_lean_proofs.sh
run_step \
  "default Kani tranche" \
  env \
    ZKF_KANI_BASELINE_SCOPE="$FORMAL_KANI_BASELINE_SCOPE" \
    ZKF_KANI_MIN_AVAILABLE_GB="$FORMAL_KANI_MIN_AVAILABLE_GB" \
    ZKF_RUN_MONTGOMERY_ASSURANCE=0 \
    bash ./scripts/run_kani_suite.sh

if [[ "$FORMAL_KANI_INCLUDE_RESIDUAL" == "1" ]]; then
  run_step \
    "residual Kani tranche" \
    env \
      ZKF_KANI_BASELINE_SCOPE="$FORMAL_KANI_BASELINE_SCOPE" \
      ZKF_KANI_MIN_AVAILABLE_GB="$FORMAL_KANI_MIN_AVAILABLE_GB" \
      ZKF_KANI_INCLUDE_RESIDUAL=1 \
      ZKF_RUN_MONTGOMERY_ASSURANCE=0 \
      bash ./scripts/run_kani_suite.sh
fi

run_step "Verus buffer proofs" bash ./scripts/run_verus_buffer_proofs.sh
run_step "Verus orbital proofs" bash ./scripts/run_verus_orbital_proofs.sh
run_step "shader SPIR-V verification" bash ./scripts/run_shader_spirv_verification.sh
