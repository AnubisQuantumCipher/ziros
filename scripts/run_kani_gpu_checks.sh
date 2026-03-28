#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
cd "$repo_root"

if ! cargo kani --version >/dev/null 2>&1; then
  echo "cargo-kani is required. Install it first, then run cargo kani setup." >&2
  exit 1
fi

harnesses=(
  verification_kani::hash_contract_rejects_zero_input_len
  verification_kani::hash_contract_rejects_short_output_buffer
  verification_kani::hash_contract_accepts_valid_shape
  verification_kani::poseidon2_contract_rejects_misaligned_state_width
  verification_kani::poseidon2_contract_rejects_bad_zero_copy_request
  verification_kani::poseidon2_contract_accepts_valid_shape
  verification_kani::ntt_contract_rejects_non_power_of_two_height
  verification_kani::ntt_contract_rejects_short_twiddle_region
  verification_kani::ntt_contract_accepts_valid_shape
  verification_kani::msm_contract_rejects_short_bucket_map
  verification_kani::msm_contract_accepts_certified_bn254_classic_shape
  verification_kani::bn254_strict_window_schedule_excludes_uncertified_c16
  verification_kani::msm_contract_rejects_invalid_naf_bucket_shape
  verification_kani::certified_bn254_surface_excludes_hybrid_and_full_gpu_routes
)

for harness in "${harnesses[@]}"; do
  cargo kani -j 1 -p zkf-metal --lib --exact --harness "$harness"
done
