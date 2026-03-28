#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
cd "$repo_root"

python3 "$repo_root/scripts/verify_gpu_proof_manifest.py"
python3 "$repo_root/scripts/verify_gpu_bundle_attestation.py"
bash "$repo_root/scripts/run_lean_proofs.sh"
bash "$repo_root/scripts/run_rocq_proofs.sh"
bash "$repo_root/scripts/run_fstar_proofs.sh"
bash "$repo_root/scripts/run_verus_gpu_checks.sh"
bash "$repo_root/scripts/run_kani_gpu_checks.sh"
