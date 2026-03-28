#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
ir_proof_root="$repo_root/zkf-ir-spec"
gpu_proof_root="$repo_root/zkf-metal/proofs/lean"
source "$repo_root/scripts/lean_toolchain.sh"

compile_lean_module() {
  local src="$1"
  local out="$2"
  run_lean -o "$out" "$src"
}

python3 "$repo_root/scripts/verify_gpu_proof_manifest.py"

cd "$ir_proof_root"
run_lean proofs/lean/Normalization.lean

export LEAN_PATH="$gpu_proof_root:${LEAN_PATH:-}"
cd "$repo_root"
compile_lean_module "$gpu_proof_root/Generated/GpuPrograms.lean" "$gpu_proof_root/Generated/GpuPrograms.olean"
compile_lean_module "$gpu_proof_root/SemanticsAst.lean" "$gpu_proof_root/SemanticsAst.olean"
compile_lean_module "$gpu_proof_root/TraceModel.lean" "$gpu_proof_root/TraceModel.olean"
compile_lean_module "$gpu_proof_root/MemoryModel.lean" "$gpu_proof_root/MemoryModel.olean"
compile_lean_module "$gpu_proof_root/FamilySpecs.lean" "$gpu_proof_root/FamilySpecs.olean"
compile_lean_module "$gpu_proof_root/KernelSemantics.lean" "$gpu_proof_root/KernelSemantics.olean"
compile_lean_module "$gpu_proof_root/LaunchSafety.lean" "$gpu_proof_root/LaunchSafety.olean"
compile_lean_module "$gpu_proof_root/CodegenSoundness.lean" "$gpu_proof_root/CodegenSoundness.olean"
compile_lean_module "$gpu_proof_root/HashReference.lean" "$gpu_proof_root/HashReference.olean"
compile_lean_module "$gpu_proof_root/Poseidon2Reference.lean" "$gpu_proof_root/Poseidon2Reference.olean"
compile_lean_module "$gpu_proof_root/NttReference.lean" "$gpu_proof_root/NttReference.olean"
compile_lean_module "$gpu_proof_root/Bn254Montgomery.lean" "$gpu_proof_root/Bn254Montgomery.olean"
compile_lean_module "$gpu_proof_root/Bn254NttArithmetic.lean" "$gpu_proof_root/Bn254NttArithmetic.olean"
compile_lean_module "$gpu_proof_root/MsmReference.lean" "$gpu_proof_root/MsmReference.olean"
compile_lean_module "$gpu_proof_root/Hash.lean" "$gpu_proof_root/Hash.olean"
compile_lean_module "$gpu_proof_root/Poseidon2.lean" "$gpu_proof_root/Poseidon2.olean"
compile_lean_module "$gpu_proof_root/Ntt.lean" "$gpu_proof_root/Ntt.olean"
compile_lean_module "$gpu_proof_root/Msm.lean" "$gpu_proof_root/Msm.olean"
