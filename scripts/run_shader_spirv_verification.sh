#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

env_file="$alias_root/.zkf-tools/spirv/spirv.env"
proof_root="$alias_root/zkf-metal/proofs/spirv"
shader_root="$alias_root/zkf-metal/src/shaders"

log() {
  printf '[shader-spirv] %s\n' "$*" >&2
}

require_binary() {
  local binary="$1"
  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "required binary '$binary' was not found in PATH" >&2
    exit 1
  fi
}

if [[ ! -x "$alias_root/.zkf-tools/spirv/bin/spirv-cross" ]] || [[ ! -x "$alias_root/.zkf-tools/spirv/bin/spirv-val" ]] || [[ ! -x "$alias_root/.zkf-tools/spirv/bin/llvm-spirv" ]]; then
  "$alias_root/scripts/bootstrap_spirv_toolchain.sh" >/dev/null
fi

if [[ ! -f "$env_file" ]]; then
  echo "missing SPIR-V environment file at $env_file" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$env_file"

require_binary xcrun
require_binary python3
require_binary spirv-as
require_binary spirv-cross
require_binary spirv-val
require_binary llvm-spirv

python3 "$alias_root/scripts/verify_gpu_proof_manifest.py"

llvm_bin_dir="$(dirname "${ZKF_SPIRV_LLVM_CONFIG}")"
clang_bin="$llvm_bin_dir/clang"
if [[ ! -x "$clang_bin" ]]; then
  clang_bin="$(command -v clang)"
fi
require_binary "$clang_bin"

tmp_dir="$(mktemp -d "$alias_root/.tmp-shader-spirv.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

extract_kernel_names() {
  python3 - "$@" <<'PY'
import pathlib
import re
import sys

names = []
for path_str in sys.argv[1:]:
    text = pathlib.Path(path_str).read_text()
    names.extend(re.findall(r'kernel\s+void\s+([A-Za-z0-9_]+)\s*\(', text))
print("\n".join(sorted(set(names))))
PY
}

combine_metal_sources() {
  local output_path="$1"
  local prepend_header="$2"
  shift 2
  python3 - "$output_path" "$prepend_header" "$@" <<'PY'
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
prepend_header = sys.argv[2] == "1"
sources = [pathlib.Path(p) for p in sys.argv[3:]]

parts = []
if prepend_header:
    parts.append("#include <metal_stdlib>\nusing namespace metal;\n\n")

for source in sources:
    text = source.read_text()
    if prepend_header:
        text = text.replace("#include <metal_stdlib>", "")
        text = text.replace("using namespace metal;", "")
    parts.append(text)
    parts.append("\n")

output.write_text("".join(parts))
PY
}

compile_mirror_spirv() {
  local source_path="$1"
  local bitcode_path="$2"
  local spirv_path="$3"

  "$clang_bin" \
    -cc1 \
    -triple spir64-unknown-unknown \
    -cl-std=CL2.0 \
    -finclude-default-header \
    -emit-llvm-bc \
    -O2 \
    -x cl \
    "$source_path" \
    -o "$bitcode_path"

  llvm-spirv -o "$spirv_path" "$bitcode_path"
  spirv-val "$spirv_path"
}

emit_compute_reflection_assembly() {
  local names_file="$1"
  local asm_out="$2"
  python3 - "$names_file" "$asm_out" <<'PY'
import pathlib
import sys

names = [line.strip() for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
out = pathlib.Path(sys.argv[2])

lines = [
    "; SPIR-V",
    "; Version: 1.0",
    "; Generator: 0",
    f"; Bound: {10 + len(names) * 4}",
    "; Schema: 0",
    "               OpCapability Shader",
    "               OpMemoryModel Logical GLSL450",
]

type_void = 1
type_fn = 2
next_id = 3
entry_ids = []

for name in names:
    entry_id = next_id
    next_id += 2
    label_id = next_id
    next_id += 1
    entry_ids.append((name, entry_id, label_id))
for name, entry_id, _ in entry_ids:
    lines.append(f'               OpEntryPoint GLCompute %{entry_id} "{name}"')
for _, entry_id, _ in entry_ids:
    lines.append(f"               OpExecutionMode %{entry_id} LocalSize 1 1 1")

lines.extend([
    f"       %{type_void} = OpTypeVoid",
    f"       %{type_fn} = OpTypeFunction %{type_void}",
])

for _, entry_id, label_id in entry_ids:
    lines.extend([
        f"       %{entry_id} = OpFunction %{type_void} None %{type_fn}",
        f"       %{label_id} = OpLabel",
        "               OpReturn",
        "               OpFunctionEnd",
    ])

out.write_text("\n".join(lines) + "\n")
PY
}

reflect_shader_spirv() {
  local asm_path="$1"
  local spirv_path="$2"
  local reflect_json="$3"
  spirv-as "$asm_path" -o "$spirv_path"
  spirv-val "$spirv_path"
  spirv-cross "$spirv_path" --reflect --output "$reflect_json"
}

extract_reflected_entrypoints() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
names = sorted({entry["name"] for entry in data.get("entryPoints", [])})
print("\n".join(names))
PY
}

assert_entrypoint_sets_match() {
  local label="$1"
  local expected_file="$2"
  local actual_file="$3"
  if ! cmp -s "$expected_file" "$actual_file"; then
    echo "entrypoint mismatch for $label" >&2
    diff -u "$expected_file" "$actual_file" || true
    exit 1
  fi
}

verify_family() {
  local label="$1"
  local prepend_header="$2"
  local mirror_kernel="$3"
  shift 3
  local metal_sources=("$@")

  local combined_metal="$tmp_dir/${label}.metal"
  local air_out="$tmp_dir/${label}.air"
  local mirror_expected="$tmp_dir/${label}.expected"
  local mirror_actual="$tmp_dir/${label}.actual"
  local bitcode_out="$tmp_dir/${label}.bc"
  local spirv_out="$tmp_dir/${label}.kernel.spv"
  local reflect_asm="$tmp_dir/${label}.reflect.spvasm"
  local reflect_spv="$tmp_dir/${label}.reflect.spv"
  local reflect_json="$tmp_dir/${label}.reflect.json"

  combine_metal_sources "$combined_metal" "$prepend_header" "${metal_sources[@]}"
  xcrun -sdk macosx metal -std=metal3.2 -O2 \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-const-variable \
    -c -o "$air_out" "$combined_metal"

  extract_kernel_names "${metal_sources[@]}" >"$mirror_expected"
  extract_kernel_names "$mirror_kernel" >"$mirror_actual"
  assert_entrypoint_sets_match "$label source/mirror" "$mirror_expected" "$mirror_actual"

  compile_mirror_spirv "$mirror_kernel" "$bitcode_out" "$spirv_out"
  emit_compute_reflection_assembly "$mirror_expected" "$reflect_asm"
  reflect_shader_spirv "$reflect_asm" "$reflect_spv" "$reflect_json"
  extract_reflected_entrypoints "$reflect_json" >"$mirror_actual"
  assert_entrypoint_sets_match "$label reflection" "$mirror_expected" "$mirror_actual"

  log "Validated $label family entrypoints via AIR compile + LLVM/SPIR-V translation + SPIR-V reflection"
}

verify_family \
  "ntt" \
  "1" \
  "$proof_root/kernels/ntt_family.cl" \
  "$shader_root/field_goldilocks.metal" \
  "$shader_root/field_babybear.metal" \
  "$shader_root/field_bn254_fr.metal" \
  "$shader_root/ntt_radix2.metal" \
  "$shader_root/ntt_bn254.metal" \
  "$shader_root/ntt_radix2_batch.metal"

verify_family \
  "poseidon2" \
  "1" \
  "$proof_root/kernels/poseidon2_family.cl" \
  "$shader_root/field_goldilocks.metal" \
  "$shader_root/field_babybear.metal" \
  "$shader_root/poseidon2.metal"

verify_family \
  "hash" \
  "1" \
  "$proof_root/kernels/hash_family.cl" \
  "$shader_root/sha256.metal" \
  "$shader_root/keccak256.metal"

verify_family \
  "msm-bn254" \
  "0" \
  "$proof_root/kernels/msm_bn254_family.cl" \
  "$shader_root/msm_bn254.metal" \
  "$shader_root/msm_reduce.metal"

verify_family \
  "msm-pallas" \
  "0" \
  "$proof_root/kernels/msm_curve_family.cl" \
  "$shader_root/msm_pallas.metal"

verify_family \
  "msm-vesta" \
  "0" \
  "$proof_root/kernels/msm_curve_family.cl" \
  "$shader_root/msm_vesta.metal"

log "GPUVerify intentionally skipped for this tranche; see zkf-metal/proofs/spirv/README.md"

cargo test -p zkf-metal --lib metal_ntt_randomized_batches_match_cpu
cargo test -p zkf-metal --lib poseidon2_randomized_batches_match_cpu
cargo test -p zkf-metal --lib randomized_hash_batches_match_cpu
cargo test -p zkf-metal --lib metal_pallas_msm_randomized_batches_match_cpu
cargo test -p zkf-metal --lib metal_vesta_msm_randomized_batches_match_cpu
