#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
hax_core_root_default="$HOME/Projects/ZK DEV/.zkf-tools/hax/src/hax/hax-lib/proof-libs/coq/coq/generated-core"
hax_core_root="${HAX_COQ_CORE_ROOT:-$hax_core_root_default}"
recordupdate_root_default="$repo_root/zkf-core/proofs/rocq/vendor/RecordUpdate"
recordupdate_root="${HAX_COQ_RECORDUPDATE_ROOT:-$recordupdate_root_default}"

if [[ $# -eq 0 ]]; then
  set -- zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v
fi

for proof_file in "$@"; do
  case "$proof_file" in
    zkf-core/proofs/rocq/*)
      extraction_root="zkf-core/proofs/rocq/extraction"
      namespace="ZkfCoreExtraction"
      ;;
    zkf-backends/proofs/rocq/*)
      extraction_root="zkf-backends/proofs/rocq/extraction"
      namespace="ZkfBackendsExtraction"
      ;;
    zkf-frontends/proofs/rocq/*)
      extraction_root="zkf-frontends/proofs/rocq/extraction"
      namespace="ZkfFrontendsExtraction"
      ;;
    zkf-lang/proofs/rocq/*)
      extraction_root="zkf-lang/proofs/rocq/extraction"
      namespace="ZkfLangExtraction"
      ;;
    zkf-runtime/proofs/rocq/*)
      extraction_root="zkf-runtime/proofs/rocq/extraction"
      namespace="ZkfRuntimeExtraction"
      ;;
    zkf-distributed/proofs/rocq/*)
      extraction_root="zkf-distributed/proofs/rocq/extraction"
      namespace="ZkfDistributedExtraction"
      ;;
    zkf-lib/proofs/rocq/*)
      extraction_root="zkf-lib/proofs/rocq/extraction"
      namespace="ZkfLibExtraction"
      ;;
    *)
      echo "unsupported Rocq proof path: $proof_file" >&2
      exit 1
      ;;
  esac

  if [[ ! -f "$repo_root/$proof_file" ]]; then
    echo "missing Rocq proof file at $repo_root/$proof_file" >&2
    exit 1
  fi

  proof_dir="$(dirname "$proof_file")"
  proof_name="$(basename "$proof_file")"
  extraction_dir_rel="extraction"
  coq_args=(-q -R "$extraction_dir_rel" "$namespace")
  if [[ -d "$hax_core_root/src" && -d "$hax_core_root/spec" && -d "$hax_core_root/phase_library" ]]; then
    coq_args+=(
      -R "$hax_core_root/src" Core
      -R "$hax_core_root/spec" Core
      -R "$hax_core_root/phase_library" Core
    )
  fi
  if [[ -d "$recordupdate_root" ]]; then
    coq_args+=(-Q "$recordupdate_root" RecordUpdate)
  fi

  printf '[rocq] %s\n' "$repo_root/$proof_file" >&2
  (
    cd "$repo_root/$proof_dir"
    coqc "${coq_args[@]}" "$proof_name"
  )
done
