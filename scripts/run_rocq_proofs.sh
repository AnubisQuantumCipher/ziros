#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

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

  printf '[rocq] %s\n' "$repo_root/$proof_file" >&2
  (
    cd "$repo_root"
    coqc -q -R "$extraction_root" "$namespace" "$proof_file"
  )
done
