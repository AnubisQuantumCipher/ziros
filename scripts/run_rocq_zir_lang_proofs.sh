#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
exec "$repo_root/scripts/run_rocq_proofs.sh" \
  zkf-lang/proofs/rocq/ZirLangSemantics.v \
  zkf-lang/proofs/rocq/ZirLangLoweringProofs.v \
  zkf-lang/proofs/rocq/ZirLangPrivacyProofs.v
