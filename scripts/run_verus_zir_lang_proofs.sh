#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
exec "$repo_root/scripts/run_verus_workspace.sh" \
  zir-lang \
  zkf-lang/proofs/verus/zir_lang_invariants_verus.rs
