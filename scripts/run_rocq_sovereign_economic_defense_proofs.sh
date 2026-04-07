#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

printf '[rocq:sovereign-economic-defense] %s\n' \
  "$repo_root/zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v" >&2

cd "$repo_root"
coqc -q -R zkf-lib/proofs/rocq/extraction ZkfLibExtraction \
  zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v
