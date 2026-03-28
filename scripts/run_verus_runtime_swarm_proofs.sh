#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

proofs=(
  "artifact zkf-runtime/proofs/verus/swarm_artifact_verus.rs"
  "entrypoint zkf-runtime/proofs/verus/swarm_entrypoint_verus.rs"
  "builder zkf-runtime/proofs/verus/swarm_builder_verus.rs"
  "queen zkf-runtime/proofs/verus/swarm_queen_verus.rs"
  "sentinel zkf-runtime/proofs/verus/swarm_sentinel_verus.rs"
  "warrior zkf-runtime/proofs/verus/swarm_warrior_verus.rs"
)

for proof in "${proofs[@]}"; do
  label="${proof%% *}"
  file="${proof#* }"
  "$repo_root/scripts/run_verus_workspace.sh" "$label" "$file"
done
