#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

proofs=(
  "graph zkf-runtime/proofs/verus/runtime_execution_graph_verus.rs"
  "context zkf-runtime/proofs/verus/runtime_execution_context_verus.rs"
  "scheduler zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
  "api zkf-runtime/proofs/verus/runtime_execution_api_verus.rs"
  "adapter zkf-runtime/proofs/verus/runtime_execution_adapter_verus.rs"
  "hybrid zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
)

for proof in "${proofs[@]}"; do
  label="${proof%% *}"
  file="${proof#* }"
  "$repo_root/scripts/run_verus_workspace.sh" "$label" "$file"
done
