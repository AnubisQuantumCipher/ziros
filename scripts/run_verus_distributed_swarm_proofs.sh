#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

proofs=(
  "consensus zkf-distributed/proofs/verus/swarm_consensus_verus.rs"
  "diplomat zkf-distributed/proofs/verus/swarm_diplomat_verus.rs"
  "epoch zkf-distributed/proofs/verus/swarm_epoch_verus.rs"
  "identity zkf-distributed/proofs/verus/swarm_identity_verus.rs"
  "memory zkf-distributed/proofs/verus/swarm_memory_verus.rs"
  "reputation zkf-distributed/proofs/verus/swarm_reputation_verus.rs"
  "coordinator zkf-distributed/proofs/verus/distributed_coordinator_swarm_verus.rs"
  "transport zkf-distributed/proofs/verus/swarm_transport_verus.rs"
)

for proof in "${proofs[@]}"; do
  label="${proof%% *}"
  file="${proof#* }"
  "$repo_root/scripts/run_verus_workspace.sh" "$label" "$file"
done
