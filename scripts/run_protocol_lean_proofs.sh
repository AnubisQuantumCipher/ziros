#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lean_toolchain.sh"

python3 "$ROOT/scripts/generate_protocol_parameter_snapshots.py"
cargo test --manifest-path "$ROOT/Cargo.toml" -p zkf-ir-spec --test protocol_parameter_snapshots
cd "$ROOT/zkf-protocol-proofs"
run_lake build ZkfProtocolProofs
cd "$ROOT"
python3 "$ROOT/scripts/check_protocol_proof_closure.py"
