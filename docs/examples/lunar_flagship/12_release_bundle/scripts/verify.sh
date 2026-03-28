#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Verifying Proofs ==="
./01_source/target/release/ziros-lunar-flagship verify 06_proofs/hazard_proof.json 06_proofs/hazard_compiled.json
./01_source/target/release/ziros-lunar-flagship verify 06_proofs/descent_proof.json 06_proofs/descent_compiled.json
echo "Both proofs verified."
