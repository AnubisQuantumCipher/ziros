#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Exporting Solidity Verifiers ==="
./01_source/target/release/ziros-lunar-flagship export 06_proofs/hazard_proof.json 07_verifiers/hazard HazardAssessmentVerifier
./01_source/target/release/ziros-lunar-flagship export 06_proofs/descent_proof.json 07_verifiers/descent PoweredDescentVerifier
echo "Export complete."
