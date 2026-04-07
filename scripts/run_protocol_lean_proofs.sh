#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${ROOT}/zkf-protocol-proofs"
LOG_DIR="${ROOT}/target-local/protocol-lean"
LOG_FILE="${LOG_DIR}/protocol_lean.log"

mkdir -p "${LOG_DIR}"

for required in \
  "${PKG_DIR}/lean-toolchain" \
  "${PKG_DIR}/lakefile.toml" \
  "${PKG_DIR}/ZkfProtocolProofs.lean" \
  "${PKG_DIR}/ZkfProtocolProofs/Groth16Exact.lean" \
  "${PKG_DIR}/ZkfProtocolProofs/FriExact.lean" \
  "${PKG_DIR}/ZkfProtocolProofs/NovaExact.lean" \
  "${PKG_DIR}/ZkfProtocolProofs/HyperNovaExact.lean"
do
  if [[ ! -f "${required}" ]]; then
    echo "missing protocol Lean artifact: ${required}" | tee "${LOG_FILE}"
    exit 1
  fi
done

{
  echo "[protocol-lean] root=${ROOT}"
  echo "[protocol-lean] package=${PKG_DIR}"
  echo "[protocol-lean] toolchain=$(cat "${PKG_DIR}/lean-toolchain")"
  cd "${PKG_DIR}"
  lake --version
  lake build
} 2>&1 | tee "${LOG_FILE}"
