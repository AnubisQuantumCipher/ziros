#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/zkf-cli"
PROOF=""
COMPILED=""
OUT_DIR=""
FRESH_PROOF=false
ALLOW_LARGE_DIRECT=false

usage() {
    cat <<'EOF'
Usage:
  scripts/production_gate.sh --proof <stark-proof.json> --compiled <stark-compiled.json> [--out-dir <dir>] [--bin <zkf-cli>] [--fresh-proof] [--allow-large-direct-materialization]

Runs an explicit strict cache prepare followed by:
  zkf runtime certify --mode gate

The certification report is written to:
  <out-dir>/strict-certification.json
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proof)
            PROOF="$2"
            shift 2
            ;;
        --compiled)
            COMPILED="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --bin)
            BIN="$2"
            shift 2
            ;;
        --fresh-proof)
            FRESH_PROOF=true
            shift 1
            ;;
        --allow-large-direct-materialization)
            ALLOW_LARGE_DIRECT=true
            shift 1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "${PROOF}" || -z "${COMPILED}" ]]; then
    usage >&2
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    echo "zkf-cli binary not found or not executable: ${BIN}" >&2
    exit 1
fi

if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zkf-production-gate.XXXXXX")"
else
    mkdir -p "${OUT_DIR}"
fi

if [[ "${FRESH_PROOF}" == "true" ]]; then
    echo "note: --fresh-proof is now handled internally by runtime certify"
fi

PREPARE_ARGS=(
    runtime prepare
    --proof "${PROOF}"
    --compiled "${COMPILED}"
    --trust strict
    --json
    --output "${OUT_DIR}/prepare-report.json"
)
if [[ "${ALLOW_LARGE_DIRECT}" == "true" ]]; then
    PREPARE_ARGS+=(--allow-large-direct-materialization)
fi

if [[ -f "${OUT_DIR}/prepare.json" || -f "${OUT_DIR}/prepare-report.json" ]]; then
    echo "reusing existing strict prepare report from ${OUT_DIR}"
else
    "${BIN}" "${PREPARE_ARGS[@]}"
fi

"${BIN}" runtime certify \
    --mode gate \
    --proof "${PROOF}" \
    --compiled "${COMPILED}" \
    --out-dir "${OUT_DIR}" \
    --json-out "${OUT_DIR}/strict-certification.json"

echo "production gate passed"
echo "artifacts: ${OUT_DIR}"
