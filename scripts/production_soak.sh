#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/zkf-cli"
PROOF=""
COMPILED=""
OUT_DIR=""
JSON_OUT=""
PARALLEL_JOBS="auto"
HOURS=12
CYCLES=20
ALLOW_LARGE_DIRECT=false

usage() {
    cat <<'EOF'
Usage:
  scripts/production_soak.sh --proof <stark-proof.json> --compiled <stark-compiled.json> [--out-dir <dir>] [--json-out <report.json>] [--bin <zkf-cli>] [--parallel-jobs <auto|n>] [--hours <n>] [--cycles <n>] [--allow-large-direct-materialization]

Runs an explicit strict cache prepare followed by:
  zkf runtime certify --mode soak
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
        --json-out)
            JSON_OUT="$2"
            shift 2
            ;;
        --bin)
            BIN="$2"
            shift 2
            ;;
        --parallel-jobs)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --hours)
            HOURS="$2"
            shift 2
            ;;
        --cycles)
            CYCLES="$2"
            shift 2
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
    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zkf-production-soak.XXXXXX")"
else
    mkdir -p "${OUT_DIR}"
fi
if [[ -z "${JSON_OUT}" ]]; then
    JSON_OUT="${OUT_DIR}/strict-certification.json"
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
    --mode soak \
    --proof "${PROOF}" \
    --compiled "${COMPILED}" \
    --out-dir "${OUT_DIR}" \
    --json-out "${JSON_OUT}" \
    --parallel-jobs "${PARALLEL_JOBS}" \
    --hours "${HOURS}" \
    --cycles "${CYCLES}"

echo "production soak report: ${JSON_OUT}"
