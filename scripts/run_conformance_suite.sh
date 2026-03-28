#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_BIN="${ZKF_CLI_BIN:-$ROOT_DIR/target-local/release/zkf-cli}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ ! -x "$CLI_BIN" ]]; then
    echo "missing CLI binary at $CLI_BIN" >&2
    echo "run ./zkf-build.sh --release -p zkf-cli first" >&2
    exit 1
fi

run_backend() {
    local backend="$1"
    local report="$WORK_DIR/$backend.conformance.json"
    "$CLI_BIN" conformance --backend "$backend" --json > "$report"
    jq -e '.tests_failed == 0' "$report" >/dev/null
}

run_backend "plonky3"
run_backend "halo2"
ZKF_ALLOW_DEV_DETERMINISTIC_GROTH16=1 run_backend "arkworks-groth16"

echo "conformance suite passed"
