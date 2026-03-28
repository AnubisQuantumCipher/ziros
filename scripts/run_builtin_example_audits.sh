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

run_case() {
    local field="$1"
    local backend="$2"
    local label="$3"
    local program="$WORK_DIR/$label.json"
    local report="$WORK_DIR/$label.audit.json"

    "$CLI_BIN" emit-example --field "$field" --out "$program" >/dev/null
    "$CLI_BIN" audit --program "$program" --backend "$backend" --json > "$report"
    jq -e '.summary.failed == 0' "$report" >/dev/null
}

run_case "bn254" "nova" "example-bn254-nova"
run_case "pasta-fp" "halo2" "example-pasta-halo2"
run_case "goldilocks" "plonky3" "example-goldilocks-plonky3"

EPA_REPORT="$WORK_DIR/epa.audit.json"
"$CLI_BIN" audit \
    --program "$ROOT_DIR/docs/examples/fixtures/epa/zirapp.json" \
    --backend "nova" \
    --json > "$EPA_REPORT"
jq -e '.summary.failed == 0' "$EPA_REPORT" >/dev/null

echo "built-in audits passed"
