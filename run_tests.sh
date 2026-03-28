#!/bin/bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_binary() {
    echo "Building zkf-cli..."
    (cd "$ROOT" && cargo build -p zkf-cli) >&2
}

find_preferred_binary() {
    local candidate
    if [[ -n "${ZKF_CLI_BIN:-}" && -x "${ZKF_CLI_BIN}" ]]; then
        echo "${ZKF_CLI_BIN}"
        return 0
    fi
    for candidate in \
        "$ROOT/bin/zkf-cli" \
        "$ROOT/target/debug/zkf-cli"
    do
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

find_release_fallback() {
    local candidate="$ROOT/target/release/zkf-cli"
    if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
    fi
    return 1
}

if ! ZKF="$(find_preferred_binary)"; then
    build_binary || exit 1
    ZKF="$(find_preferred_binary || find_release_fallback)" || {
        echo "error: could not find zkf-cli in bin/, target/debug/, or target/release/ after build" >&2
        exit 1
    }
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zkf-test-suite.XXXXXX")"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$TMP_DIR" || exit 1

PROGRAM_BACKEND="arkworks-groth16"
echo "Using zkf binary: $ZKF"
echo "Working directory: $TMP_DIR"
echo "Starting CLI smoke suite"

run_cmd() {
    local cmd_name="$1"
    shift
    echo
    echo "Testing: $cmd_name"
    "$ZKF" "$@" >"${cmd_name}.log" 2>&1
    local status=$?
    if [[ "$status" -eq 0 ]]; then
        echo "PASS: $cmd_name"
        return 0
    fi
    echo "FAIL: $cmd_name (exit code $status)"
    echo "---- ${cmd_name}.log ----"
    cat "${cmd_name}.log"
    return "$status"
}

if ! run_cmd "emit-example" emit-example --out test.ir.json; then exit 1; fi
printf '{"x":"3","y":"4"}\n' > inputs.json
cat > vectors.json <<'JSON'
[
  {
    "name": "main",
    "inputs": {
      "x": "3",
      "y": "4"
    },
    "expect_pass": true
  }
]
JSON

if ! run_cmd "optimize" optimize --program test.ir.json --out opt.ir.json --json; then exit 1; fi
if ! run_cmd "compile" compile --program opt.ir.json --backend "$PROGRAM_BACKEND" --out comp.json; then exit 1; fi
if ! run_cmd "witness" witness --program opt.ir.json --inputs inputs.json --out wit.json; then exit 1; fi
if ! run_cmd "prove" prove --program opt.ir.json --inputs inputs.json --backend "$PROGRAM_BACKEND" --out proof.json; then exit 1; fi
if ! run_cmd "verify" verify --program opt.ir.json --artifact proof.json --backend "$PROGRAM_BACKEND"; then exit 1; fi
if ! run_cmd "explore" explore --proof proof.json --backend "$PROGRAM_BACKEND" --json; then exit 1; fi
if ! run_cmd "debug" debug --program opt.ir.json --inputs inputs.json --out debug.json; then exit 1; fi
if ! run_cmd "estimate-gas" estimate-gas --artifact proof.json --backend "$PROGRAM_BACKEND" --json; then exit 1; fi
if ! run_cmd "deploy" deploy --artifact proof.json --backend "$PROGRAM_BACKEND" --out verifier.sol --json; then exit 1; fi
if ! run_cmd "audit" audit --program opt.ir.json --backend "$PROGRAM_BACKEND" --out audit.json --json; then exit 1; fi
if ! run_cmd "test-vectors" test-vectors --program opt.ir.json --vectors vectors.json --backends "$PROGRAM_BACKEND" --json; then exit 1; fi

if ! run_cmd "capabilities" capabilities; then exit 1; fi
if ! run_cmd "frontends" frontends --json; then exit 1; fi
if ! run_cmd "doctor" doctor --json; then exit 1; fi
if ! run_cmd "metal-doctor" metal-doctor --json; then exit 1; fi
if ! run_cmd "registry-list" registry list --json; then exit 1; fi

echo
echo "Starting Python release-tool regression suite"
if python3 -m unittest discover -s "$ROOT/scripts/tests" -p 'test_*.py'; then
    echo "PASS: python-release-tools"
else
    status=$?
    echo "FAIL: python-release-tools (exit code $status)"
    exit "$status"
fi

echo
echo "All smoke tests passed."
