#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/../02_app"
OUTPUT_DIR="${1:-$SCRIPT_DIR/..}"
echo "=== Running Satellite Fuel Compliance Verifier ==="
cd "$APP_DIR"
cargo run -- "$OUTPUT_DIR" 2>&1
