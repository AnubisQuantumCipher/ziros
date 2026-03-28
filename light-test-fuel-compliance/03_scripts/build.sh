#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/../02_app"
echo "=== Building Satellite Fuel Compliance Verifier ==="
cd "$APP_DIR"
cargo build 2>&1
echo "=== Build complete ==="
