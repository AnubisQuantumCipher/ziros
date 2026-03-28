#!/usr/bin/env bash
set -euo pipefail
echo "=== ZirOS Lunar Flagship Setup ==="
echo "Checking prerequisites..."
command -v cargo &>/dev/null || { echo "ERROR: Rust not found. Install: https://rustup.rs"; exit 1; }
echo "Rust: $(rustc --version)"
ZIROS="$HOME/Desktop/ziros-release"
[ -d "$ZIROS/zkf-lib" ] || { echo "ERROR: ZirOS v0.1.0 not found at $ZIROS. Clone: gh repo clone AnubisQuantumCipher/ziros ~/Desktop/ziros-release -- --branch v0.1.0"; exit 1; }
echo "ZirOS: $ZIROS (v0.1.0 release)"
echo "Setup complete."
