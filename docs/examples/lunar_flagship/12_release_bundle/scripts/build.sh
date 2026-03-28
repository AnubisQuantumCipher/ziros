#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Building ZirOS Lunar Flagship ==="
cargo build --release --manifest-path 01_source/Cargo.toml
echo "Build complete: 01_source/target/release/ziros-lunar-flagship"
