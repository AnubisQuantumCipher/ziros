#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target-public}"

cargo build --manifest-path "$ROOT/Cargo.toml" --release -p zkf-lib --example plonky3_manual_soak --features metal-gpu
exec "$TARGET_DIR/release/examples/plonky3_manual_soak" "$@"
