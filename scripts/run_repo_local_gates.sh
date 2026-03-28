#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${ROOT_DIR}/Cargo.toml"

cd "${ROOT_DIR}"

echo "[gates] cargo build --workspace"
cargo build --workspace

echo "[gates] cargo clippy --workspace -- -D warnings"
cargo clippy --workspace -- -D warnings

echo "[gates] rustfmt workspace check"
python3 "${ROOT_DIR}/scripts/check_rustfmt_workspace.py" --check

if [[ "${1:-}" == "--with-lib-tests" ]]; then
    echo "[gates] cargo test --workspace --lib --no-fail-fast"
    cargo test --workspace --lib --no-fail-fast
fi
