#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-local}"

TARGET_TRIPLE="aarch64-apple-darwin"
DIST_ROOT="$ROOT_DIR/dist"
DIST_DIR="$DIST_ROOT/$TARGET_TRIPLE"
HARNESS_BIN="$ROOT_DIR/$CARGO_TARGET_DIR/ffi_smoke"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
VERSION="0.4.1"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

cargo build --workspace --release --features metal-gpu,neural-engine
cargo build -p zkf-ffi --release

cp "$ROOT_DIR/$CARGO_TARGET_DIR/release/zkf-cli" "$DIST_DIR/zkf"
cp "$ROOT_DIR/$CARGO_TARGET_DIR/release/libzkf_ffi.dylib" "$DIST_DIR/libzkf_ffi.dylib"
cp "$ROOT_DIR/$CARGO_TARGET_DIR/release/libzkf_ffi.a" "$DIST_DIR/libzkf_ffi.a"

strip "$DIST_DIR/zkf"
strip -x "$DIST_DIR/libzkf_ffi.dylib"

cbindgen --crate zkf-ffi --lang c --output "$DIST_DIR/zkf.h"

ZKF_SHA="$(shasum -a 256 "$DIST_DIR/zkf" | awk '{print $1}')"
DYLIB_SHA="$(shasum -a 256 "$DIST_DIR/libzkf_ffi.dylib" | awk '{print $1}')"
STATIC_SHA="$(shasum -a 256 "$DIST_DIR/libzkf_ffi.a" | awk '{print $1}')"

cat >"$DIST_DIR/manifest.json" <<EOF
{
  "version": "$VERSION",
  "build_date": "$BUILD_DATE",
  "target_triple": "$TARGET_TRIPLE",
  "binaries": {
    "zkf": {
      "path": "zkf",
      "sha256": "$ZKF_SHA"
    },
    "libzkf_ffi.dylib": {
      "path": "libzkf_ffi.dylib",
      "sha256": "$DYLIB_SHA"
    },
    "libzkf_ffi.a": {
      "path": "libzkf_ffi.a",
      "sha256": "$STATIC_SHA"
    }
  }
}
EOF

clang \
  "$ROOT_DIR/zkf-ffi/examples/ffi_smoke.c" \
  -I"$DIST_DIR" \
  -L"$DIST_DIR" \
  -Wl,-rpath,"$DIST_DIR" \
  -lzkf_ffi \
  -o "$HARNESS_BIN"

"$HARNESS_BIN"

tar -czf "$DIST_ROOT/zkf-aarch64-apple-darwin-v$VERSION.tar.gz" -C "$DIST_ROOT" "$TARGET_TRIPLE"
