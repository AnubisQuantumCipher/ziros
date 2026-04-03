#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS="$SCRIPT_DIR/../contracts/compact"
OUTPUT="$SCRIPT_DIR/../contracts/compiled"
COMPACT_RUNNER="${COMPACT_RUNNER:-run-compactc}"
COMPACT_VERSION="${COMPACTC_VERSION:-0.30.0}"
COMPACT_PACKAGE_DIR="$SCRIPT_DIR/../node_modules/@midnight-ntwrk/midnight-js-compact"
CACHE_ROOT="${COMPACT_CACHE_ROOT:-$HOME/.cache/ziros/compactc}"
CACHE_DIR="$CACHE_ROOT/$COMPACT_VERSION"

prepare_compact_toolchain() {
  if [ -n "${COMPACT_HOME:-}" ] && [ -x "${COMPACT_HOME}/compactc.bin" ]; then
    echo "${COMPACT_HOME}/compactc.bin"
    return 0
  fi

  local managed_dir="$COMPACT_PACKAGE_DIR/managed/$COMPACT_VERSION"
  if [ ! -x "$managed_dir/compactc.bin" ]; then
    echo "Preparing Compact toolchain v$COMPACT_VERSION..."
    (
      cd "$SCRIPT_DIR/.."
      npm run fetch-compactc >/dev/null
    )
  fi

  if [ ! -x "$managed_dir/compactc.bin" ]; then
    echo "Error: Compact toolchain v$COMPACT_VERSION is missing at $managed_dir"
    exit 1
  fi

  mkdir -p "$CACHE_ROOT"
  rm -rf "$CACHE_DIR"
  cp -R "$managed_dir" "$CACHE_DIR"

  for tool in compactc compactc.bin zkir zkir-v3 format-compact fixup-compact; do
    if [ -e "$CACHE_DIR/$tool" ]; then
      xattr -dr com.apple.provenance "$CACHE_DIR/$tool" 2>/dev/null || true
      xattr -dr com.apple.quarantine "$CACHE_DIR/$tool" 2>/dev/null || true
      codesign --force --sign - "$CACHE_DIR/$tool" >/dev/null 2>&1 || true
    fi
  done

  echo "$CACHE_DIR/compactc.bin"
}

mkdir -p "$OUTPUT"
rm -rf "$OUTPUT"/*

COMPACTC_BIN="$(prepare_compact_toolchain)"
COMPILE_CMD=("$COMPACTC_BIN")
export PATH="$(dirname "$COMPACTC_BIN"):$PATH"

count=0
for contract in "$CONTRACTS"/*.compact; do
  [ -f "$contract" ] || continue
  name=$(basename "$contract" .compact)
  echo "Compiling $name..."
  "${COMPILE_CMD[@]}" "$contract" "$OUTPUT/$name/"
  if ! find "$OUTPUT/$name" -path '*/keys/*.verifier' -print -quit | grep -q .; then
    echo "Error: Compact compile for $name did not produce verifier assets under $OUTPUT/$name/keys/"
    exit 1
  fi
  echo "  -> $OUTPUT/$name/"
  count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
  echo "Warning: no .compact files found in $CONTRACTS"
  exit 1
fi

echo ""
echo "All $count contract(s) compiled successfully."
