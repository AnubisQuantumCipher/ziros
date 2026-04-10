#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS="$SCRIPT_DIR/../contracts/compact"
OUTPUT="$SCRIPT_DIR/../contracts/compiled"
COMPACT_RUNNER="${COMPACT_RUNNER:-run-compactc}"

mkdir -p "$OUTPUT"
rm -rf "$OUTPUT"/*

if command -v compactc &>/dev/null; then
  COMPILE_CMD=("compactc")
elif command -v "$COMPACT_RUNNER" &>/dev/null; then
  COMPILE_CMD=("$COMPACT_RUNNER")
else
  echo "Error: neither '$COMPACT_RUNNER' nor 'compactc' was found."
  echo "Run 'npm run fetch-compactc' or install the Midnight Compact compiler first."
  exit 1
fi

count=0
for contract in "$CONTRACTS"/*.compact; do
  [ -f "$contract" ] || continue
  name=$(basename "$contract" .compact)
  echo "Compiling $name..."
  "${COMPILE_CMD[@]}" "$contract" "$OUTPUT/$name/"
  echo "  -> $OUTPUT/$name/"
  count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
  echo "Warning: no .compact files found in $CONTRACTS"
  exit 1
fi

echo ""
echo "All $count contract(s) compiled successfully."
