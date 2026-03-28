#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$SCRIPT_DIR/.."
APP_DIR="$BASE_DIR/02_app"

echo "============================================"
echo "  End-to-End: Satellite Fuel Compliance"
echo "============================================"
echo ""

# 1. Build
echo "[1/3] Building..."
cd "$APP_DIR"
cargo build 2>&1 | tail -1
echo ""

# 2. Run (build circuit + prove + verify)
echo "[2/3] Running full pipeline..."
cargo run -- "$BASE_DIR" 2>&1 | grep -v "^warning:" | grep -v "^   -->" | grep -v "^    |" | grep -v "^$" | grep -v "^    ="
echo ""

# 3. Verify outputs exist
echo "[3/3] Checking artifacts..."
PASS=true
for f in \
  "04_artifacts/program.json" \
  "04_artifacts/valid_inputs.json" \
  "04_artifacts/manifest.json" \
  "05_proofs/proof_artifact.json" \
  "05_proofs/proof_metadata.json" \
  "06_verifiers/verification_result.json" \
  "07_test_results/test_log.txt"; do
  if [ -f "$BASE_DIR/$f" ]; then
    echo "  OK: $f"
  else
    echo "  MISSING: $f"
    PASS=false
  fi
done

echo ""
if $PASS; then
  echo "=== END-TO-END: ALL CHECKS PASSED ==="
else
  echo "=== END-TO-END: SOME CHECKS FAILED ==="
  exit 1
fi
