#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Full Mission (200-step descent) ==="
./01_source/target/release/ziros-lunar-flagship full-mission
