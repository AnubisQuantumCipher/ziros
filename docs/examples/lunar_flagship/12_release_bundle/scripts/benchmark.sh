#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./01_source/target/release/ziros-lunar-flagship benchmark
