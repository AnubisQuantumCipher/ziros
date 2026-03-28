#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() {
  printf '[montgomery-assurance] %s\n' "$*" >&2
}

log "Checking strict-lane exclusion of zkf-crypto-accel Montgomery as a regression backstop"
python3 ./scripts/check_strict_montgomery_exclusion.py

log "Running zkf-core large-prime Montgomery regression corpus"
cargo test -p zkf-core montgomery_assurance --lib

log "Running zkf-crypto-accel BN254 Montgomery regression corpus"
cargo test -p zkf-crypto-accel montgomery_assurance --lib
