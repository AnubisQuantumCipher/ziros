#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <pin-file>" >&2
  exit 1
fi

repo_root="${ZKF_FSTAR_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)}"
pin_file="$1"
bootstrap_script="$repo_root/scripts/bootstrap_hax_toolchain.sh"
env_file="$repo_root/.zkf-tools/hax/hax.env"

if [ ! -f "$pin_file" ]; then
  echo "missing hax pin at $pin_file" >&2
  exit 1
fi

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

crate_rel="$(pin_value crate_root)"
crate_name="$(pin_value crate)"
backend_name="$(pin_value backend)"
include_filter="$(pin_value include)"
switch_name="$(pin_value opam_switch)"

if [ -z "$crate_rel" ] || [ -z "$crate_name" ] || [ -z "$backend_name" ] || [ -z "$include_filter" ]; then
  echo "incomplete hax pin metadata in $pin_file" >&2
  exit 1
fi

crate_root="$repo_root/$crate_rel"
output_dir="$crate_root/proofs/fstar/extraction"

if [ ! -f "$env_file" ]; then
  "$bootstrap_script"
fi

if [ -f "$env_file" ]; then
  # shellcheck disable=SC1090
  source "$env_file"
fi

if ! cargo hax --version >/dev/null 2>&1; then
  "$bootstrap_script"
  # shellcheck disable=SC1090
  source "$env_file"
fi

if ! cargo hax --version >/dev/null 2>&1; then
  echo "cargo-hax is required to extract $crate_name proof kernels into F*" >&2
  exit 1
fi

if [ -n "$switch_name" ] && [ "$(opam switch show 2>/dev/null || true)" != "$switch_name" ]; then
  echo "expected opam switch '$switch_name' while running hax extraction" >&2
  exit 1
fi

mkdir -p "$output_dir"
find "$output_dir" -mindepth 1 -delete

cd "$repo_root"
cargo hax -C -p "$crate_name" ';' into -i "$include_filter" --output-dir "$output_dir" "$backend_name"

if ! find "$output_dir" -type f \( -name '*.fst' -o -name '*.fsti' \) | grep -q .; then
  echo "no F* extraction files were written to $output_dir" >&2
  exit 1
fi

printf '[hax] wrote %s extraction into %s\n' "$crate_name" "$output_dir"
