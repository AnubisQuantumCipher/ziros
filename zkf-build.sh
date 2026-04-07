#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(build)
elif [[ "${args[0]}" == -* ]]; then
  args=(build "${args[@]}")
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  export MallocNanoZone="${MallocNanoZone:-0}"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-public}"

cargo "${args[@]}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  exit 0
fi

if [[ " ${args[*]} " != *" --release "* ]]; then
  exit 0
fi

case "${args[0]}" in
  build|install)
    ;;
  *)
    exit 0
    ;;
esac

release_features="metal-gpu"
skip_feature_flag=0
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --all-features)
      skip_feature_flag=1
      ;;
    --features|-F)
      if (( i + 1 < ${#args[@]} )); then
        release_features="${args[$((i + 1))]},metal-gpu"
      fi
      ;;
  esac
done

release_args=(build --release -p zkf-cli)
if (( skip_feature_flag == 0 )); then
  release_args+=(--features "$release_features")
fi

echo "[zkf-build] macOS release policy: ensuring zkf-cli is built with Metal support" >&2
cargo "${release_args[@]}"
