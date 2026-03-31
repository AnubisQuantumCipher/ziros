#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"

coqc_bin="${COQC:-}"
if [[ -z "$coqc_bin" ]]; then
  if command -v coqc >/dev/null 2>&1; then
    coqc_bin="$(command -v coqc)"
  else
    echo "missing \`coqc\` on PATH" >&2
    exit 1
  fi
fi
coqbin_dir="$(cd "$(dirname "$coqc_bin")" && pwd -L)"

generated_core_dir="${HAX_GENERATED_CORE_DIR:-}"
if [[ -z "$generated_core_dir" ]]; then
  candidate_generated_core="/Users/sicarii/Projects/ZK DEV/.zkf-tools/hax/src/hax/hax-lib/proof-libs/coq/coq/generated-core"
  if [[ -d "$candidate_generated_core" ]]; then
    generated_core_dir="$candidate_generated_core"
  fi
fi

record_update_dir="${ROCQ_RECORDUPDATE_DIR:-}"
if [[ -z "$record_update_dir" ]]; then
  candidate_record_update="/Users/sicarii/Projects/ZK DEV/zkf-core/proofs/rocq/vendor/RecordUpdate"
  if [[ -d "$candidate_record_update" ]]; then
    record_update_dir="$candidate_record_update"
  fi
fi

log() {
  printf '[rocq] %s\n' "$*" >&2
}

ensure_generated_core() {
  if [[ -z "$generated_core_dir" || -z "$record_update_dir" ]]; then
    echo "missing generated-core or RecordUpdate proof library path; set HAX_GENERATED_CORE_DIR and ROCQ_RECORDUPDATE_DIR" >&2
    exit 1
  fi

  log "Rebuilding generated-core with toolchain from $coqc_bin"
  (
    cd "$generated_core_dir"
    make -B -j2 src/Core.vo COQBIN="$coqbin_dir/"
  )
}

run_workspace() {
  local workspace="$1"
  shift
  local -a base_args=("$@")
  local project_file="$workspace/_CoqProject"
  if [[ ! -f "$project_file" ]]; then
    echo "missing Rocq project file at $project_file" >&2
    exit 1
  fi

  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    case "$line" in
      -Q\ *)
        set -- $line
        base_args+=("$1" "$2" "$3")
        ;;
      -R\ *)
        set -- $line
        base_args+=("$1" "$2" "$3")
        ;;
      ./*.v)
        local proof_rel="${line#./}"
        log "Compiling ${workspace#$repo_root/}/$proof_rel"
        (
          cd "$workspace"
          "$coqc_bin" "${base_args[@]}" "$proof_rel"
        )
        ;;
    esac
  done < "$project_file"
}

ensure_generated_core

shared_args=(
  -Q "$record_update_dir" RecordUpdate
  -R "$generated_core_dir/src" Core
  -R "$generated_core_dir/spec" Core
  -R "$generated_core_dir/phase_library" Core
)

run_workspace "$repo_root/zkf-core/proofs/rocq" "${shared_args[@]}"
run_workspace "$repo_root/zkf-frontends/proofs/rocq" "${shared_args[@]}"
