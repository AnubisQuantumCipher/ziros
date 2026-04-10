#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/run_thrust_checks.sh [--strict] [--out-dir DIR] [--timeout SECONDS] [target...]

Run Thrust over safe-Rust support targets. Named targets:

  runtime-core             zkf-runtime/src/*_core.rs
  distributed-swarm-core   zkf-distributed/src/swarm_*_core.rs
  zir-lang-core            zkf-lang/src/lib.rs
  proof-spec-core          zkf-core/src/proof_*_spec.rs
  all-core                 runtime-core + distributed-swarm-core + zir-lang-core

Evidence is written to target-local/formal/thrust by default and is not counted
in zkf-ir-spec/verification-ledger.json.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
strict=false
out_dir="${repo_root}/target-local/formal/thrust"
timeout_seconds=30
target_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      strict=true
      shift
      ;;
    --out-dir)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      out_dir="$2"
      shift 2
      ;;
    --timeout)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      timeout_seconds="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      target_args+=("$1")
      shift
      ;;
  esac
done

if [[ ${#target_args[@]} -eq 0 ]]; then
  target_args=(runtime-core)
fi

mkdir -p "${out_dir}/smt2"
log_file="${out_dir}/thrust.log"
summary_file="${out_dir}/thrust-evidence.json"
pin_file="${repo_root}/formal/tools/thrust-pin.json"
pin_commit="$(
  sed -n 's/.*"upstream_commit": "\(.*\)",/\1/p' "${pin_file}" 2>/dev/null | head -n 1
)"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "${value}"
}

json_array() {
  local first=true
  printf '['
  for value in "$@"; do
    if [[ "${first}" == true ]]; then
      first=false
    else
      printf ','
    fi
    printf '"%s"' "$(json_escape "${value}")"
  done
  printf ']'
}

target_files=()
passed=()
failed=()
skipped=()
trusted_functions=()
notes=()

append_if_file() {
  local path="$1"
  if [[ -f "${repo_root}/${path}" ]]; then
    target_files+=("${path}")
  fi
}

expand_target() {
  local target="$1"
  case "${target}" in
    runtime-core)
      while IFS= read -r -d '' file; do
        target_files+=("${file#${repo_root}/}")
      done < <(find "${repo_root}/zkf-runtime/src" -maxdepth 1 -name '*_core.rs' -type f -print0 | sort -z)
      ;;
    distributed-swarm-core)
      while IFS= read -r -d '' file; do
        target_files+=("${file#${repo_root}/}")
      done < <(find "${repo_root}/zkf-distributed/src" -maxdepth 1 -name 'swarm_*_core.rs' -type f -print0 | sort -z)
      ;;
    zir-lang-core)
      append_if_file "zkf-lang/src/lib.rs"
      ;;
    proof-spec-core)
      while IFS= read -r -d '' file; do
        target_files+=("${file#${repo_root}/}")
      done < <(find "${repo_root}/zkf-core/src" -maxdepth 1 -name 'proof_*_spec.rs' -type f -print0 | sort -z)
      ;;
    all-core)
      expand_target runtime-core
      expand_target distributed-swarm-core
      expand_target zir-lang-core
      ;;
    *)
      append_if_file "${target}"
      ;;
  esac
}

write_summary() {
  local status="$1"
  local reason="$2"
  set +u
  {
    printf '{\n'
    printf '  "schema": "zkf-thrust-evidence-v1",\n'
    printf '  "tool": "thrust",\n'
    printf '  "tool_commit": "%s",\n' "$(json_escape "${pin_commit:-unknown}")"
    printf '  "solver": "%s",\n' "$(json_escape "${THRUST_SOLVER:-z3}")"
    printf '  "solver_args": "%s",\n' "$(json_escape "${THRUST_SOLVER_ARGS:-fp.spacer.global=true fp.validate=true}")"
    printf '  "timeout_seconds": %s,\n' "${timeout_seconds}"
    printf '  "strict": %s,\n' "${strict}"
    printf '  "status": "%s",\n' "$(json_escape "${status}")"
    printf '  "reason": "%s",\n' "$(json_escape "${reason}")"
    printf '  "target_files": '
    json_array "${target_files[@]}"
    printf ',\n'
    printf '  "passed": '
    json_array "${passed[@]}"
    printf ',\n'
    printf '  "failed": '
    json_array "${failed[@]}"
    printf ',\n'
    printf '  "skipped": '
    json_array "${skipped[@]}"
    printf ',\n'
    printf '  "trusted_functions": '
    json_array "${trusted_functions[@]}"
    printf ',\n'
    printf '  "notes": '
    json_array "${notes[@]}"
    printf ',\n'
    printf '  "log_path": "%s",\n' "$(json_escape "${log_file}")"
    printf '  "counted_in_verification_ledger": false\n'
    printf '}\n'
  } >"${summary_file}"
  set -u
}

: >"${log_file}"

for target in "${target_args[@]}"; do
  expand_target "${target}"
done

if [[ ${#target_files[@]} -eq 0 ]]; then
  notes+=("no Thrust target files were found")
  write_summary "skipped_no_targets" "no targets requested or discovered"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

if ! command -v "${THRUST_RUSTC:-thrust-rustc}" >/dev/null 2>&1; then
  notes+=("missing thrust-rustc frontend")
  for file in "${target_files[@]}"; do
    skipped+=("${file}:missing-thrust-rustc")
  done
  write_summary "skipped_missing_tool" "thrust-rustc was not found in PATH"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

if ! command -v "${THRUST_SOLVER:-z3}" >/dev/null 2>&1; then
  notes+=("missing CHC solver")
  for file in "${target_files[@]}"; do
    skipped+=("${file}:missing-solver")
  done
  write_summary "skipped_missing_solver" "configured THRUST_SOLVER was not found in PATH"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

export THRUST_SOLVER="${THRUST_SOLVER:-z3}"
export THRUST_SOLVER_ARGS="${THRUST_SOLVER_ARGS:-fp.spacer.global=true fp.validate=true}"
export THRUST_SOLVER_TIMEOUT_SECS="${timeout_seconds}"
export THRUST_OUTPUT_DIR="${out_dir}/smt2"

for file in "${target_files[@]}"; do
  path="${repo_root}/${file}"
  if [[ ! -f "${path}" ]]; then
    failed+=("${file}:missing-file")
    continue
  fi

  while IFS= read -r trusted; do
    [[ -n "${trusted}" ]] && trusted_functions+=("${trusted}")
  done < <(rg -n "#\\[thrust::trusted\\]|thrust::trusted" "${path}" 2>/dev/null || true)

  echo "[thrust] ${file}" >>"${log_file}"
  if "${THRUST_RUSTC:-thrust-rustc}" -Adead_code -C debug-assertions=false "${path}" >>"${log_file}" 2>&1; then
    passed+=("${file}")
  else
    failed+=("${file}:thrust-rustc-failed")
  fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
  write_summary "failed" "one or more Thrust targets failed"
  cat "${summary_file}" >&2
  exit 1
fi

write_summary "passed" "all requested Thrust targets passed"
cat "${summary_file}"
