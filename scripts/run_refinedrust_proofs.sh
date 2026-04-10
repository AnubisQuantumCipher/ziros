#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/run_refinedrust_proofs.sh [--strict] [--out-dir DIR] [surface...]

Run pinned RefinedRust proof surfaces. Surface names resolve under
formal/refinedrust/<surface>. Each surface may contain:

  target_path  path, relative to repo root, where `cargo refinedrust` runs
  dune_path    path, relative to repo root, where `dune build` runs

If no surface is supplied, every directory under formal/refinedrust is used.
Evidence is written to target-local/formal/refinedrust by default.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
strict=false
out_dir="${repo_root}/target-local/formal/refinedrust"
surfaces=()

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
      surfaces+=("$1")
      shift
      ;;
  esac
done

mkdir -p "${out_dir}"
log_file="${out_dir}/refinedrust.log"
summary_file="${out_dir}/refinedrust-evidence.json"
pin_file="${repo_root}/formal/tools/refinedrust-pin.json"
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

passed=()
failed=()
skipped=()
notes=()

write_summary() {
  local status="$1"
  local reason="$2"
  set +u
  {
    printf '{\n'
    printf '  "schema": "zkf-refinedrust-evidence-v1",\n'
    printf '  "tool": "refinedrust",\n'
    printf '  "tool_commit": "%s",\n' "$(json_escape "${pin_commit:-unknown}")"
    printf '  "strict": %s,\n' "${strict}"
    printf '  "status": "%s",\n' "$(json_escape "${status}")"
    printf '  "reason": "%s",\n' "$(json_escape "${reason}")"
    printf '  "surfaces": '
    json_array "${surfaces[@]}"
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

if [[ ${#surfaces[@]} -eq 0 ]]; then
  while IFS= read -r -d '' surface_dir; do
    surfaces+=("$(basename "${surface_dir}")")
  done < <(find "${repo_root}/formal/refinedrust" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
fi

if [[ ${#surfaces[@]} -eq 0 ]]; then
  notes+=("no RefinedRust surfaces are checked in yet")
  write_summary "skipped_no_surfaces" "no surfaces requested or discovered"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

if ! command -v cargo-refinedrust >/dev/null 2>&1; then
  notes+=("missing cargo-refinedrust frontend")
  for surface in "${surfaces[@]}"; do
    skipped+=("${surface}:missing-cargo-refinedrust")
  done
  write_summary "skipped_missing_tool" "cargo-refinedrust was not found in PATH"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

if ! command -v dune >/dev/null 2>&1; then
  notes+=("missing dune Rocq build frontend")
  for surface in "${surfaces[@]}"; do
    skipped+=("${surface}:missing-dune")
  done
  write_summary "skipped_missing_tool" "dune was not found in PATH"
  if [[ "${strict}" == true ]]; then
    cat "${summary_file}" >&2
    exit 1
  fi
  cat "${summary_file}"
  exit 0
fi

for surface in "${surfaces[@]}"; do
  if [[ "${surface}" = /* || "${surface}" == */* ]]; then
    surface_dir="${repo_root}/${surface}"
    surface_name="$(basename "${surface}")"
  else
    surface_dir="${repo_root}/formal/refinedrust/${surface}"
    surface_name="${surface}"
  fi

  if [[ ! -d "${surface_dir}" ]]; then
    failed+=("${surface_name}:missing-surface-dir")
    continue
  fi

  target_dir="${surface_dir}"
  if [[ -f "${surface_dir}/target_path" ]]; then
    target_rel="$(sed -n '1p' "${surface_dir}/target_path")"
    if [[ "${target_rel}" = /* ]]; then
      target_dir="${target_rel}"
    else
      target_dir="${repo_root}/${target_rel}"
    fi
  fi

  dune_dir="${surface_dir}"
  if [[ -f "${surface_dir}/dune_path" ]]; then
    dune_rel="$(sed -n '1p' "${surface_dir}/dune_path")"
    if [[ "${dune_rel}" = /* ]]; then
      dune_dir="${dune_rel}"
    else
      dune_dir="${repo_root}/${dune_rel}"
    fi
  fi

  if [[ ! -d "${target_dir}" ]]; then
    failed+=("${surface_name}:missing-target-dir")
    continue
  fi
  if [[ ! -d "${dune_dir}" ]]; then
    failed+=("${surface_name}:missing-dune-dir")
    continue
  fi

  {
    echo "[refinedrust:${surface_name}] target_dir=${target_dir}"
    echo "[refinedrust:${surface_name}] dune_dir=${dune_dir}"
  } >>"${log_file}"

  if ! (cd "${target_dir}" && cargo refinedrust) >>"${log_file}" 2>&1; then
    failed+=("${surface_name}:cargo-refinedrust-failed")
    continue
  fi

  if ! (cd "${dune_dir}" && dune build) >>"${log_file}" 2>&1; then
    failed+=("${surface_name}:dune-build-failed")
    continue
  fi

  passed+=("${surface_name}")
done

if [[ ${#failed[@]} -gt 0 ]]; then
  write_summary "failed" "one or more RefinedRust surfaces failed"
  cat "${summary_file}" >&2
  exit 1
fi

write_summary "passed" "all requested RefinedRust surfaces passed"
cat "${summary_file}"
