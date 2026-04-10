#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/run_refinedrust_proofs.sh [--strict] [--out-dir DIR] [surface...]

Run pinned RefinedRust proof surfaces. Surface names resolve under
formal/refinedrust/<surface>. Each surface may contain:

  target_path  path, relative to repo root, where `cargo refinedrust` runs
  dune_path    path, relative to repo root, where `dune build` runs
  cargo_args   optional one-argument-per-line cargo args passed after `--`
  theorem_ids  optional one-theorem-id-per-line ledger rows for counted surfaces

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
counted_theorem_ids=()

read_lines_file() {
  local path="$1"
  local target="$2"
  local line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    case "${target}" in
      cargo_args)
        cargo_args+=("${line}")
        ;;
      counted_theorem_ids)
        counted_theorem_ids+=("${line}")
        ;;
      *)
        echo "internal error: unknown read_lines_file target ${target}" >&2
        exit 2
        ;;
    esac
  done <"${path}"
}

normalize_generated_dune_project() {
  local dune_dir="$1"
  local project_file="${dune_dir}/dune-project"
  local dune_version

  if [[ ! -f "${project_file}" ]]; then
    return
  fi

  dune_version="$(dune --version 2>/dev/null | head -n 1)"
  case "${dune_version}" in
    3.2[1-9]*|3.[3-9]*|[4-9]*)
      if grep -q '^(lang dune 3\.20)' "${project_file}"; then
        sed 's/^(lang dune 3\.20)$/\(lang dune 3.21\)/' "${project_file}" >"${project_file}.tmp"
        mv "${project_file}.tmp" "${project_file}"
        notes+=("normalized stale generated dune-project from language 3.20 to 3.21 for local dune ${dune_version}")
      fi
      if grep -q '^(using coq ' "${project_file}"; then
        sed 's/^(using coq .*)$/\(using rocq 0.11\)/' "${project_file}" >"${project_file}.tmp"
        mv "${project_file}.tmp" "${project_file}"
        notes+=("normalized stale generated dune-project from coq extension to rocq 0.11 for local dune ${dune_version}")
      fi
      ;;
  esac
}

ensure_generated_opam_packages() {
  local dune_dir="$1"
  local package
  local opam_file

  while IFS= read -r package || [[ -n "${package}" ]]; do
    if [[ -z "${package}" ]]; then
      continue
    fi
    opam_file="${dune_dir}/${package}.opam"
    if [[ -f "${opam_file}" ]]; then
      continue
    fi
    {
      printf 'opam-version: "2.0"\n'
      printf 'name: "%s"\n' "${package}"
      printf 'version: "dev"\n'
      printf 'synopsis: "Generated RefinedRust proof package marker"\n'
      printf 'description: "Generated locally by scripts/run_refinedrust_proofs.sh so dune can check RefinedRust proof stanzas with package metadata."\n'
      printf 'depends: [\n'
      printf '  "dune"\n'
      printf ']\n'
    } >"${opam_file}"
    notes+=("created generated opam package marker ${opam_file}")
  done < <(find "${dune_dir}" -name dune -type f -exec sed -n 's/^[[:space:]]*(package \([^)]*\)).*/\1/p' {} + | sort -u)
}

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
    printf '  "counted_theorem_ids": '
    json_array "${counted_theorem_ids[@]}"
    printf ',\n'
    printf '  "log_path": "%s",\n' "$(json_escape "${log_file}")"
    if [[ "${status}" == "passed" && ${#counted_theorem_ids[@]} -gt 0 ]]; then
      printf '  "counted_in_verification_ledger": true\n'
    else
      printf '  "counted_in_verification_ledger": false\n'
    fi
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

  cargo_args=()
  if [[ -f "${surface_dir}/cargo_args" ]]; then
    read_lines_file "${surface_dir}/cargo_args" cargo_args
  fi

  if [[ -f "${surface_dir}/theorem_ids" ]]; then
    read_lines_file "${surface_dir}/theorem_ids" counted_theorem_ids
  fi

  {
    echo "[refinedrust:${surface_name}] target_dir=${target_dir}"
    echo "[refinedrust:${surface_name}] dune_dir=${dune_dir}"
    if [[ ${#cargo_args[@]} -gt 0 ]]; then
      echo "[refinedrust:${surface_name}] cargo_args=${cargo_args[*]}"
    fi
  } >>"${log_file}"

  if [[ ${#cargo_args[@]} -gt 0 ]]; then
    if ! (cd "${target_dir}" && cargo refinedrust -- "${cargo_args[@]}") >>"${log_file}" 2>&1; then
      failed+=("${surface_name}:cargo-refinedrust-failed")
      continue
    fi
  else
    if ! (cd "${target_dir}" && cargo refinedrust) >>"${log_file}" 2>&1; then
      failed+=("${surface_name}:cargo-refinedrust-failed")
      continue
    fi
  fi

  normalize_generated_dune_project "${dune_dir}"
  ensure_generated_opam_packages "${dune_dir}"

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
