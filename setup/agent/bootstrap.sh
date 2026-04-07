#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash setup/agent/bootstrap.sh [--check-only] [--json] [--no-midnight] [--no-evm]

Build and validate the ZirOS agent operator path on Apple Silicon.
EOF
}

check_only=0
json_output=0
enable_midnight=1
enable_evm=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only)
      check_only=1
      ;;
    --json)
      json_output=1
      ;;
    --no-midnight)
      enable_midnight=0
      ;;
    --no-evm)
      enable_evm=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
configured_target_dir=""
if [[ -f "${repo_root}/.cargo/config.toml" ]]; then
  configured_target_dir="$(
    sed -n 's/^target-dir = "\(.*\)"/\1/p' "${repo_root}/.cargo/config.toml" | head -n 1
  )"
fi
if [[ -n "${configured_target_dir}" ]]; then
  target_dir="${repo_root}/${configured_target_dir}/release"
else
  target_dir="${repo_root}/target/release"
fi
local_bin="${HOME}/.local/bin"
cache_root="${HOME}/.zkf/cache"
state_root="${HOME}/.zkf/state"
socket_path="${cache_root}/agent/ziros-agentd.sock"
brain_path="${cache_root}/agent/brain.sqlite3"
cli_artifact=""

declare -a missing=()
declare -a checks=()
compactc_path=""
bootstrap_ok=1

have_command() {
  command -v "$1" >/dev/null 2>&1
}

require_command() {
  local name="$1"
  if have_command "$name"; then
    checks+=("require:${name}:pass")
  else
    missing+=("$name")
    checks+=("require:${name}:fail")
  fi
}

resolve_compactc_path() {
  if [[ -n "${COMPACTC_BIN:-}" && -x "${COMPACTC_BIN}" ]]; then
    printf '%s\n' "${COMPACTC_BIN}"
    return 0
  fi

  if have_command compactc; then
    command -v compactc
    return 0
  fi

  local platform="aarch64-darwin"
  local versions_root="${HOME}/.compact/versions"
  local required="${versions_root}/0.30.0/${platform}/compactc"
  if [[ -x "${required}" ]]; then
    printf '%s\n' "${required}"
    return 0
  fi

  local candidate=""
  for candidate in "${versions_root}"/*/"${platform}"/compactc; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

run_check() {
  local label="$1"
  shift
  local timeout_seconds="${ZIROS_BOOTSTRAP_CHECK_TIMEOUT_SECONDS:-20}"
  if python3 - "$timeout_seconds" "$@" <<'PY' >/dev/null 2>&1
import subprocess
import sys

timeout_seconds = float(sys.argv[1])
command = sys.argv[2:]

try:
    completed = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout_seconds,
        check=False,
    )
    raise SystemExit(completed.returncode)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
PY
  then
    checks+=("check:${label}:pass")
  else
    checks+=("check:${label}:fail")
    return 1
  fi
}

run_advisory_check() {
  local label="$1"
  shift
  local timeout_seconds="${ZIROS_BOOTSTRAP_CHECK_TIMEOUT_SECONDS:-20}"
  if python3 - "$timeout_seconds" "$@" <<'PY' >/dev/null 2>&1
import subprocess
import sys

timeout_seconds = float(sys.argv[1])
command = sys.argv[2:]

try:
    completed = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout_seconds,
        check=False,
    )
    raise SystemExit(completed.returncode)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
PY
  then
    checks+=("advisory:${label}:pass")
  else
    checks+=("advisory:${label}:fail")
    return 1
  fi
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ZirOS agent bootstrap requires macOS." >&2
  exit 1
fi

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "ZirOS agent bootstrap requires Apple Silicon (arm64)." >&2
  exit 1
fi

require_command cargo
require_command rustc
require_command git
require_command xcrun

if (( enable_midnight )); then
  require_command node
  require_command npm
  require_command compact
  if compactc_path="$(resolve_compactc_path)"; then
    checks+=("require:compactc:pass")
  else
    missing+=("compactc")
    checks+=("require:compactc:fail")
  fi
fi

if (( enable_evm )); then
  require_command forge
  require_command anvil
  require_command cast
fi

if (( ${#missing[@]} > 0 )); then
  if (( json_output )); then
    printf '{\n'
    printf '  "schema": "ziros-agent-bootstrap-v1",\n'
    printf '  "ok": false,\n'
    printf '  "repo_root": "%s",\n' "$repo_root"
    printf '  "missing_required_commands": ['
    for i in "${!missing[@]}"; do
      [[ "$i" -gt 0 ]] && printf ', '
      printf '"%s"' "${missing[$i]}"
    done
    printf ']\n}\n'
  else
    echo "Missing required commands:"
    printf '  - %s\n' "${missing[@]}"
  fi
  exit 1
fi

mkdir -p "$local_bin" "$cache_root" "$state_root"

if (( ! check_only )); then
  cargo build -p zkf-cli --release
  cargo build -p zkf-agent --release --bin ziros-agentd
fi

if [[ -x "${target_dir}/zkf-cli" ]]; then
  cli_artifact="${target_dir}/zkf-cli"
elif [[ -x "${target_dir}/zkf" ]]; then
  cli_artifact="${target_dir}/zkf"
fi

if (( ! check_only )); then
  if [[ -z "${cli_artifact}" ]]; then
    echo "Could not find a built ZirOS CLI artifact under ${target_dir}." >&2
    exit 1
  fi
  ln -sfn "${cli_artifact}" "${local_bin}/ziros"
  ln -sfn "${cli_artifact}" "${local_bin}/zkf"
  ln -sfn "${target_dir}/ziros-agentd" "${local_bin}/ziros-agentd"
fi

ziros_cmd="${local_bin}/ziros"
if [[ ! -x "$ziros_cmd" ]]; then
  ziros_cmd="${cli_artifact}"
fi

if [[ ! -x "$ziros_cmd" ]]; then
  echo "Could not find a built ZirOS CLI at ${local_bin}/ziros or ${target_dir}/zkf-cli." >&2
  exit 1
fi

if ! run_check "ziros-doctor" "$ziros_cmd" doctor --json; then
  bootstrap_ok=0
fi
if ! run_check "ziros-metal-doctor" "$ziros_cmd" metal-doctor --json; then
  bootstrap_ok=0
fi
run_advisory_check "ziros-agent-doctor" "$ziros_cmd" agent --json doctor || true
run_advisory_check "ziros-agent-provider-status" "$ziros_cmd" agent --json provider status || true

if (( enable_midnight )); then
  if ! run_check "ziros-midnight-doctor" "$ziros_cmd" midnight doctor --json --network preprod; then
    bootstrap_ok=0
  fi
fi

if (( enable_evm )); then
  if ! run_check "ziros-evm-diagnose" "$ziros_cmd" evm diagnose --json; then
    bootstrap_ok=0
  fi
fi

path_ready="false"
case ":${PATH}:" in
  *":${HOME}/.local/bin:"*)
    path_ready="true"
    ;;
esac

if (( json_output )); then
  printf '{\n'
  printf '  "schema": "ziros-agent-bootstrap-v1",\n'
  printf '  "ok": %s,\n' "$([[ $bootstrap_ok -eq 1 ]] && echo true || echo false)"
  printf '  "check_only": %s,\n' "$([[ $check_only -eq 1 ]] && echo true || echo false)"
  printf '  "repo_root": "%s",\n' "$repo_root"
  printf '  "ziros_command": "%s",\n' "$ziros_cmd"
  printf '  "daemon_binary": "%s",\n' "${local_bin}/ziros-agentd"
  printf '  "socket_path": "%s",\n' "$socket_path"
  printf '  "brain_path": "%s",\n' "$brain_path"
  printf '  "path_ready": %s,\n' "$path_ready"
  if [[ -n "${compactc_path}" ]]; then
    printf '  "compactc_path": "%s",\n' "$compactc_path"
  fi
  printf '  "checks": [\n'
  for i in "${!checks[@]}"; do
    IFS=':' read -r kind label status <<<"${checks[$i]}"
    [[ "$i" -gt 0 ]] && printf ',\n'
    printf '    { "kind": "%s", "label": "%s", "status": "%s" }' "$kind" "$label" "$status"
  done
  printf '\n  ],\n'
  printf '  "next_steps": [\n'
  printf '    "source $HOME/.ziros/agent.env",\n'
  printf '    "ziros-agentd",\n'
  printf '    "ziros agent --json run --goal \\"Inspect this ZirOS checkout and summarize the current operator state.\\""\n'
  printf '  ]\n'
  printf '}\n'
else
  if [[ $bootstrap_ok -eq 1 ]]; then
    echo "ZirOS agent bootstrap is ready."
  else
    echo "ZirOS agent bootstrap completed, but one or more health checks failed."
  fi
  echo "Repo root: ${repo_root}"
  echo "CLI: ${ziros_cmd}"
  echo "Daemon: ${local_bin}/ziros-agentd"
  echo "Socket: ${socket_path}"
  echo "Brain: ${brain_path}"
  if [[ -n "${compactc_path}" ]]; then
    echo "compactc: ${compactc_path}"
  fi
  if [[ "$path_ready" != "true" ]]; then
    echo
    echo "Add ~/.local/bin to PATH before starting a new shell:"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
  fi
  echo
  echo "Checks:"
  for entry in "${checks[@]}"; do
    IFS=':' read -r kind label status <<<"${entry}"
    [[ "${kind}" == "check" || "${kind}" == "advisory" ]] || continue
    echo "  ${label}: ${status}"
  done
  echo
  echo "Next:"
  echo '  source "$HOME/.ziros/agent.env"'
  echo "  ziros-agentd"
  echo '  ziros agent --json run --goal "Inspect this ZirOS checkout and summarize the current operator state."'
fi

if [[ $bootstrap_ok -ne 1 ]]; then
  exit 1
fi
