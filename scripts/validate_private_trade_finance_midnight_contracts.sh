#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
default_artifact_root="$repo_root/dist/showcases/private_trade_finance_settlement"
if [[ -f "$repo_root/16_compact/trade-finance-settlement/package_manifest.json" ]]; then
  default_artifact_root="$repo_root"
elif [[ -f "$repo_root/midnight_package/trade-finance-settlement/package_manifest.json" ]]; then
  default_artifact_root="$repo_root"
fi
artifact_root="${1:-$default_artifact_root}"
network="${2:-preprod}"

canonicalize_target_path() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  printf '%s/%s\n' "$(cd "$(dirname "$target")" && pwd -L)" "$(basename "$target")"
}

artifact_root="$(canonicalize_target_path "$artifact_root")"

artifact_layout=""
package_root=""
validation_root=""
if [[ -f "$artifact_root/midnight_package/trade-finance-settlement/package_manifest.json" ]]; then
  artifact_layout="showcase"
  package_root="$artifact_root/midnight_package/trade-finance-settlement"
  validation_root="$artifact_root/midnight_validation"
elif [[ -f "$artifact_root/16_compact/trade-finance-settlement/package_manifest.json" ]]; then
  artifact_layout="subsystem"
  package_root="$artifact_root/16_compact/trade-finance-settlement"
  validation_root="$artifact_root/17_report/midnight_validation"
else
  echo "could not detect trade-finance artifact layout under: $artifact_root" >&2
  echo "expected either midnight_package/trade-finance-settlement or 16_compact/trade-finance-settlement" >&2
  exit 1
fi

package_manifest="$package_root/package_manifest.json"
flow_manifest="$package_root/flow_manifest.json"
compile_root="$validation_root/compiled"
compile_reports="$validation_root/compile"
deploy_reports="$validation_root/deploy_prepare"
call_reports="$validation_root/call_prepare"
deploy_assets="$validation_root/deploy_prepare_assets"
call_assets="$validation_root/call_prepare_assets"
inputs_root="$validation_root/inputs"
admission_root="$validation_root/admission"

if [[ ! -f "$package_manifest" ]]; then
  echo "missing Midnight package manifest: $package_manifest" >&2
  exit 1
fi
if [[ ! -f "$flow_manifest" ]]; then
  echo "missing Midnight flow manifest: $flow_manifest" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to validate the trade finance Midnight package" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to validate the trade finance Midnight package" >&2
  exit 1
fi

mkdir -p \
  "$compile_root" \
  "$compile_reports" \
  "$deploy_reports" \
  "$call_reports" \
  "$deploy_assets" \
  "$call_assets" \
  "$inputs_root" \
  "$admission_root"
rm -rf "$deploy_assets" "$call_assets"
mkdir -p "$deploy_assets" "$call_assets"

if [[ -z "${COMPACTC_BIN:-}" && -x "$HOME/.compact/versions/0.30.0/aarch64-darwin/compactc" ]]; then
  export COMPACTC_BIN="$HOME/.compact/versions/0.30.0/aarch64-darwin/compactc"
fi
if [[ -n "${COMPACTC_BIN:-}" && -x "${COMPACTC_BIN}" ]]; then
  export PATH="$(dirname "${COMPACTC_BIN}"):$PATH"
fi

first_executable() {
  local candidate
  for candidate in "$@"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

supports_midnight_subcommand() {
  local candidate="$1"
  [[ -n "$candidate" && -x "$candidate" ]] || return 1
  "$candidate" midnight --help >/dev/null 2>&1
}

first_midnight_capable_executable() {
  local candidate
  for candidate in "$@"; do
    if supports_midnight_subcommand "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

resolve_cli_bin() {
  local resolved=""
  resolved="$(
    first_midnight_capable_executable \
      "${ZKF_SUBSYSTEM_ZIROS_BIN:-}" \
      "${ZKF_SUBSYSTEM_ZKF_BIN:-}" \
      "$artifact_root/20_release/bin/zkf" \
      "$repo_root/target/debug/zkf" \
      "$repo_root/target/debug/ziros"
  )" || true
  if [[ -n "$resolved" ]]; then
    printf '%s\n' "$resolved"
    return 0
  fi

  resolved="$(command -v zkf || true)"
  if supports_midnight_subcommand "$resolved"; then
    printf '%s\n' "$resolved"
    return 0
  fi

  resolved="$(command -v ziros || true)"
  if supports_midnight_subcommand "$resolved"; then
    printf '%s\n' "$resolved"
    return 0
  fi

  if [[ -f "$repo_root/Cargo.toml" ]]; then
    cargo build -q -p zkf-cli --manifest-path "$repo_root/Cargo.toml"
    resolved="$(
      first_midnight_capable_executable \
        "$repo_root/target/debug/zkf" \
        "$repo_root/target/debug/ziros"
    )" || true
    if [[ -n "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  fi

  echo "could not resolve a zkf/ziros CLI binary from env, bundled package, repo-local build, or PATH" >&2
  return 1
}

clear_prepare_sidecars() {
  local root="$1"
  rm -rf \
    "$root/contract" \
    "$root/compiler" \
    "$root/keys" \
    "$root/zkir"
}

snapshot_prepare_assets() {
  local source_root="$1"
  local bundle_root="$2"
  local dir_name
  rm -rf "$bundle_root"
  mkdir -p "$bundle_root"
  for dir_name in contract compiler keys zkir; do
    if [[ -d "$source_root/$dir_name" ]]; then
      cp -R "$source_root/$dir_name" "$bundle_root/$dir_name"
    fi
  done
}

augment_prepare_report() {
  local json_path="$1"
  local bundle_root="$2"
  local compiled_zkir_path="$3"
  if [[ ! -f "$json_path" ]]; then
    return 0
  fi
  local tmp_json
  tmp_json="$(mktemp)"
  jq \
    --arg zkir_path "$compiled_zkir_path" \
    --arg asset_bundle_root "$bundle_root" \
    --arg contract_bundle_root "$bundle_root/contract" \
    --arg compiler_bundle_root "$bundle_root/compiler" \
    --arg keys_bundle_root "$bundle_root/keys" \
    --arg zkir_bundle_root "$bundle_root/zkir" \
    '.zkir_path = $zkir_path
     | .asset_bundle_root = $asset_bundle_root
     | .contract_bundle_root = $contract_bundle_root
     | .compiler_bundle_root = $compiler_bundle_root
     | .keys_bundle_root = $keys_bundle_root
     | .zkir_bundle_root = $zkir_bundle_root' \
    "$json_path" > "$tmp_json"
  mv "$tmp_json" "$json_path"
}

ziros_bin="$(resolve_cli_bin)"

run_ziros() {
  "$ziros_bin" "$@"
}

hash -r
clear_prepare_sidecars "$deploy_reports"
clear_prepare_sidecars "$call_reports"
run_ziros midnight status --json > "$validation_root/midnight_status.json"
if [[ "$(jq -r '.ready' "$validation_root/midnight_status.json")" != "true" ]]; then
  echo "Midnight status is not ready:" >&2
  jq '.blocked_reasons' "$validation_root/midnight_status.json" >&2
  exit 1
fi

gateway_ready_code="$(
  curl -sS \
    -o "$validation_root/gateway_ready.body" \
    -w '%{http_code}' \
    http://127.0.0.1:6311/ready || true
)"
jq -n \
  --arg url "http://127.0.0.1:6311/ready" \
  --arg http_code "${gateway_ready_code:-000}" \
  '{
    url: $url,
    http_code: ($http_code | tonumber? // 0),
    reachable: (($http_code == "200") or ($http_code == "401")),
    auth_required: ($http_code == "401")
  }' > "$validation_root/gateway_ready.json"

while IFS= read -r rel_path; do
  contract_id="$(basename "$rel_path" .compact)"
  source_path="$package_root/$rel_path"
  out_dir="$compile_root/$contract_id"
  mkdir -p "$out_dir"

  run_ziros midnight contract compile \
    --source "$source_path" \
    --out "$out_dir" \
    --network "$network" \
    --json > "$compile_reports/$contract_id.json"

  run_ziros midnight contract deploy-prepare \
    --source "$source_path" \
    --out "$deploy_reports/$contract_id.json" \
    --network "$network" \
    --json > /dev/null
  if [[ -f "$deploy_reports/$contract_id.json" ]]; then
    bundle_root="$deploy_assets/$contract_id"
    snapshot_prepare_assets "$deploy_reports" "$bundle_root"
    zkir_basename="$(
      jq -r '.zkir_path | split("/") | last' "$deploy_reports/$contract_id.json"
    )"
    compiled_zkir_path="$(jq -r '.zkir_path // empty' "$deploy_reports/$contract_id.json")"
    if [[ -n "$zkir_basename" && "$zkir_basename" != "null" ]]; then
      compiled_zkir_path="$compile_root/$contract_id/zkir/$zkir_basename"
    fi
    augment_prepare_report "$deploy_reports/$contract_id.json" "$bundle_root" "$compiled_zkir_path"
  fi
  clear_prepare_sidecars "$deploy_reports"

  admission_code="$(
    curl -sS \
      -o "$admission_root/$contract_id.body" \
      -w '%{http_code}' \
      -H 'content-type: application/json' \
      -d "{\"contract_path\":\"$source_path\",\"contract_name\":\"$(basename "$source_path")\"}" \
      http://127.0.0.1:6311/v1/verify-compact || true
  )"
  jq -n \
    --arg contract_id "$contract_id" \
    --arg source_path "$source_path" \
    --arg http_code "${admission_code:-000}" \
    '{
      contract_id: $contract_id,
      source_path: $source_path,
      http_code: ($http_code | tonumber? // 0),
      admitted: ($http_code == "200"),
      auth_required: ($http_code == "401")
    }' > "$admission_root/$contract_id.json"
done < <(jq -r '.contracts[]' "$package_manifest")

call_count="$(jq '.calls | length' "$flow_manifest")"
for ((index = 0; index < call_count; index++)); do
  call_id="$(jq -r ".calls[$index].call_id" "$flow_manifest")"
  rel_source="$(jq -r ".calls[$index].compact_source" "$flow_manifest")"
  circuit_name="$(jq -r ".calls[$index].circuit_name" "$flow_manifest")"
  contract_id="$(basename "$rel_source" .compact)"
  source_path="$package_root/$rel_source"
  inputs_path="$inputs_root/$call_id.json"
  jq ".calls[$index].inputs" "$flow_manifest" > "$inputs_path"

  run_ziros midnight contract call-prepare \
    --source "$source_path" \
    --call "$circuit_name" \
    --inputs "$inputs_path" \
    --out "$call_reports/$call_id.json" \
    --network "$network" \
    --json > /dev/null
  if [[ -f "$call_reports/$call_id.json" ]]; then
    bundle_root="$call_assets/$call_id"
    snapshot_prepare_assets "$call_reports" "$bundle_root"
    zkir_basename="$(
      jq -r '.zkir_path | split("/") | last' "$call_reports/$call_id.json"
    )"
    compiled_zkir_path="$(jq -r '.zkir_path // empty' "$call_reports/$call_id.json")"
    if [[ -n "$zkir_basename" && "$zkir_basename" != "null" ]]; then
      compiled_zkir_path="$compile_root/$contract_id/zkir/$zkir_basename"
    fi
    augment_prepare_report "$call_reports/$call_id.json" "$bundle_root" "$compiled_zkir_path"
  fi
  clear_prepare_sidecars "$call_reports"
done

jq -n \
  --arg schema "trade-finance-midnight-validation-summary-v1" \
  --arg artifact_layout "$artifact_layout" \
  --arg artifact_root "$artifact_root" \
  --arg package_root "$package_root" \
  --arg network "$network" \
  --slurpfile status "$validation_root/midnight_status.json" \
  --slurpfile ready "$validation_root/gateway_ready.json" \
  --slurpfile package "$package_manifest" \
  --slurpfile flow "$flow_manifest" \
  '{
    schema: $schema,
    artifact_layout: $artifact_layout,
    artifact_root: $artifact_root,
    package_root: $package_root,
    network: $network,
    status: $status[0],
    gateway_ready: $ready[0],
    contract_count: ($package[0].contracts | length),
    call_count: ($flow[0].calls | length),
    contracts: $package[0].contracts,
    call_ids: ($flow[0].calls | map(.call_id)),
    compile_reports_root: "compile",
    deploy_prepare_reports_root: "deploy_prepare",
    call_prepare_reports_root: "call_prepare",
    deploy_prepare_assets_root: "deploy_prepare_assets",
    call_prepare_assets_root: "call_prepare_assets",
    inputs_root: "inputs",
    admission_reports_root: "admission"
  }' > "$validation_root/summary.json"

echo "$validation_root"
