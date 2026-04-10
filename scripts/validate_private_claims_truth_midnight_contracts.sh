#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
artifact_root="${1:-$repo_root/dist/showcases/private_claims_truth_and_settlement}"
network="${2:-preprod}"

canonicalize_target_path() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  printf '%s/%s\n' "$(cd "$(dirname "$target")" && pwd -L)" "$(basename "$target")"
}

artifact_root="$(canonicalize_target_path "$artifact_root")"

package_root="$artifact_root/midnight_package/claims-truth-settlement"
package_manifest="$package_root/package_manifest.json"
flow_manifest="$package_root/flow_manifest.json"
validation_root="$artifact_root/midnight_validation"
compile_root="$validation_root/compiled"
compile_reports="$validation_root/compile"
deploy_reports="$validation_root/deploy_prepare"
call_reports="$validation_root/call_prepare"
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
  echo "jq is required to validate the claims Midnight package" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to validate the claims Midnight package" >&2
  exit 1
fi

mkdir -p \
  "$compile_root" \
  "$compile_reports" \
  "$deploy_reports" \
  "$call_reports" \
  "$inputs_root" \
  "$admission_root"

if [[ -z "${COMPACTC_BIN:-}" && -x "$HOME/.compact/versions/0.30.0/aarch64-darwin/compactc" ]]; then
  export COMPACTC_BIN="$HOME/.compact/versions/0.30.0/aarch64-darwin/compactc"
fi
if [[ -n "${COMPACTC_BIN:-}" && -x "${COMPACTC_BIN}" ]]; then
  export PATH="$(dirname "${COMPACTC_BIN}"):$PATH"
fi

ziros_bin=""
if [[ -f "$repo_root/Cargo.toml" ]]; then
  cargo build -q -p zkf-cli --manifest-path "$repo_root/Cargo.toml"
  if [[ -x "$repo_root/target/debug/ziros" ]]; then
    ziros_bin="$repo_root/target/debug/ziros"
  fi
fi
if [[ -z "$ziros_bin" ]]; then
  ziros_bin="$(command -v ziros || true)"
fi
if [[ -z "$ziros_bin" ]]; then
  echo "could not resolve a ziros binary or repo-local zkf-cli build" >&2
  exit 1
fi

run_ziros() {
  "$ziros_bin" "$@"
}

hash -r
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
done

jq -n \
  --arg schema "claims-truth-midnight-validation-summary-v1" \
  --arg artifact_root "$artifact_root" \
  --arg package_root "$package_root" \
  --arg network "$network" \
  --slurpfile status "$validation_root/midnight_status.json" \
  --slurpfile ready "$validation_root/gateway_ready.json" \
  --slurpfile package "$package_manifest" \
  --slurpfile flow "$flow_manifest" \
  '{
    schema: $schema,
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
    inputs_root: "inputs",
    admission_reports_root: "admission"
  }' > "$validation_root/summary.json"

echo "$validation_root"
