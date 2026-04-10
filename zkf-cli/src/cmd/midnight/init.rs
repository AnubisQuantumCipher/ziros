use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::doctor::{handle_doctor, DoctorArgs};
use super::gateway::{admit_compact_request, VerifyCompactRequest};
use super::shared::{
    compare_project_package_pins, copy_dir_recursive_filtered, copy_file,
    current_timestamp_rfc3339ish, ensure_sed_dapp_root, midnight_template_catalog, network_config,
    node_version, npm_version, read_text, resolve_compactc_binary, template_contract_filename,
    template_contract_source, MidnightNetwork, REQUIRED_COMPACTC_VERSION, REQUIRED_NODE_MAJOR,
};
use crate::util::write_json;

pub(crate) fn handle_init(
    name: String,
    template: String,
    out: Option<PathBuf>,
    network: String,
) -> Result<(), String> {
    let network = MidnightNetwork::parse(&network)?;
    let root = out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&name)
    });
    if root.exists() {
        return Err(format!(
            "refusing to overwrite existing path {}",
            root.display()
        ));
    }

    let template_config = template_scaffold_config(&template)?;
    handle_doctor(DoctorArgs {
        json: false,
        strict: false,
        project: None,
        network: network.as_str().to_string(),
        proof_server_url: None,
        gateway_url: None,
        browser_check: false,
        no_browser_check: true,
        require_wallet: false,
    })?;
    run_preflight_checks(network)?;

    let temp_root = root.with_extension(format!(
        "zkf-midnight-init-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    ));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)
            .map_err(|error| format!("failed to clear {}: {error}", temp_root.display()))?;
    }
    fs::create_dir_all(&temp_root)
        .map_err(|error| format!("failed to create {}: {error}", temp_root.display()))?;

    scaffold_project(&temp_root, &name, &template_config, network)?;

    let admission_path = temp_root.join("data").join("gateway-admission.json");
    let report = admit_compact_request(&VerifyCompactRequest {
        template_id: Some(template.clone()),
        contract_path: Some(
            temp_root
                .join("contracts")
                .join("compact")
                .join(&template_config.contract_file)
                .display()
                .to_string(),
        ),
        contract_source: None,
        contract_name: Some(template_config.contract_file.clone()),
        output_path: Some(admission_path.display().to_string()),
    })?;

    run_command(&temp_root, "npm", &["install"])?;
    run_command(&temp_root, "npm", &["run", "compile-contracts"])?;
    run_command(&temp_root, "npm", &["run", "typecheck"])?;

    let package_report = compare_project_package_pins(&temp_root)?;
    if !package_report.missing.is_empty()
        || !package_report.mismatched.is_empty()
        || !package_report.lock_missing.is_empty()
        || !package_report.lock_mismatched.is_empty()
    {
        return Err(format!(
            "generated project package pins drifted: missing={:?} mismatched={:?} lock_missing={:?} lock_mismatched={:?}",
            package_report.missing,
            package_report.mismatched,
            package_report.lock_missing,
            package_report.lock_mismatched
        ));
    }

    handle_doctor(DoctorArgs {
        json: false,
        strict: false,
        project: Some(temp_root.clone()),
        network: network.as_str().to_string(),
        proof_server_url: None,
        gateway_url: None,
        browser_check: false,
        no_browser_check: true,
        require_wallet: false,
    })?;

    if let Some(parent) = root.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::rename(&temp_root, &root).map_err(|error| {
        format!(
            "failed to finalize scaffold {} -> {}: {error}",
            temp_root.display(),
            root.display()
        )
    })?;
    run_command(&root, "npm", &["run", "build"])?;

    println!(
        "Midnight project created at {} [{} admitted]",
        root.display(),
        report.contract_id
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct TemplateScaffoldConfig {
    template_id: String,
    display_name: String,
    description: String,
    contract_file: String,
    artifact_directory: String,
    circuit_id: String,
    page_href: String,
    ledger_summary_fields: Vec<String>,
    sample_inputs: BTreeMap<String, Value>,
}

fn template_scaffold_config(template_id: &str) -> Result<TemplateScaffoldConfig, String> {
    let catalog = midnight_template_catalog()?;
    let entry = catalog
        .into_iter()
        .find(|entry| entry.template_id == template_id)
        .ok_or_else(|| format!("unknown Midnight template '{template_id}'"))?;
    match template_id {
        "token-transfer" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "token_transfer".to_string(),
            circuit_id: "submitTransfer".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "last_transfer_commitment".to_string(),
                "last_amount".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("amount".to_string(), json!(7)),
                ("senderCommitment".to_string(), json!(11)),
                ("recipientCommitment".to_string(), json!(13)),
            ]),
        }),
        "cooperative-treasury" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "cooperative_treasury".to_string(),
            circuit_id: "proveTreasuryCompliance".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "compliance_status".to_string(),
                "reserve_ratio_adequate".to_string(),
                "treasury_commitment".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("memberContributions".to_string(), json!(1000)),
                ("memberDistributions".to_string(), json!(200)),
                ("reserveBalance".to_string(), json!(300)),
                ("minReserveRatio".to_string(), json!(10)),
                ("maxDistribution".to_string(), json!(90)),
                ("fairnessTolerance".to_string(), json!(4000)),
            ]),
        }),
        "private-voting" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "private_voting".to_string(),
            circuit_id: "submitVoteCommitment".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "latest_vote_commitment".to_string(),
                "election_open".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("candidateCommitment".to_string(), json!(101)),
                ("electionId".to_string(), json!(2026)),
                ("ballotNullifier".to_string(), json!(303)),
            ]),
        }),
        "credential-verification" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "credential_verification".to_string(),
            circuit_id: "verifyCredentialAdmission".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "credential_commitment".to_string(),
                "age_requirement_satisfied".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("subjectCommitment".to_string(), json!(77)),
                ("policyCommitment".to_string(), json!(21)),
                ("ageOverTwentyOne".to_string(), json!(true)),
            ]),
        }),
        "private-auction" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "private_auction".to_string(),
            circuit_id: "submitBidCommitment".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "latest_bid_commitment".to_string(),
                "auction_active".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("bidderCommitment".to_string(), json!(111)),
                ("bidCommitment".to_string(), json!(999)),
                ("auctionId".to_string(), json!(42)),
            ]),
        }),
        "supply-chain-provenance" => Ok(TemplateScaffoldConfig {
            template_id: template_id.to_string(),
            display_name: entry.display_name,
            description: entry.description,
            contract_file: template_contract_filename(template_id),
            artifact_directory: "supply_chain_provenance".to_string(),
            circuit_id: "attestProvenance".to_string(),
            page_href: "/contract".to_string(),
            ledger_summary_fields: vec![
                "provenance_commitment".to_string(),
                "provenance_verified".to_string(),
            ],
            sample_inputs: BTreeMap::from([
                ("productCommitment".to_string(), json!(91)),
                ("batchCommitment".to_string(), json!(92)),
                ("routeCommitment".to_string(), json!(93)),
            ]),
        }),
        _ => Err(format!("unknown Midnight template '{template_id}'")),
    }
}

fn run_preflight_checks(network: MidnightNetwork) -> Result<(), String> {
    let compactc = resolve_compactc_binary().ok_or_else(|| {
        format!(
            "compactc {REQUIRED_COMPACTC_VERSION} is required before `zkf midnight init` can run"
        )
    })?;
    let compactc_version = super::shared::compactc_version(&compactc)?;
    validate_compactc_preflight(&compactc, &compactc_version)?;

    let node = node_version()?;
    validate_node_preflight(&node)?;
    let _ = npm_version()?;

    if network != MidnightNetwork::Offline {
        let config = network_config(network, None, None);
        ensure_http_reachable(&config.rpc_url)?;
        ensure_http_reachable(&config.indexer_url)?;
    }
    Ok(())
}

fn validate_compactc_preflight(compactc: &Path, version: &str) -> Result<(), String> {
    if version != REQUIRED_COMPACTC_VERSION {
        return Err(format!(
            "zkf midnight init requires compactc {}, found {} at {}",
            REQUIRED_COMPACTC_VERSION,
            version,
            compactc.display()
        ));
    }
    Ok(())
}

fn parse_node_major(version: &str) -> Result<u64, String> {
    version
        .split('.')
        .next()
        .and_then(|raw| raw.trim_start_matches('v').parse::<u64>().ok())
        .ok_or_else(|| format!("failed to parse Node.js version: {version}"))
}

fn validate_node_preflight(version: &str) -> Result<(), String> {
    let node_major = parse_node_major(version)?;
    if node_major < REQUIRED_NODE_MAJOR {
        return Err(format!(
            "zkf midnight init requires Node.js {}+, found {}",
            REQUIRED_NODE_MAJOR, version
        ));
    }
    Ok(())
}

fn ensure_http_reachable(url: &str) -> Result<(), String> {
    match ureq::get(url)
        .timeout(std::time::Duration::from_secs(5))
        .call()
    {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(_, _)) => Ok(()),
        Err(error) => Err(format!("{url}: {error}")),
    }
}

fn scaffold_project(
    root: &Path,
    name: &str,
    template: &TemplateScaffoldConfig,
    network: MidnightNetwork,
) -> Result<(), String> {
    let sed_root = ensure_sed_dapp_root()?;
    let dashboard_src = sed_root.join("src/dashboard");
    let midnight_src = sed_root.join("src/midnight");

    for dir in [
        "contracts/compact",
        "src/dashboard/app",
        "src/dashboard/components",
        "src/dashboard/lib",
        "src/midnight",
        "src/deploy",
        "src/onboarding",
        "scripts",
        "data",
    ] {
        fs::create_dir_all(root.join(dir))
            .map_err(|error| format!("failed to create {}: {error}", root.join(dir).display()))?;
    }

    copy_dir_recursive_filtered(
        &dashboard_src.join("components"),
        &root.join("src/dashboard/components"),
        &[],
    )?;
    copy_dir_recursive_filtered(
        &dashboard_src.join("lib"),
        &root.join("src/dashboard/lib"),
        &[],
    )?;
    copy_dir_recursive_filtered(
        &midnight_src,
        &root.join("src/midnight"),
        &["contracts.ts", "config.ts", "witness-data.ts"],
    )?;
    copy_file(
        &dashboard_src.join("next-env.d.ts"),
        &root.join("src/dashboard/next-env.d.ts"),
    )?;
    copy_file(
        &dashboard_src.join("tsconfig.json"),
        &root.join("src/dashboard/tsconfig.json"),
    )?;
    copy_file(&sed_root.join("tsconfig.json"), &root.join("tsconfig.json"))?;

    fs::write(
        root.join("contracts/compact").join(&template.contract_file),
        template_contract_source(&template.template_id)?,
    )
    .map_err(|error| {
        format!(
            "failed to write contract {}: {error}",
            root.join("contracts/compact")
                .join(&template.contract_file)
                .display()
        )
    })?;

    fs::write(
        root.join("sample-inputs.json"),
        serde_json::to_vec_pretty(&json!({
            template.template_id.clone(): template.sample_inputs,
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("failed to write sample-inputs.json: {error}"))?;

    write_json(
        &root.join("data/template-catalog-entry.json"),
        &json!({
            "templateId": template.template_id,
            "displayName": template.display_name,
            "description": template.description,
            "generatedAt": current_timestamp_rfc3339ish(),
        }),
    )?;

    if template.template_id == "cooperative-treasury"
        && sed_root.join("data/deployment-manifest.json").exists()
    {
        copy_file(
            &sed_root.join("data/deployment-manifest.json"),
            &root.join("data/deployment-manifest.json"),
        )?;
    } else {
        write_json(
            &root.join("data/deployment-manifest.json"),
            &json!({
                "network": network.as_str(),
                "networkName": format!("Midnight {}", network.as_str()),
                "deployedAt": current_timestamp_rfc3339ish(),
                "updatedAt": current_timestamp_rfc3339ish(),
                "contracts": [],
            }),
        )?;
    }

    write_text(
        &root.join("src/midnight/contracts.ts"),
        &contracts_ts(template),
    )?;
    write_text(&root.join("src/midnight/config.ts"), &config_ts(network))?;
    write_text(
        &root.join("src/midnight/witness-data.ts"),
        &witness_data_ts(template),
    )?;
    write_text(&root.join("src/midnight/artifacts.ts"), &artifacts_ts())?;
    write_text(&root.join("src/midnight/runtime.ts"), &runtime_ts())?;
    write_text(&root.join("src/deploy/deploy-all.ts"), &deploy_all_ts())?;
    write_text(&root.join("src/deploy/call-all.ts"), &call_all_ts())?;
    write_text(&root.join("src/deploy/config.ts"), &deploy_config_ts())?;
    write_text(
        &root.join("src/onboarding/e2e-smoke.ts"),
        &e2e_smoke_ts(template),
    )?;
    write_text(
        &root.join("src/dashboard/app/layout.tsx"),
        &layout_tsx(name),
    )?;
    write_text(
        &root.join("src/dashboard/app/page.tsx"),
        &home_page_tsx(template),
    )?;
    write_text(
        &root.join("src/dashboard/app/contract/page.tsx"),
        &contract_page_tsx(template),
    )?;
    copy_file(
        &dashboard_src.join("app/api/runtime/route.ts"),
        &root.join("src/dashboard/app/api/runtime/route.ts"),
    )?;
    copy_file(
        &dashboard_src.join("app/api/contracts/[contractKey]/route.ts"),
        &root.join("src/dashboard/app/api/contracts/[contractKey]/route.ts"),
    )?;

    let source_package: Value =
        serde_json::from_str(&read_text(&sed_root.join("package.json"))?)
            .map_err(|error| format!("failed to parse SED package.json: {error}"))?;
    write_json(
        &root.join("package.json"),
        &generated_package_json(name, &source_package),
    )?;
    let env_contents = env_example(network);
    write_text(&root.join(".env.example"), &env_contents)?;
    write_text(&root.join(".env"), &env_contents)?;
    write_text(
        &root.join("next.config.mjs"),
        "export { default } from './src/dashboard/next.config.mjs';\n",
    )?;
    copy_file(
        &dashboard_src.join("next.config.mjs"),
        &root.join("src/dashboard/next.config.mjs"),
    )?;
    write_text(
        &root.join("scripts/compile-contracts.sh"),
        &compile_contracts_sh(),
    )?;
    write_text(
        &root.join("scripts/start-proof-server.sh"),
        &start_proof_server_sh(),
    )?;
    write_text(&root.join("scripts/start-gateway.sh"), &start_gateway_sh())?;
    write_text(&root.join("README.md"), &readme_md(name, template, network))?;

    Ok(())
}

fn run_command(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to run `{program} {}`: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`{program} {}` failed: stdout={}; stderr={}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn generated_package_json(name: &str, source: &Value) -> Value {
    let mut object = source.as_object().cloned().unwrap_or_default();
    object.insert("name".to_string(), Value::String(name.to_string()));
    object.insert(
        "description".to_string(),
        Value::String(format!(
            "{name} -- ZirOS Midnight Developer Platform scaffold"
        )),
    );
    object.insert(
        "scripts".to_string(),
        Value::Object(Map::from_iter([
            (
                "build".to_string(),
                Value::String("npm run typecheck && next build src/dashboard".to_string()),
            ),
            (
                "start".to_string(),
                Value::String("next start src/dashboard".to_string()),
            ),
            (
                "fetch-compactc".to_string(),
                Value::String("fetch-compactc".to_string()),
            ),
            (
                "compile-contracts".to_string(),
                Value::String("bash scripts/compile-contracts.sh".to_string()),
            ),
            (
                "start-proof-server".to_string(),
                Value::String("bash scripts/start-proof-server.sh".to_string()),
            ),
            (
                "start-gateway".to_string(),
                Value::String("bash scripts/start-gateway.sh".to_string()),
            ),
            (
                "deploy".to_string(),
                Value::String("tsx src/deploy/deploy-all.ts".to_string()),
            ),
            (
                "call".to_string(),
                Value::String("tsx src/deploy/call-all.ts".to_string()),
            ),
            (
                "test:e2e".to_string(),
                Value::String("tsx src/onboarding/e2e-smoke.ts".to_string()),
            ),
            (
                "typecheck".to_string(),
                Value::String("tsc --noEmit".to_string()),
            ),
        ])),
    );
    normalize_generated_dependency_versions(&mut object);
    Value::Object(object)
}

fn normalize_generated_dependency_versions(object: &mut Map<String, Value>) {
    for section in ["dependencies", "devDependencies"] {
        let Some(entries) = object.get_mut(section).and_then(Value::as_object_mut) else {
            continue;
        };
        if let Some(version) = entries.get_mut("axios") {
            *version = Value::String("^1.14.0".to_string());
        }
    }
}

fn env_example(network: MidnightNetwork) -> String {
    let network_defaults = network_config(network, None, None);
    let compactc_bin = resolve_compactc_binary()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| format!("/absolute/path/to/compactc-{REQUIRED_COMPACTC_VERSION}"));
    format!(
        "MIDNIGHT_NETWORK={}\nMIDNIGHT_PROVING_MODE=local-zkf-proof-server\nMIDNIGHT_PROOF_SERVER_URL=http://127.0.0.1:6300\nMIDNIGHT_GATEWAY_URL=http://127.0.0.1:6311\nMIDNIGHT_RPC_URL={}\nMIDNIGHT_INDEXER_URL={}\nMIDNIGHT_COMPACT_ARTIFACT_ROOT=./contracts/compiled\nMIDNIGHT_EXPLORER_URL={}\nCOMPACTC_BIN={}\nMIDNIGHT_WALLET_SEED=\nMIDNIGHT_WALLET_MNEMONIC=\nMIDNIGHT_PRIVATE_STATE_PASSWORD=\n",
        network.as_str(),
        network_defaults.rpc_url,
        network_defaults.indexer_url,
        network_defaults.explorer_url,
        compactc_bin,
    )
}

fn compile_contracts_sh() -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS="$SCRIPT_DIR/../contracts/compact"
OUTPUT="$SCRIPT_DIR/../contracts/compiled"
COMPACTC_BIN="${{COMPACTC_BIN:-}}"
ENV_FILE="$SCRIPT_DIR/../.env"

if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
  COMPACTC_BIN="${{COMPACTC_BIN:-}}"
fi

mkdir -p "$OUTPUT"

if [ -z "$COMPACTC_BIN" ]; then
  if command -v compactc >/dev/null 2>&1; then
    COMPACTC_BIN="$(command -v compactc)"
  else
    echo "Error: compactc was not found. Set COMPACTC_BIN to the compactc {required_compactc_version} binary."
    exit 1
  fi
fi

for contract in "$CONTRACTS"/*.compact; do
  [ -f "$contract" ] || continue
  name=$(basename "$contract" .compact)
  echo "Compiling $name..."
  "$COMPACTC_BIN" "$contract" "$OUTPUT/$name/"
done

echo "Compact compilation complete."
"#,
        required_compactc_version = REQUIRED_COMPACTC_VERSION
    )
}

fn start_proof_server_sh() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

PORT="${PROOF_SERVER_PORT:-6300}"
ZKF_BIN="${ZKF_PATH:-zkf}"

exec "$ZKF_BIN" midnight proof-server serve --port "$PORT" --engine umpg
"#
    .to_string()
}

fn start_gateway_sh() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

PORT="${MIDNIGHT_GATEWAY_PORT:-6311}"
ZKF_BIN="${ZKF_PATH:-zkf}"

exec "$ZKF_BIN" midnight gateway serve --port "$PORT"
"#
    .to_string()
}

fn contracts_ts(template: &TemplateScaffoldConfig) -> String {
    format!(
        "export type ContractKey = '{key}';\n\n\
export interface ContractDefinition {{\n  key: ContractKey;\n  artifactDirectory: string;\n  compactSource: string;\n  displayName: string;\n  description: string;\n  pageHref: string;\n  circuitId: string;\n  ledgerSummaryFields: string[];\n}}\n\n\
export const CONTRACTS: ContractDefinition[] = [\n  {{\n    key: '{key}',\n    artifactDirectory: '{artifact_directory}',\n    compactSource: '{contract_file}',\n    displayName: '{display_name}',\n    description: {description:?},\n    pageHref: '{page_href}',\n    circuitId: '{circuit_id}',\n    ledgerSummaryFields: [{ledger_fields}],\n  }},\n];\n\n\
export const CONTRACTS_BY_KEY: Record<ContractKey, ContractDefinition> = Object.fromEntries(\n  CONTRACTS.map((contract) => [contract.key, contract]),\n) as Record<ContractKey, ContractDefinition>;\n\n\
export function isContractKey(value: string): value is ContractKey {{\n  return value in CONTRACTS_BY_KEY;\n}}\n\n\
export function getContractDefinition(contractKey: ContractKey): ContractDefinition {{\n  return CONTRACTS_BY_KEY[contractKey];\n}}\n",
        key = template.template_id,
        artifact_directory = template.artifact_directory,
        contract_file = template.contract_file,
        display_name = template.display_name,
        description = template.description,
        page_href = template.page_href,
        circuit_id = template.circuit_id,
        ledger_fields = template
            .ledger_summary_fields
            .iter()
            .map(|field| format!("{field:?}"))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn config_ts(network: MidnightNetwork) -> String {
    let defaults = network_config(network, None, None);
    format!(
        r#"import {{ setNetworkId, type NetworkId }} from '@midnight-ntwrk/midnight-js-network-id';
import type {{ Configuration as WalletServiceConfiguration }} from '@midnight-ntwrk/dapp-connector-api';

export type MidnightNetwork = 'preprod' | 'preview' | 'local' | 'offline';
export type MidnightProvingMode = 'local-zkf-proof-server' | 'wallet-proving-provider';

export interface MidnightRuntimeConfig {{
  network: MidnightNetwork;
  provingMode: MidnightProvingMode;
  proofServerUrl: string;
  rpcUrl: string;
  indexerUrl: string;
  indexerWsUrl: string;
  compactArtifactRoot: string;
  explorerUrl: string;
  operatorSeed?: string;
  operatorMnemonic?: string;
  privateStatePassword?: string;
  sampleInputsPath: string;
}}

const NETWORK_DEFAULTS: Record<Exclude<MidnightNetwork, 'offline'>, Omit<MidnightRuntimeConfig, 'provingMode' | 'operatorSeed' | 'operatorMnemonic' | 'privateStatePassword' | 'sampleInputsPath'>> = {{
  preprod: {{
    network: 'preprod',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: '{preprod_rpc}',
    indexerUrl: '{preprod_indexer}',
    indexerWsUrl: '{preprod_indexer_ws}',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: '{preprod_explorer}',
  }},
  preview: {{
    network: 'preview',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'https://rpc.preview.midnight.network',
    indexerUrl: 'https://indexer.preview.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'https://explorer.preview.midnight.network',
  }},
  local: {{
    network: 'local',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'http://127.0.0.1:9944',
    indexerUrl: 'http://127.0.0.1:8088/api/v4/graphql',
    indexerWsUrl: 'ws://127.0.0.1:8088/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'http://127.0.0.1:8080',
  }},
}};

function normalizeNetwork(value: string | undefined): MidnightNetwork {{
  if (value === 'preview' || value === 'local' || value === 'offline' || value === 'preprod') {{
    return value;
  }}
  return '{default_network}';
}}

function normalizeProvingMode(value: string | undefined): MidnightProvingMode {{
  return value === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server';
}}

function networkIdForSdk(network: MidnightNetwork): NetworkId {{
  if (network === 'local' || network === 'offline') {{
    return 'preprod' as NetworkId;
  }}
  return network as NetworkId;
}}

export function configureMidnightNetwork(network: MidnightNetwork): void {{
  if (network === 'offline') {{
    return;
  }}
  setNetworkId(networkIdForSdk(network));
}}

export function getRuntimeConfig(overrides: Partial<MidnightRuntimeConfig> = {{}}): MidnightRuntimeConfig {{
  const network = overrides.network ?? normalizeNetwork(process.env.MIDNIGHT_NETWORK);
  const defaults = network === 'offline' ? NETWORK_DEFAULTS.preprod : NETWORK_DEFAULTS[network];
  const config: MidnightRuntimeConfig = {{
    network,
    provingMode: overrides.provingMode ?? normalizeProvingMode(process.env.MIDNIGHT_PROVING_MODE),
    proofServerUrl: overrides.proofServerUrl ?? process.env.MIDNIGHT_PROOF_SERVER_URL ?? defaults.proofServerUrl,
    rpcUrl: overrides.rpcUrl ?? process.env.MIDNIGHT_RPC_URL ?? defaults.rpcUrl,
    indexerUrl: overrides.indexerUrl ?? process.env.MIDNIGHT_INDEXER_URL ?? defaults.indexerUrl,
    indexerWsUrl: overrides.indexerWsUrl ?? process.env.MIDNIGHT_INDEXER_WS_URL ?? defaults.indexerWsUrl,
    compactArtifactRoot: overrides.compactArtifactRoot ?? process.env.MIDNIGHT_COMPACT_ARTIFACT_ROOT ?? defaults.compactArtifactRoot,
    explorerUrl: overrides.explorerUrl ?? process.env.MIDNIGHT_EXPLORER_URL ?? defaults.explorerUrl,
    operatorSeed: overrides.operatorSeed ?? process.env.MIDNIGHT_WALLET_SEED,
    operatorMnemonic: overrides.operatorMnemonic ?? process.env.MIDNIGHT_WALLET_MNEMONIC,
    privateStatePassword: overrides.privateStatePassword ?? process.env.MIDNIGHT_PRIVATE_STATE_PASSWORD,
    sampleInputsPath: overrides.sampleInputsPath ?? process.env.MIDNIGHT_SAMPLE_INPUTS_PATH ?? './sample-inputs.json',
  }};

  configureMidnightNetwork(config.network);
  return config;
}}

export function mergeWalletConfiguration(
  base: MidnightRuntimeConfig,
  walletConfiguration?: Partial<WalletServiceConfiguration> | null,
): MidnightRuntimeConfig {{
  if (!walletConfiguration) {{
    return base;
  }}

  return getRuntimeConfig({{
    ...base,
    network: normalizeNetwork(walletConfiguration.networkId),
    indexerUrl: walletConfiguration.indexerUri ?? base.indexerUrl,
    indexerWsUrl: walletConfiguration.indexerWsUri ?? base.indexerWsUrl,
    rpcUrl: walletConfiguration.substrateNodeUri ?? base.rpcUrl,
    proofServerUrl: walletConfiguration.proverServerUri ?? base.proofServerUrl,
  }});
}}

export function explorerLink(baseUrl: string, txHash?: string, contractAddress?: string): string {{
  if (txHash) {{
    return `${{baseUrl}}/transactions/${{txHash}}`;
  }}
  if (contractAddress) {{
    return `${{baseUrl}}/contracts/${{contractAddress}}`;
  }}
  return baseUrl;
}}

function proofServerPort(proofServerUrl: string): string {{
  try {{
    const parsed = new URL(proofServerUrl);
    return parsed.port || '6300';
  }} catch {{
    return '6300';
  }}
}}

export function proofServerStartCommand(proofServerUrl: string): string {{
  return `zkf midnight proof-server serve --port ${{proofServerPort(proofServerUrl)}} --engine umpg`;
}}

export function proofServerUnavailableMessage(proofServerUrl: string): string {{
  return `Proof server unavailable at ${{proofServerUrl}}. Start it with: ${{proofServerStartCommand(proofServerUrl)}}.`;
}}
"#,
        preprod_rpc = defaults.rpc_url,
        preprod_indexer = defaults.indexer_url,
        preprod_indexer_ws = defaults.indexer_url.replace("https://", "wss://") + "/ws",
        preprod_explorer = defaults.explorer_url,
        default_network = network.as_str(),
    )
}

fn witness_data_ts(_template: &TemplateScaffoldConfig) -> String {
    format!(
        r#"import {{ readFile }} from 'node:fs/promises';
import {{ resolve }} from 'node:path';

import type {{ ContractKey }} from './contracts';
import {{ getRuntimeConfig, type MidnightRuntimeConfig }} from './config';

type JsonMap = Record<string, unknown>;
type ContractSnapshots = Partial<Record<ContractKey, JsonMap>>;
type WitnessFunction = (context: {{ privateState: undefined }}) => [undefined, [bigint]];

function asRecord(value: unknown): JsonMap {{
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonMap) : {{}};
}}

function toBigInt(value: unknown): bigint {{
  if (typeof value === 'bigint') {{
    return value;
  }}
  if (typeof value === 'boolean') {{
    return value ? 1n : 0n;
  }}
  if (typeof value === 'number') {{
    return BigInt(Math.round(value));
  }}
  if (typeof value === 'string') {{
    const trimmed = value.trim();
    if (/^(0x)?[0-9a-fA-F]+$/.test(trimmed)) {{
      return BigInt(trimmed.startsWith('0x') ? trimmed : `0x${{trimmed}}`);
    }}
    return BigInt(Math.round(Number.parseFloat(trimmed) || 0));
  }}
  return 0n;
}}

async function loadSampleInputs(config: MidnightRuntimeConfig = getRuntimeConfig()): Promise<JsonMap> {{
  const raw = await readFile(resolve(config.sampleInputsPath), 'utf-8');
  return JSON.parse(raw) as JsonMap;
}}

async function contractInputs(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig,
): Promise<JsonMap> {{
  const inputs = await loadSampleInputs(config);
  return asRecord(inputs[contractKey] ?? inputs);
}}

export async function buildWitnessValues(
  contractKey: ContractKey,
  options: {{ config?: MidnightRuntimeConfig; inputs?: JsonMap; contractSnapshots?: ContractSnapshots }} = {{}},
): Promise<Record<string, bigint>> {{
  const config = options.config ?? getRuntimeConfig();
  const input = options.inputs ?? (await contractInputs(contractKey, config));
  return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, toBigInt(value)]));
}}

export async function buildCompactWitnesses(
  contractKey: ContractKey,
  options: {{ config?: MidnightRuntimeConfig; inputs?: JsonMap; contractSnapshots?: ContractSnapshots }} = {{}},
): Promise<Record<string, WitnessFunction>> {{
  const values = await buildWitnessValues(contractKey, options);
  return Object.fromEntries(
    Object.entries(values).map(([name, value]) => [
      name,
      ({{ privateState }}: {{ privateState: undefined }}) => [privateState, value],
    ]),
  ) as Record<string, WitnessFunction>;
}}

export async function buildProofWitnessPayload(
  contractKey: ContractKey,
  options: {{ config?: MidnightRuntimeConfig; inputs?: JsonMap; contractSnapshots?: ContractSnapshots }} = {{}},
): Promise<{{ circuit: ContractKey; version: number; inputs: Record<string, string> }}> {{
  const values = await buildWitnessValues(contractKey, options);
  return {{
    circuit: contractKey,
    version: 1,
    inputs: Object.fromEntries(Object.entries(values).map(([key, value]) => [key, value.toString()])),
  }};
}}
"#
    )
}

fn artifacts_ts() -> String {
    r#"import { access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { CONTRACTS, type ContractDefinition, type ContractKey, getContractDefinition } from './contracts';
import { getRuntimeConfig, type MidnightRuntimeConfig } from './config';
import { buildCompactWitnesses } from './witness-data';

export interface ArtifactStatus {
  contract: ContractDefinition;
  artifactDir: string;
  contractModulePath: string;
  ready: boolean;
}

export interface LoadedContractArtifacts {
  contract: ContractDefinition;
  artifactDir: string;
  contractModule: Record<string, unknown>;
  compiledContract: unknown;
  decodeLedgerState: (contractState: unknown) => Record<string, unknown>;
}

async function isReadable(pathname: string): Promise<boolean> {
  try {
    await access(pathname);
    return true;
  } catch {
    return false;
  }
}

async function loadCompactJsModule(): Promise<Record<string, unknown>> {
  const esmEntry = resolve(process.cwd(), 'node_modules/@midnight-ntwrk/compact-js/dist/esm/index.js');
  const moduleUrl = pathToFileURL(esmEntry).href;
  return (await import(moduleUrl)) as Record<string, unknown>;
}

export function resolveArtifactDirectory(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): string {
  return resolve(config.compactArtifactRoot, getContractDefinition(contractKey).artifactDirectory);
}

export async function getArtifactStatus(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<ArtifactStatus> {
  const contract = getContractDefinition(contractKey);
  const artifactDir = resolveArtifactDirectory(contractKey, config);
  const contractModulePath = join(artifactDir, 'contract', 'index.js');
  const keysDir = join(artifactDir, 'keys');
  const zkirDir = join(artifactDir, 'zkir');

  const ready =
    (await isReadable(contractModulePath)) &&
    (await isReadable(keysDir)) &&
    (await isReadable(zkirDir));

  return {
    contract,
    artifactDir,
    contractModulePath,
    ready,
  };
}

export async function listArtifactStatuses(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<ArtifactStatus[]> {
  return Promise.all(CONTRACTS.map((contract) => getArtifactStatus(contract.key, config)));
}

export async function loadCompiledContract(
  contractKey: ContractKey,
  options: {
    config?: MidnightRuntimeConfig;
    contractSnapshots?: Partial<Record<ContractKey, Record<string, unknown>>>;
  } = {},
): Promise<LoadedContractArtifacts> {
  const config = options.config ?? getRuntimeConfig();
  const status = await getArtifactStatus(contractKey, config);

  if (!status.ready) {
    throw new Error(
      `Compiled Midnight artifacts are missing for ${contractKey}. Run "npm run compile-contracts" first.`,
    );
  }

  const moduleUrl = pathToFileURL(status.contractModulePath).href;
  const contractModule = (await import(moduleUrl)) as Record<string, unknown>;
  const contractCtor = contractModule.Contract as never;
  const witnesses = await buildCompactWitnesses(contractKey, {
    config,
    contractSnapshots: options.contractSnapshots,
  });
  const compactJs = await loadCompactJsModule();
  const CompiledContract = compactJs.CompiledContract as {
    make: (artifactDirectory: string, contract: never) => unknown;
    withWitnesses: (witnesses: never) => (value: unknown) => unknown;
    withCompiledFileAssets: (artifactDir: string) => (value: unknown) => unknown;
  };
  const compiled = CompiledContract.make(status.contract.artifactDirectory, contractCtor) as {
    pipe: (...ops: Array<(value: unknown) => unknown>) => unknown;
  };

  const compiledContract = compiled.pipe(
    CompiledContract.withWitnesses(witnesses as never),
    CompiledContract.withCompiledFileAssets(status.artifactDir),
  );

  return {
    contract: status.contract,
    artifactDir: status.artifactDir,
    contractModule,
    compiledContract,
    decodeLedgerState(contractState: unknown) {
      const ledgerDecoder = contractModule.ledger as ((value: unknown) => Record<string, unknown>) | undefined;
      if (!ledgerDecoder) {
        return {};
      }
      const maybeData =
        contractState &&
        typeof contractState === 'object' &&
        'data' in (contractState as Record<string, unknown>)
          ? (contractState as Record<string, unknown>).data
          : contractState;
      return ledgerDecoder(maybeData);
    },
  };
}
"#
    .to_string()
}

fn runtime_ts() -> String {
    r#"import { CONTRACTS, type ContractKey } from './contracts';
import {
  explorerLink,
  getRuntimeConfig,
  proofServerUnavailableMessage,
  type MidnightRuntimeConfig,
} from './config';
import { readDeploymentManifest, type DeploymentManifest, type DeploymentManifestEntry } from './manifest';
import { loadCompiledContract, listArtifactStatuses } from './artifacts';

export interface ContractRuntimeSnapshot {
  key: ContractKey;
  displayName: string;
  description: string;
  pageHref: string;
  deployed: boolean;
  address: string | null;
  txHash: string | null;
  lastCallTxHash: string | null;
  explorerUrl: string;
  artifactReady: boolean;
  publicStateSnapshot: Record<string, unknown> | null;
  error?: string;
}

export interface RuntimeSnapshot {
  generatedAt: string;
  config: {
    network: string;
    provingMode: string;
    proofServerUrl: string;
    rpcUrl: string;
    indexerUrl: string;
    indexerWsUrl: string;
    compactArtifactRoot: string;
    explorerUrl: string;
  };
  proofServer: {
    healthy: boolean;
    error?: string;
  };
  manifest: DeploymentManifest | null;
  contracts: ContractRuntimeSnapshot[];
}

async function healthCheck(url: string): Promise<{ healthy: boolean; error?: string }> {
  try {
    const response = await fetch(`${url.replace(/\/$/, '')}/health`);
    if (!response.ok) {
      return {
        healthy: false,
        error: `${proofServerUnavailableMessage(url)} HTTP ${response.status}.`,
      };
    }
    return { healthy: true };
  } catch (error) {
    return {
      healthy: false,
      error:
        `${proofServerUnavailableMessage(url)} ` +
        (error instanceof Error ? error.message : String(error)),
    };
  }
}

function entryForContract(
  manifest: DeploymentManifest | null,
  contractKey: ContractKey,
): DeploymentManifestEntry | null {
  return manifest?.contracts.find((contract) => contract.name === contractKey) ?? null;
}

async function readContractSnapshot(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig,
  manifest: DeploymentManifest | null,
): Promise<ContractRuntimeSnapshot> {
  const artifactStatuses = await listArtifactStatuses(config);
  const status = artifactStatuses.find((artifact) => artifact.contract.key === contractKey);
  const entry = entryForContract(manifest, contractKey);
  const contract = status!.contract;

  const baseSnapshot: ContractRuntimeSnapshot = {
    key: contract.key,
    displayName: contract.displayName,
    description: contract.description,
    pageHref: contract.pageHref,
    deployed: Boolean(entry?.address),
    address: entry?.address ?? null,
    txHash: entry?.txHash ?? null,
    lastCallTxHash: entry?.lastCallTxHash ?? null,
    explorerUrl: entry?.explorerUrl ?? explorerLink(config.explorerUrl, entry?.txHash, entry?.address),
    artifactReady: Boolean(status?.ready),
    publicStateSnapshot: entry?.publicStateSnapshot ?? null,
  };

  if (!status?.ready || !entry?.address) {
    return baseSnapshot;
  }

  try {
    const loaded = await loadCompiledContract(contractKey, { config });
    const { createPrepareProviders } = await import('./providers');
    const providers = createPrepareProviders(config, loaded.artifactDir, {
      coinPublicKey: '00' as never,
      encryptionPublicKey: '00' as never,
    });
    const rawState = await providers.publicDataProvider.queryContractState(entry.address as never);

    return {
      ...baseSnapshot,
      publicStateSnapshot: rawState ? loaded.decodeLedgerState(rawState) : baseSnapshot.publicStateSnapshot,
    };
  } catch (error) {
    return {
      ...baseSnapshot,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function collectContractSnapshots(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
  manifest?: DeploymentManifest | null,
): Promise<ContractRuntimeSnapshot[]> {
  const resolvedManifest = manifest ?? (await readDeploymentManifest());
  return Promise.all(CONTRACTS.map((contract) => readContractSnapshot(contract.key, config, resolvedManifest)));
}

export async function buildRuntimeSnapshot(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<RuntimeSnapshot> {
  const manifest = await readDeploymentManifest();
  return {
    generatedAt: new Date().toISOString(),
    config: {
      network: config.network,
      provingMode: config.provingMode,
      proofServerUrl: config.proofServerUrl,
      rpcUrl: config.rpcUrl,
      indexerUrl: config.indexerUrl,
      indexerWsUrl: config.indexerWsUrl,
      compactArtifactRoot: config.compactArtifactRoot,
      explorerUrl: config.explorerUrl,
    },
    proofServer: await healthCheck(config.proofServerUrl),
    manifest,
    contracts: await collectContractSnapshots(config, manifest),
  };
}
"#
    .to_string()
}

fn deploy_all_ts() -> String {
    r#"import { pathToFileURL } from 'node:url';

import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from '../midnight/artifacts';
import { CONTRACTS, type ContractKey } from '../midnight/contracts';
import { explorerLink, getRuntimeConfig, type MidnightNetwork, type MidnightProvingMode } from '../midnight/config';
import { upsertDeploymentManifestEntry } from '../midnight/manifest';
import {
  type MidnightWalletProvider,
  buildHeadlessWallet,
  collectDustDiagnostics,
  createDeployProviders,
  formatDust,
  waitForSpendableDust,
} from '../midnight/providers';

export interface DeployAllOptions {
  network?: string;
  provingMode?: MidnightProvingMode;
  manifestPath?: string;
}

function dustSummary(diagnostics: Awaited<ReturnType<typeof collectDustDiagnostics>>): string {
  return (
    `spendable=${formatDust(diagnostics.spendableDustRaw)} DUST ` +
    `(${diagnostics.spendableDustCoins} coin(s)), ` +
    `registered NIGHT=${diagnostics.registeredNightUtxos}`
  );
}

function networkLabel(network: MidnightNetwork): string {
  switch (network) {
    case 'preprod':
      return 'Midnight Preprod';
    case 'preview':
      return 'Midnight Preview';
    case 'local':
      return 'Midnight Local';
    case 'offline':
      return 'Midnight Offline';
  }
}

async function deploySingleContract(
  contractKey: ContractKey,
  options: {
    walletProvider: MidnightWalletProvider;
    network?: string;
    provingMode?: MidnightProvingMode;
    manifestPath?: string;
  },
): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
  });
  const loaded = await loadCompiledContract(contractKey, { config });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    options.walletProvider,
    contractKey,
    config.provingMode,
  );

  const deployed = await deployContract(providers, {
    compiledContract: loaded.compiledContract as never,
    args: [],
  });

  const address = String(deployed.deployTxData.public.contractAddress);
  const txHash = deployed.deployTxData.public.txHash;
  const onChainState = await providers.publicDataProvider.queryContractState(address as never);
  const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : null;
  const deepLink = explorerLink(config.explorerUrl, txHash, address);

  await upsertDeploymentManifestEntry(
    {
      name: contractKey,
      address,
      txHash,
      deployedAt: new Date().toISOString(),
      explorerUrl: deepLink,
      publicStateSnapshot: snapshot,
    },
    {
      network: config.network,
      networkName: networkLabel(config.network),
      manifestPath: options.manifestPath,
    },
  );

  console.log(`${loaded.contract.displayName}`);
  console.log(`  Address:  ${address}`);
  console.log(`  Tx Hash:  ${txHash}`);
  console.log(`  Explorer: ${deepLink}`);
}

export async function deployAll(options: DeployAllOptions = {}): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
  });
  const walletProvider = await buildHeadlessWallet(config);

  try {
    const diagnostics = await collectDustDiagnostics(walletProvider);
    if (diagnostics.spendableDustRaw <= 0n) {
      if (diagnostics.registeredNightUtxos === 0) {
        throw new Error(
          'Operator wallet has no spendable tDUST and no NIGHT UTXOs registered for dust generation.',
        );
      }
      await waitForSpendableDust(walletProvider);
    }

    for (const contract of CONTRACTS) {
      await waitForSpendableDust(walletProvider);
      console.log(`--- Deploying ${contract.displayName} ---`);
      await deploySingleContract(contract.key, { ...options, walletProvider });
      console.log(`Wallet dust: ${dustSummary(await collectDustDiagnostics(walletProvider))}`);
    }
  } finally {
    await walletProvider.stop();
  }
}

const isDirectExecution =
  process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectExecution) {
  deployAll({
    network: process.env.MIDNIGHT_NETWORK,
    provingMode:
      process.env.MIDNIGHT_PROVING_MODE === 'wallet-proving-provider'
        ? 'wallet-proving-provider'
        : 'local-zkf-proof-server',
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
"#
        .to_string()
}

fn call_all_ts() -> String {
    r#"import { pathToFileURL } from 'node:url';

import { createUnprovenCallTx } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from '../midnight/artifacts';
import { CONTRACTS, type ContractKey } from '../midnight/contracts';
import { getRuntimeConfig, type MidnightNetwork, type MidnightProvingMode } from '../midnight/config';
import { readDeploymentManifest, upsertDeploymentManifestEntry } from '../midnight/manifest';
import {
  type MidnightWalletProvider,
  buildHeadlessWallet,
  createDeployProviders,
  waitForSpendableDust,
} from '../midnight/providers';

export interface CallAllOptions {
  network?: string;
  provingMode?: MidnightProvingMode;
  manifestPath?: string;
}

async function callSingleContract(
  contractKey: ContractKey,
  options: {
    walletProvider: MidnightWalletProvider;
    network?: string;
    provingMode?: MidnightProvingMode;
    manifestPath?: string;
  },
): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
  });
  const manifest = await readDeploymentManifest(options.manifestPath);
  const entry = manifest?.contracts.find((value) => value.name === contractKey);
  if (!entry?.address) {
    throw new Error(`Contract ${contractKey} is not deployed. Run "npm run deploy" first.`);
  }

  const loaded = await loadCompiledContract(contractKey, { config });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    options.walletProvider,
    contractKey,
    config.provingMode,
  );
  const callTxData = await createUnprovenCallTx(providers as never, {
    compiledContract: loaded.compiledContract as never,
    contractAddress: entry.address as never,
    circuitId: loaded.contract.circuitId as never,
    args: [],
  } as never);
  const provenTx = await (providers.proofProvider as any).proveTx(callTxData.private.unprovenTx);
  const balancedTx = await (options.walletProvider as any).balanceTx(provenTx);
  const txId = await (options.walletProvider as any).submitTx(balancedTx);
  const txData = await (providers.publicDataProvider as any).watchForTxData(txId as never);
  const onChainState = await (providers.publicDataProvider as any).queryContractState(entry.address as never);
  const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : entry.publicStateSnapshot ?? null;

  await upsertDeploymentManifestEntry(
    {
      ...entry,
      publicStateSnapshot: snapshot,
      lastCallTxHash: txData.txHash,
      lastCallAt: new Date().toISOString(),
    },
    {
      network: config.network,
      networkName: config.network,
      manifestPath: options.manifestPath,
    },
  );

  console.log(`${loaded.contract.displayName}`);
  console.log(`  Address:      ${entry.address}`);
  console.log(`  Last call tx: ${txData.txHash}`);
}

export async function callAll(options: CallAllOptions = {}): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
  });
  const walletProvider = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(walletProvider);
    for (const contract of CONTRACTS) {
      await waitForSpendableDust(walletProvider);
      console.log(`--- Calling ${contract.displayName} ---`);
      await callSingleContract(contract.key, { ...options, walletProvider });
    }
  } finally {
    await walletProvider.stop();
  }
}

const isDirectExecution =
  process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectExecution) {
  callAll({
    network: process.env.MIDNIGHT_NETWORK,
    provingMode:
      process.env.MIDNIGHT_PROVING_MODE === 'wallet-proving-provider'
        ? 'wallet-proving-provider'
        : 'local-zkf-proof-server',
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
"#
    .to_string()
}

fn deploy_config_ts() -> String {
    "export {\n  explorerLink,\n  getRuntimeConfig as getNetworkConfig,\n  type MidnightRuntimeConfig as NetworkConfig,\n  type MidnightNetwork,\n  type MidnightProvingMode,\n} from '../midnight/config';\n".to_string()
}

fn e2e_smoke_ts(template: &TemplateScaffoldConfig) -> String {
    format!(
        r#"import {{ buildRuntimeSnapshot }} from '../midnight/runtime';
import {{ getContractDefinition }} from '../midnight/contracts';

async function main() {{
  const runtime = await buildRuntimeSnapshot();
  const contract = runtime.contracts.find((entry) => entry.key === '{key}');
  if (!contract) {{
    throw new Error('Contract runtime snapshot was not generated.');
  }}
  const definition = getContractDefinition('{key}');
  console.log(JSON.stringify({{
    contractKey: contract.key,
    displayName: definition.displayName,
    proofServerHealthy: runtime.proofServer.healthy,
    artifactReady: contract.artifactReady,
  }}, null, 2));
}}

main().catch((error) => {{
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
}});
"#,
        key = template.template_id
    )
}

fn layout_tsx(name: &str) -> String {
    format!(
        r#"import React from 'react';
import type {{ Metadata }} from 'next';
import Link from 'next/link';

import {{ DashboardProvider }} from '../components/DashboardProvider';
import HeaderStatus from '../components/HeaderStatus';

export const metadata: Metadata = {{
  title: {title:?},
  description: 'ZirOS Midnight Developer Platform scaffold',
}};

const navLinks = [
  {{ href: '/', label: 'Home' }},
  {{ href: '/contract', label: 'Contract' }},
];

export default function RootLayout({{ children }}: {{ children: React.ReactNode }}) {{
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(99,102,241,0.18),_transparent_30%),linear-gradient(180deg,_#030712_0%,_#020617_100%)] text-white antialiased">
        <DashboardProvider>
          <div className="flex min-h-screen">
            <aside className="flex w-64 flex-shrink-0 flex-col border-r border-gray-800/70 bg-black/20 backdrop-blur">
              <div className="border-b border-gray-800/70 px-5 py-5">
                <p className="text-sm font-semibold text-white">{title}</p>
                <p className="text-[11px] text-gray-500">ZirOS Midnight Developer Platform</p>
              </div>
              <nav className="flex-1 px-3 py-4">
                <ul className="space-y-1">
                  {{navLinks.map((link) => (
                    <li key={{link.href}}>
                      <Link
                        href={{link.href}}
                        className="flex items-center gap-3 rounded-xl px-3 py-2 text-sm text-gray-400 transition-colors hover:bg-gray-900/70 hover:text-white"
                      >
                        <span>{{link.label}}</span>
                      </Link>
                    </li>
                  ))}}
                </ul>
              </nav>
            </aside>
            <main className="flex min-w-0 flex-1 flex-col">
              <header className="flex h-16 flex-shrink-0 items-center justify-between border-b border-gray-800/70 px-6 backdrop-blur">
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-[0.32em] text-gray-500">Production transaction flow</p>
                  <h1 className="truncate text-sm font-semibold text-white">
                    Lace connect, ZirOS proof server, Compact admission, Midnight transaction
                  </h1>
                </div>
                <HeaderStatus />
              </header>
              <div className="flex-1 overflow-auto p-6">{{children}}</div>
            </main>
          </div>
        </DashboardProvider>
      </body>
    </html>
  );
}}
"#,
        title = name
    )
}

fn home_page_tsx(template: &TemplateScaffoldConfig) -> String {
    format!(
        r#"'use client';

import Link from 'next/link';

import NightDustStatus from '../components/NightDustStatus';
import {{ useDashboard }} from '../components/DashboardProvider';

export default function DashboardHome() {{
  const {{
    runtime,
    runtimeError,
    wallet,
    walletError,
    loadingRuntime,
    laceAvailable,
    connectingWallet,
    connectWallet,
  }} = useDashboard();

  if (loadingRuntime && !runtime) {{
    return <div className="rounded-2xl border border-gray-800 bg-gray-900/90 p-6 text-sm text-gray-400">Loading runtime snapshot...</div>;
  }}

  if (!runtime) {{
    return <div className="rounded-2xl border border-red-800 bg-red-950/30 p-6 text-sm text-red-200">{{runtimeError ?? 'Runtime snapshot could not be loaded.'}}</div>;
  }}

  const contract = runtime.contracts[0];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.6fr_1fr]">
        <div className="rounded-3xl border border-gray-800 bg-gray-900/90 p-6">
          <p className="text-[10px] uppercase tracking-[0.32em] text-indigo-300">{template_id}</p>
          <h2 className="mt-3 text-3xl font-semibold text-white">{display_name}</h2>
          <p className="mt-3 text-sm leading-6 text-gray-400">{description}</p>

          {{!wallet?.connected && (
            <button
              onClick={{() => void connectWallet()}}
              disabled={{!laceAvailable || connectingWallet}}
              className="mt-6 inline-flex items-center justify-center rounded-xl border border-indigo-600 bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {{laceAvailable ? (connectingWallet ? 'Connecting Lace...' : 'Connect Lace') : 'Lace unavailable'}}
            </button>
          )}}

          <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded-2xl border border-gray-800 bg-gray-950/80 p-4">
              <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500">Network</p>
              <p className="mt-2 text-lg font-semibold text-white">{{runtime.config.network}}</p>
            </div>
            <div className="rounded-2xl border border-gray-800 bg-gray-950/80 p-4">
              <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500">Artifacts</p>
              <p className="mt-2 text-lg font-semibold text-white">{{contract?.artifactReady ? 'Compiled' : 'Missing'}}</p>
            </div>
            <div className="rounded-2xl border border-gray-800 bg-gray-950/80 p-4">
              <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500">Proof server</p>
              <p className="mt-2 text-lg font-semibold text-white">{{runtime.proofServer.healthy ? 'Healthy' : 'Unavailable'}}</p>
            </div>
          </div>

          <div className="mt-6 flex flex-wrap gap-3">
            <Link
              href="/contract"
              className="inline-flex items-center rounded-xl border border-indigo-600 bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500"
            >
              Open Contract
            </Link>
          </div>
        </div>
        <NightDustStatus />
      </div>

      {{(runtimeError || walletError) && (
        <div className="rounded-2xl border border-red-800 bg-red-950/30 p-4 text-sm text-red-200">
          {{runtimeError ?? walletError}}
        </div>
      )}}
    </div>
  );
}}
"#,
        template_id = template.template_id,
        display_name = template.display_name,
        description = template.description,
    )
}

fn contract_page_tsx(template: &TemplateScaffoldConfig) -> String {
    format!(
        r#"import ContractDetailPage from '../../components/ContractDetailPage';

export default function ContractPage() {{
  return <ContractDetailPage contractKey={key:?} />;
}}
"#,
        key = template.template_id
    )
}

fn readme_md(name: &str, template: &TemplateScaffoldConfig, network: MidnightNetwork) -> String {
    format!(
        "# {name}\n\n\
This project was generated by `zkf midnight init` using the `{template_id}` template.\n\n\
## Included\n\n\
- Pinned Midnight package lane\n\
- Native ZirOS Midnight proof server launcher\n\
- Compact admission report at `data/gateway-admission.json`\n\
- Production-mode Next.js dashboard under `src/dashboard/`\n\
- Midnight runtime and deploy helpers under `src/midnight/` and `src/deploy/`\n\n\
## Commands\n\n\
- `npm install`\n\
- `npm run compile-contracts`\n\
- `npm run typecheck`\n\
- `npm run build`\n\
- `npm run start`\n\
- `npm run start-proof-server`\n\
- `npm run start-gateway`\n\
- `npm run deploy`\n\n\
## Defaults\n\n\
- Template: `{template_id}`\n\
- Network: `{network}`\n\
- Circuit: `{circuit_id}`\n\n\
The generated scaffold is production-mode only: `npm run build && npm run start`.\n",
        name = name,
        template_id = template.template_id,
        network = network.as_str(),
        circuit_id = template.circuit_id,
    )
}

fn write_text(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::write(path, content).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn template_scaffold_config_rejects_unknown_template() {
        let error =
            template_scaffold_config("unknown-template").expect_err("unknown template should fail");
        assert!(error.contains("unknown Midnight template"));
    }

    #[test]
    fn compactc_preflight_rejects_wrong_version() {
        let error = validate_compactc_preflight(Path::new("/tmp/compactc"), "0.29.0")
            .expect_err("wrong compactc version should fail");
        assert!(error.contains(REQUIRED_COMPACTC_VERSION));
    }

    #[test]
    fn node_preflight_rejects_old_or_invalid_versions() {
        let old_version =
            validate_node_preflight("v21.9.0").expect_err("old Node.js version should fail");
        assert!(old_version.contains("Node.js"));

        let invalid_version =
            validate_node_preflight("not-a-version").expect_err("invalid Node.js should fail");
        assert!(invalid_version.contains("failed to parse Node.js version"));
    }

    #[test]
    fn generated_package_json_matches_pinned_midnight_package_lane() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manifest = super::super::shared::midnight_package_manifest().expect("manifest");
        let mut dependencies = serde_json::Map::new();
        let mut dev_dependencies = serde_json::Map::new();
        let mut package_lock_packages = serde_json::Map::new();
        package_lock_packages.insert(String::new(), json!({ "name": "midnight-generated" }));

        for pin in &manifest.packages {
            match pin.section.as_str() {
                "dependencies" => {
                    dependencies.insert(pin.name.clone(), json!(pin.version));
                }
                "devDependencies" => {
                    dev_dependencies.insert(pin.name.clone(), json!(pin.version));
                }
                other => panic!("unexpected section {other}"),
            }
            package_lock_packages.insert(
                format!("node_modules/{}", pin.name),
                json!({ "version": pin.version }),
            );
        }

        let generated = generated_package_json(
            "midnight-generated",
            &json!({
                "name": "seed-project",
                "dependencies": dependencies,
                "devDependencies": dev_dependencies,
            }),
        );
        fs::write(
            temp.path().join("package.json"),
            serde_json::to_vec_pretty(&generated).expect("generated package.json"),
        )
        .expect("write package.json");
        fs::write(
            temp.path().join("package-lock.json"),
            serde_json::to_vec_pretty(&json!({
                "name": "midnight-generated",
                "lockfileVersion": 3,
                "packages": package_lock_packages,
            }))
            .expect("package-lock"),
        )
        .expect("write package-lock.json");

        let report = compare_project_package_pins(temp.path()).expect("package pin report");
        assert_eq!(report.required_total, manifest.packages.len());
        assert_eq!(report.matched, manifest.packages.len());
        assert!(report.missing.is_empty());
        assert!(report.mismatched.is_empty());
        assert!(report.lock_missing.is_empty());
        assert!(report.lock_mismatched.is_empty());
    }
}
