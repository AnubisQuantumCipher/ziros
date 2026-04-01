// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
use libcrux_ml_dsa::ml_dsa_87::{MLDSA87SigningKey, MLDSA87VerificationKey, generate_key_pair};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_core::{FieldElement, Program};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

use crate::util::{read_json, sha256_hex};

pub(crate) const REQUIRED_COMPACT_MANAGER_VERSION: &str = "0.5.1";
pub(crate) const REQUIRED_COMPACTC_VERSION: &str = "0.30.0";
pub(crate) const REQUIRED_COMPACT_RUNTIME_VERSION: &str = "0.15.0";
pub(crate) const REQUIRED_COMPACT_JS_VERSION: &str = "2.5.0";
pub(crate) const REQUIRED_MIDNIGHT_JS_VERSION: &str = "4.0.2";
pub(crate) const REQUIRED_DAPP_CONNECTOR_API_VERSION: &str = "4.0.1";
pub(crate) const REQUIRED_LEDGER_WIRE_COMPAT_VERSION: &str = "8.0.3";
pub(crate) const REQUIRED_NODE_MAJOR: u64 = 22;
pub(crate) const DEFAULT_PROOF_SERVER_URL: &str = "http://127.0.0.1:6300";
pub(crate) const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:6311";
pub(crate) const DEFAULT_SED_DAPP_ROOT: &str =
    "/Users/sicarii/Desktop/ziros-sovereign-economic-defense/dapp";
pub(crate) const MIDNIGHT_GATEWAY_ML_DSA_CONTEXT: &[u8] = b"zkf-midnight-gateway-v1";

const MIDNIGHT_PACKAGE_MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/midnight-package-manifest.json"
));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MidnightPackagePinV1 {
    pub name: String,
    pub version: String,
    pub section: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MidnightPackageManifestV1 {
    pub schema: String,
    pub compact: String,
    pub compactc: String,
    pub compact_runtime: String,
    pub compact_js: String,
    pub midnight_js: String,
    pub dapp_connector_api: String,
    pub ledger_wire_compat: String,
    pub node_major: u64,
    #[serde(default)]
    pub packages: Vec<MidnightPackagePinV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightTemplateCatalogEntryV1 {
    pub schema: String,
    pub template_id: String,
    pub display_name: String,
    pub description: String,
    pub backend_lane: String,
    #[serde(default)]
    pub compact_asset_paths: Vec<String>,
    #[serde(default)]
    pub role_views: Vec<String>,
    #[serde(default)]
    pub gateway_sample_vectors: Vec<String>,
    #[serde(default)]
    pub package_pins: Vec<String>,
    pub release_ready: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MidnightNetwork {
    Preprod,
    Preview,
    Local,
    Offline,
}

impl MidnightNetwork {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "preprod" => Ok(Self::Preprod),
            "preview" => Ok(Self::Preview),
            "local" => Ok(Self::Local),
            "offline" => Ok(Self::Offline),
            other => Err(format!(
                "unknown Midnight network '{other}' (expected preprod, preview, local, or offline)"
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Preprod => "preprod",
            Self::Preview => "preview",
            Self::Local => "local",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightNetworkConfig {
    pub network: String,
    pub rpc_url: String,
    pub indexer_url: String,
    pub explorer_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightProjectPackageReport {
    pub required_total: usize,
    pub matched: usize,
    #[serde(default)]
    pub missing: Vec<String>,
    #[serde(default)]
    pub mismatched: Vec<String>,
    #[serde(default)]
    pub lock_missing: Vec<String>,
    #[serde(default)]
    pub lock_mismatched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightGatewayAttestorKeyFileV1 {
    pub version: u32,
    pub ml_dsa87_signing_key: Vec<u8>,
    pub ml_dsa87_public_key: Vec<u8>,
}

impl MidnightGatewayAttestorKeyFileV1 {
    pub(crate) fn signing_key(&self) -> Result<MLDSA87SigningKey, String> {
        let bytes: [u8; MLDSA87SigningKey::len()] = self
            .ml_dsa87_signing_key
            .as_slice()
            .try_into()
            .map_err(|_| "Midnight gateway ML-DSA-87 private key is corrupt".to_string())?;
        Ok(MLDSA87SigningKey::new(bytes))
    }

    pub(crate) fn public_key(&self) -> Result<MLDSA87VerificationKey, String> {
        let bytes: [u8; MLDSA87VerificationKey::len()] = self
            .ml_dsa87_public_key
            .as_slice()
            .try_into()
            .map_err(|_| "Midnight gateway ML-DSA-87 public key is corrupt".to_string())?;
        Ok(MLDSA87VerificationKey::new(bytes))
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        let _ = self.signing_key()?;
        let _ = self.public_key()?;
        Ok(())
    }
}

fn pinned_package(name: &str, version: &str, section: &str) -> MidnightPackagePinV1 {
    MidnightPackagePinV1 {
        name: name.to_string(),
        version: version.to_string(),
        section: section.to_string(),
    }
}

fn expected_midnight_package_pins() -> Vec<MidnightPackagePinV1> {
    vec![
        pinned_package(
            "@midnight-ntwrk/compact-js",
            REQUIRED_COMPACT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/compact-runtime",
            REQUIRED_COMPACT_RUNTIME_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/dapp-connector-api",
            REQUIRED_DAPP_CONNECTOR_API_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/ledger-v8",
            REQUIRED_LEDGER_WIRE_COMPAT_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-contracts",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-http-client-proof-provider",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-indexer-public-data-provider",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-level-private-state-provider",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-network-id",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-node-zk-config-provider",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-types",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-utils",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/testkit-js",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-address-format",
            "3.1.0",
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-capabilities",
            "3.2.0",
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-dust-wallet",
            "3.0.0",
            "dependencies",
        ),
        pinned_package("@midnight-ntwrk/wallet-sdk-facade", "3.0.0", "dependencies"),
        pinned_package("@midnight-ntwrk/wallet-sdk-hd", "3.0.1", "dependencies"),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-indexer-client",
            "1.2.0",
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-shielded",
            "2.1.0",
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/wallet-sdk-unshielded-wallet",
            "2.1.0",
            "dependencies",
        ),
        pinned_package(
            "@midnight-ntwrk/midnight-js-compact",
            REQUIRED_MIDNIGHT_JS_VERSION,
            "devDependencies",
        ),
    ]
}

fn expected_midnight_package_manifest() -> MidnightPackageManifestV1 {
    MidnightPackageManifestV1 {
        schema: "zkf-midnight-package-manifest-v1".to_string(),
        compact: REQUIRED_COMPACT_MANAGER_VERSION.to_string(),
        compactc: REQUIRED_COMPACTC_VERSION.to_string(),
        compact_runtime: REQUIRED_COMPACT_RUNTIME_VERSION.to_string(),
        compact_js: REQUIRED_COMPACT_JS_VERSION.to_string(),
        midnight_js: REQUIRED_MIDNIGHT_JS_VERSION.to_string(),
        dapp_connector_api: REQUIRED_DAPP_CONNECTOR_API_VERSION.to_string(),
        ledger_wire_compat: REQUIRED_LEDGER_WIRE_COMPAT_VERSION.to_string(),
        node_major: REQUIRED_NODE_MAJOR,
        packages: expected_midnight_package_pins(),
    }
}

pub(crate) fn expected_midnight_package_count() -> usize {
    expected_midnight_package_pins().len()
}

pub(crate) fn expected_midnight_package_pin_strings() -> Vec<String> {
    expected_midnight_package_pins()
        .into_iter()
        .map(|entry| format!("{}@{}", entry.name, entry.version))
        .collect()
}

pub(crate) fn expected_midnight_package_lane_label() -> String {
    format!(
        "{} @midnight-ntwrk packages pinned to the March 2026 lane",
        expected_midnight_package_count()
    )
}

pub(crate) fn expected_midnight_package_total_label() -> String {
    format!(
        "{} pinned @midnight-ntwrk packages",
        expected_midnight_package_count()
    )
}

fn validate_midnight_package_manifest(manifest: &MidnightPackageManifestV1) -> Result<(), String> {
    let expected = expected_midnight_package_manifest();
    if manifest != &expected {
        return Err(
            "embedded Midnight package manifest drifted from the pinned shared.rs lane".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn midnight_package_manifest() -> Result<MidnightPackageManifestV1, String> {
    let manifest: MidnightPackageManifestV1 = serde_json::from_str(MIDNIGHT_PACKAGE_MANIFEST_JSON)
        .map_err(|error| format!("failed to parse Midnight package manifest: {error}"))?;
    validate_midnight_package_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn midnight_template_catalog() -> Result<Vec<MidnightTemplateCatalogEntryV1>, String> {
    let _ = midnight_package_manifest()?;
    let package_pins = expected_midnight_package_pin_strings();
    Ok(vec![
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "token-transfer".to_string(),
            display_name: "Token Transfer".to_string(),
            description: "Midnight-native token transfer starter with a pinned ZirOS proof server lane and SED-style dashboard shell.".to_string(),
            backend_lane: "midnight-native-contract+ziros-proof-server".to_string(),
            compact_asset_paths: vec!["contracts/compact/token_transfer.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins: package_pins.clone(),
            release_ready: true,
        },
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "cooperative-treasury".to_string(),
            display_name: "Cooperative Treasury".to_string(),
            description: "Reuse the shipped SED cooperative treasury contract, selective-disclosure runtime, and deployment evidence lane.".to_string(),
            backend_lane: "sed-circuit-1+midnight-compact".to_string(),
            compact_asset_paths: vec!["contracts/compact/cooperative_treasury.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins: package_pins.clone(),
            release_ready: true,
        },
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "private-voting".to_string(),
            display_name: "Private Voting".to_string(),
            description: "Anonymous voting scaffold bound to a Compact commitment contract and the existing ZirOS private-vote lane.".to_string(),
            backend_lane: "ziros-private-vote+midnight-compact".to_string(),
            compact_asset_paths: vec!["contracts/compact/private_voting.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins: package_pins.clone(),
            release_ready: true,
        },
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "credential-verification".to_string(),
            display_name: "Credential Verification".to_string(),
            description: "Private identity and age-gating scaffold with an honest Groth16-labeled proof lane and Compact admission contract.".to_string(),
            backend_lane: "ziros-private-identity+midnight-compact".to_string(),
            compact_asset_paths: vec!["contracts/compact/credential_verification.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins: package_pins.clone(),
            release_ready: true,
        },
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "private-auction".to_string(),
            display_name: "Private Auction".to_string(),
            description: "Sealed-bid auction starter with a Compact commitment contract and ZirOS selective-disclosure dashboard lane.".to_string(),
            backend_lane: "ziros-poseidon-commitment+midnight-compact".to_string(),
            compact_asset_paths: vec!["contracts/compact/private_auction.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins: package_pins.clone(),
            release_ready: true,
        },
        MidnightTemplateCatalogEntryV1 {
            schema: "zkf-midnight-template-catalog-entry-v1".to_string(),
            template_id: "supply-chain-provenance".to_string(),
            display_name: "Supply Chain Provenance".to_string(),
            description: "Selective-disclosure provenance scaffold backed by a Compact attestation contract and ZirOS provenance-style proof lane.".to_string(),
            backend_lane: "ziros-provenance+midnight-compact".to_string(),
            compact_asset_paths: vec!["contracts/compact/supply_chain_provenance.compact".to_string()],
            role_views: vec![
                "public".to_string(),
                "reviewer".to_string(),
                "operator".to_string(),
            ],
            gateway_sample_vectors: vec!["generated-smoke-vector".to_string()],
            package_pins,
            release_ready: true,
        },
    ])
}

pub(crate) fn network_config(
    network: MidnightNetwork,
    proof_server_url: Option<&str>,
    gateway_url: Option<&str>,
) -> MidnightNetworkConfig {
    let _ = (proof_server_url, gateway_url);
    match network {
        MidnightNetwork::Preprod | MidnightNetwork::Offline => MidnightNetworkConfig {
            network: network.as_str().to_string(),
            rpc_url: "https://rpc.preprod.midnight.network".to_string(),
            indexer_url: "https://indexer.preprod.midnight.network/api/v4/graphql".to_string(),
            explorer_url: "https://explorer.preprod.midnight.network".to_string(),
        },
        MidnightNetwork::Preview => MidnightNetworkConfig {
            network: "preview".to_string(),
            rpc_url: "https://rpc.preview.midnight.network".to_string(),
            indexer_url: "https://indexer.preview.midnight.network/api/v4/graphql".to_string(),
            explorer_url: "https://explorer.preview.midnight.network".to_string(),
        },
        MidnightNetwork::Local => MidnightNetworkConfig {
            network: "local".to_string(),
            rpc_url: "http://127.0.0.1:9944".to_string(),
            indexer_url: "http://127.0.0.1:8088/api/v4/graphql".to_string(),
            explorer_url: "http://127.0.0.1:8080".to_string(),
        },
    }
}

pub(crate) fn locate_midnight_project_root(provided: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = provided {
        let normalized = if path.is_file() {
            path.parent().unwrap_or(path).to_path_buf()
        } else {
            path.to_path_buf()
        };
        return find_ancestor_with_file(&normalized, "package.json");
    }
    env::current_dir()
        .ok()
        .and_then(|cwd| find_ancestor_with_file(&cwd, "package.json"))
}

fn find_ancestor_with_file(start: &Path, file_name: &str) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join(file_name).exists() {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

pub(crate) fn compare_project_package_pins(
    project_root: &Path,
) -> Result<MidnightProjectPackageReport, String> {
    let manifest = midnight_package_manifest()?;
    let package_json: Value = read_json(&project_root.join("package.json"))?;
    let package_lock: Option<Value> = read_json(&project_root.join("package-lock.json")).ok();
    let package_versions = collect_package_json_versions(&package_json);
    let lock_versions = package_lock
        .as_ref()
        .map(collect_package_lock_versions)
        .unwrap_or_default();

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    let mut lock_missing = Vec::new();
    let mut lock_mismatched = Vec::new();
    let mut matched = 0usize;

    for pin in &manifest.packages {
        match package_versions.get(&pin.name) {
            Some(found) if found == &pin.version => {
                matched += 1;
            }
            Some(found) => mismatched.push(format!(
                "{} (expected {}, found {})",
                pin.name, pin.version, found
            )),
            None => missing.push(pin.name.clone()),
        }

        match lock_versions.get(&pin.name) {
            Some(found) if found == &pin.version => {}
            Some(found) => lock_mismatched.push(format!(
                "{} (expected {}, found {})",
                pin.name, pin.version, found
            )),
            None => lock_missing.push(pin.name.clone()),
        }
    }

    Ok(MidnightProjectPackageReport {
        required_total: manifest.packages.len(),
        matched,
        missing,
        mismatched,
        lock_missing,
        lock_mismatched,
    })
}

fn collect_package_json_versions(value: &Value) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(map) = value.get(section).and_then(Value::as_object) {
            for (name, version) in map {
                if name.starts_with("@midnight-ntwrk/") {
                    if let Some(version) = version.as_str() {
                        versions.insert(name.clone(), version.to_string());
                    }
                }
            }
        }
    }
    versions
}

fn collect_package_lock_versions(value: &Value) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (key, package) in packages {
            let Some(name) = key.strip_prefix("node_modules/") else {
                continue;
            };
            if !name.starts_with("@midnight-ntwrk/") {
                continue;
            }
            if let Some(version) = package.get("version").and_then(Value::as_str) {
                versions.insert(name.to_string(), version.to_string());
            }
        }
    }
    if versions.is_empty() {
        collect_package_lock_versions_v1(value.get("dependencies"))
    } else {
        versions
    }
}

fn collect_package_lock_versions_v1(root: Option<&Value>) -> BTreeMap<String, String> {
    fn visit(
        prefix: Option<&str>,
        value: &Value,
        out: &mut BTreeMap<String, String>,
        seen: &mut BTreeSet<String>,
    ) {
        let Some(map) = value.as_object() else {
            return;
        };
        for (name, node) in map {
            let resolved_name = match prefix {
                Some(parent) if name.starts_with('@') => format!("{parent}/{name}"),
                _ => name.clone(),
            };
            if resolved_name.starts_with("@midnight-ntwrk/")
                && seen.insert(resolved_name.clone())
                && let Some(version) = node.get("version").and_then(Value::as_str)
            {
                out.insert(resolved_name.clone(), version.to_string());
            }
            if let Some(children) = node.get("dependencies") {
                let next_prefix = resolved_name
                    .starts_with("@midnight-ntwrk")
                    .then_some(resolved_name.as_str());
                visit(next_prefix, children, out, seen);
            }
        }
    }

    let mut out = BTreeMap::new();
    let mut seen = BTreeSet::new();
    if let Some(root) = root {
        visit(None, root, &mut out, &mut seen);
    }
    out
}

pub(crate) fn resolve_compactc_binary() -> Option<PathBuf> {
    if let Some(path) = env::var_os("COMPACTC_BIN").map(PathBuf::from)
        && is_executable_file(&path)
    {
        return Some(path);
    }

    if let Some(path) = search_path_for_binary("compactc") {
        return Some(path);
    }

    let home = env::var_os("HOME").map(PathBuf::from)?;
    let versions_root = home.join(".compact").join("versions");
    let platform = compact_platform_directory();
    let required = versions_root
        .join(REQUIRED_COMPACTC_VERSION)
        .join(platform)
        .join("compactc");
    if is_executable_file(&required) {
        return Some(required);
    }

    let mut versions = fs::read_dir(&versions_root)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let raw = name.to_str()?;
            let parsed = Version::parse(raw).ok()?;
            Some((parsed, entry.path()))
        })
        .collect::<Vec<_>>();
    versions.sort_by(|left, right| right.0.cmp(&left.0));
    for (_, version_dir) in versions {
        let candidate = version_dir.join(platform).join("compactc");
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn resolve_compact_manager_binary() -> Option<PathBuf> {
    search_path_for_binary("compact")
}

pub(crate) fn compactc_version(path: &Path) -> Result<String, String> {
    binary_version(path, ["--version"])
}

pub(crate) fn compact_manager_version(path: &Path) -> Result<String, String> {
    binary_version(path, ["compile", "--version"])
}

pub(crate) fn binary_version<I, S>(binary: &Path, args: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with status {}",
            binary.display(),
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("{} returned non-utf8 output: {error}", binary.display()))?;
    extract_semver_token(&stdout).ok_or_else(|| {
        format!(
            "failed to parse a semantic version from {} output: {}",
            binary.display(),
            stdout.trim()
        )
    })
}

pub(crate) fn node_version() -> Result<String, String> {
    search_path_for_binary("node")
        .ok_or_else(|| "node was not found on PATH".to_string())
        .and_then(|path| binary_version(&path, ["--version"]))
}

pub(crate) fn npm_version() -> Result<String, String> {
    search_path_for_binary("npm")
        .ok_or_else(|| "npm was not found on PATH".to_string())
        .and_then(|path| binary_version(&path, ["--version"]))
}

fn extract_semver_token(raw: &str) -> Option<String> {
    raw.split_whitespace()
        .map(|token| token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.'))
        .find_map(|token| {
            let normalized = token.trim_start_matches('v');
            Version::parse(normalized)
                .ok()
                .map(|_| normalized.to_string())
        })
}

fn compact_platform_directory() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "aarch64-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "x86_64-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "x86_64-linux"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "aarch64-linux"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        "unsupported-platform"
    }
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|entry| entry.join(name))
        .find(|candidate| is_executable_file(candidate))
}

pub(crate) fn sed_dapp_root() -> PathBuf {
    env::var_os("ZIROS_SED_DAPP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SED_DAPP_ROOT))
}

pub(crate) fn ensure_sed_dapp_root() -> Result<PathBuf, String> {
    let root = sed_dapp_root();
    if !root.exists() {
        return Err(format!("SED DApp root does not exist: {}", root.display()));
    }
    Ok(root)
}

pub(crate) fn copy_dir_recursive_filtered(
    source: &Path,
    destination: &Path,
    skip_names: &[&str],
) -> Result<(), String> {
    let metadata = fs::metadata(source)
        .map_err(|error| format!("failed to stat {}: {error}", source.display()))?;
    if !metadata.is_dir() {
        return Err(format!("expected directory at {}", source.display()));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create {}: {error}", destination.display()))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?
    {
        let entry =
            entry.map_err(|error| format!("failed to iterate {}: {error}", source.display()))?;
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if skip_names.iter().any(|skip| skip == &file_name.as_ref()) {
            continue;
        }
        let destination_path = destination.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|error| format!("failed to stat {}: {error}", entry_path.display()))?
            .is_dir()
        {
            copy_dir_recursive_filtered(&entry_path, &destination_path, skip_names)?;
        } else {
            copy_file(&entry_path, &destination_path)?;
        }
    }
    Ok(())
}

pub(crate) fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::copy(source, destination).map_err(|error| {
        format!(
            "failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

pub(crate) fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

pub(crate) fn current_timestamp_rfc3339ish() -> String {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("{unix_seconds}Z")
}

pub(crate) fn midnight_gateway_attestor_key_path() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home
        .join(".zkf")
        .join("state")
        .join("midnight-gateway-attestor-v1.json"))
}

pub(crate) fn load_or_create_gateway_attestor() -> Result<MidnightGatewayAttestorKeyFileV1, String>
{
    let path = midnight_gateway_attestor_key_path()?;
    if path.exists() {
        let key_file: MidnightGatewayAttestorKeyFileV1 = read_json(&path)?;
        key_file.validate()?;
        return Ok(key_file);
    }

    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    let key_file = MidnightGatewayAttestorKeyFileV1 {
        version: 1,
        ml_dsa87_signing_key: keypair.signing_key.as_slice().to_vec(),
        ml_dsa87_public_key: keypair.verification_key.as_slice().to_vec(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let content = serde_json::to_vec_pretty(&key_file).map_err(|error| error.to_string())?;
    fs::write(&path, content).map_err(|error| format!("{}: {error}", path.display()))?;
    key_file.validate()?;
    Ok(key_file)
}

pub(crate) fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

pub(crate) fn compile_compact_contract(
    source_path: &Path,
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let compactc = resolve_compactc_binary().ok_or_else(|| {
        format!("compactc was not found; install compactc {REQUIRED_COMPACTC_VERSION} first")
    })?;
    let version = compactc_version(&compactc)?;
    if version != REQUIRED_COMPACTC_VERSION {
        return Err(format!(
            "compactc {} is installed at {}, but {} is required",
            version,
            compactc.display(),
            REQUIRED_COMPACTC_VERSION
        ));
    }

    fs::create_dir_all(out_dir)
        .map_err(|error| format!("failed to create {}: {error}", out_dir.display()))?;
    let output = Command::new(&compactc)
        .arg(source_path)
        .arg(out_dir)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", compactc.display()))?;
    if !output.status.success() {
        return Err(format!(
            "compactc failed for {}: stdout={}; stderr={}",
            source_path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    discover_first_zkir(out_dir).ok_or_else(|| {
        format!(
            "compactc succeeded for {} but no .zkir file was emitted under {}",
            source_path.display(),
            out_dir.display()
        )
    })
}

fn discover_first_zkir(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).ok()?.filter_map(Result::ok) {
                stack.push(entry.path());
            }
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "zkir")
        {
            return Some(path);
        }
    }
    None
}

pub(crate) fn import_compact_program(zkir_path: &Path) -> Result<Program, String> {
    let value = serde_json::json!({
        "zkir_path": zkir_path.display().to_string(),
    });
    let frontend = frontend_for(FrontendKind::Compact);
    frontend
        .compile_to_ir(
            &value,
            &FrontendImportOptions {
                source_path: Some(zkir_path.to_path_buf()),
                ..FrontendImportOptions::default()
            },
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn poseidon_commitment_from_bytes(bytes: &[u8]) -> Result<String, String> {
    let digest = sha256_hex(bytes);
    let raw = hex_to_bytes(&digest)?;
    let mut lanes = [FieldElement::ZERO; 4];
    for (index, lane) in lanes.iter_mut().enumerate() {
        let start = index * 8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&raw[start..start + 8]);
        *lane = FieldElement::from_u64(u64::from_be_bytes(chunk));
    }
    zkf_lib::poseidon_hash4_bn254(&lanes).map(|value| value.to_string())
}

pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string has an odd length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&hex[offset..offset + 2], 16)
                .map_err(|error| format!("invalid hex at offset {offset}: {error}"))
        })
        .collect()
}

pub(crate) fn template_contract_filename(template_id: &str) -> String {
    template_id.replace('-', "_") + ".compact"
}

pub(crate) fn template_contract_source(template_id: &str) -> Result<String, String> {
    match template_id {
        "cooperative-treasury" => read_text(
            &ensure_sed_dapp_root()?.join("contracts/compact/cooperative_treasury.compact"),
        ),
        "token-transfer" => Ok(r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger last_transfer_commitment: Bytes<32>;
export ledger last_amount: Uint<64>;

witness amount(): Uint<64>;
witness senderCommitment(): Uint<64>;
witness recipientCommitment(): Uint<64>;

export circuit submitTransfer(): [] {
  const amt = amount();
  const sender = senderCommitment();
  const recipient = recipientCommitment();
  const commitment = persistentHash<[Uint<64>, Uint<64>, Uint<64>, Uint<64>]>(
    disclose([amt, sender, recipient, 0])
  );
  last_transfer_commitment = disclose(commitment);
  last_amount = disclose(amt);
}
"#
        .to_string()),
        "private-voting" => Ok(r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger latest_vote_commitment: Bytes<32>;
export ledger election_open: Boolean;

witness candidateCommitment(): Uint<64>;
witness electionId(): Uint<64>;
witness ballotNullifier(): Uint<64>;

export circuit submitVoteCommitment(): [] {
  const candidate = candidateCommitment();
  const election = electionId();
  const nullifier = ballotNullifier();
  const commitment = persistentHash<[Uint<64>, Uint<64>, Uint<64>, Uint<64>]>(
    disclose([candidate, election, nullifier, 0])
  );
  latest_vote_commitment = disclose(commitment);
  election_open = disclose(true);
}
"#
        .to_string()),
        "credential-verification" => Ok(r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger credential_commitment: Bytes<32>;
export ledger age_requirement_satisfied: Boolean;

witness subjectCommitment(): Uint<64>;
witness policyCommitment(): Uint<64>;
witness ageOverTwentyOne(): Boolean;

export circuit verifyCredentialAdmission(): [] {
  const subject = subjectCommitment();
  const policy = policyCommitment();
  const ageSatisfied = ageOverTwentyOne();
  const commitment = persistentHash<[Uint<64>, Uint<64>, Boolean, Uint<64>]>(
    disclose([subject, policy, ageSatisfied, 0])
  );
  credential_commitment = disclose(commitment);
  age_requirement_satisfied = disclose(ageSatisfied);
}
"#
        .to_string()),
        "private-auction" => Ok(r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger latest_bid_commitment: Bytes<32>;
export ledger auction_active: Boolean;

witness bidderCommitment(): Uint<64>;
witness bidCommitment(): Uint<64>;
witness auctionId(): Uint<64>;

export circuit submitBidCommitment(): [] {
  const bidder = bidderCommitment();
  const bid = bidCommitment();
  const auction = auctionId();
  const commitment = persistentHash<[Uint<64>, Uint<64>, Uint<64>, Uint<64>]>(
    disclose([bidder, bid, auction, 0])
  );
  latest_bid_commitment = disclose(commitment);
  auction_active = disclose(true);
}
"#
        .to_string()),
        "supply-chain-provenance" => Ok(r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger provenance_commitment: Bytes<32>;
export ledger provenance_verified: Boolean;

witness productCommitment(): Uint<64>;
witness batchCommitment(): Uint<64>;
witness routeCommitment(): Uint<64>;

export circuit attestProvenance(): [] {
  const product = productCommitment();
  const batch = batchCommitment();
  const route = routeCommitment();
  const commitment = persistentHash<[Uint<64>, Uint<64>, Uint<64>, Uint<64>]>(
    disclose([product, batch, route, 0])
  );
  provenance_commitment = disclose(commitment);
  provenance_verified = disclose(true);
}
"#
        .to_string()),
        other => Err(format!("unknown Midnight template '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_project_package_files(
        root: &Path,
        package_json: &serde_json::Value,
        package_lock: &serde_json::Value,
    ) {
        fs::write(
            root.join("package.json"),
            serde_json::to_vec_pretty(package_json).expect("package.json"),
        )
        .expect("write package.json");
        fs::write(
            root.join("package-lock.json"),
            serde_json::to_vec_pretty(package_lock).expect("package-lock.json"),
        )
        .expect("write package-lock.json");
    }

    #[test]
    fn embedded_midnight_package_manifest_matches_pinned_lane() {
        let manifest = midnight_package_manifest().expect("manifest");

        assert_eq!(manifest, expected_midnight_package_manifest());
        assert_eq!(manifest.packages.len(), expected_midnight_package_count());
    }

    #[test]
    fn compare_project_package_pins_accepts_matching_project() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manifest = midnight_package_manifest().expect("manifest");

        let mut dependencies = serde_json::Map::new();
        let mut dev_dependencies = serde_json::Map::new();
        let mut package_lock_packages = serde_json::Map::new();
        package_lock_packages.insert(String::new(), json!({ "name": "midnight-test-project" }));
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

        write_project_package_files(
            temp.path(),
            &json!({
                "name": "midnight-test-project",
                "dependencies": dependencies,
                "devDependencies": dev_dependencies,
            }),
            &json!({
                "name": "midnight-test-project",
                "lockfileVersion": 3,
                "packages": package_lock_packages,
            }),
        );

        let report = compare_project_package_pins(temp.path()).expect("package pin report");
        assert_eq!(report.required_total, manifest.packages.len());
        assert_eq!(report.matched, manifest.packages.len());
        assert!(report.missing.is_empty());
        assert!(report.mismatched.is_empty());
        assert!(report.lock_missing.is_empty());
        assert!(report.lock_mismatched.is_empty());
    }
}
