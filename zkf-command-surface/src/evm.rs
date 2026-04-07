use crate::shell::run_zkf_cli;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmVerifierExportReportV1 {
    pub backend: String,
    pub evm_target: String,
    pub artifact_path: String,
    pub solidity_path: String,
    pub contract_name: String,
    pub solidity_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algebraic_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_boundary_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmFoundryProjectBundleV1 {
    pub schema: String,
    pub generated_at: String,
    pub project_root: String,
    pub solidity_path: String,
    pub contract_name: String,
    pub foundry_toml_path: String,
    pub verifier_contract_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmToolStatusV1 {
    pub tool: String,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmDiagnoseReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub ready: bool,
    pub forge: EvmToolStatusV1,
    pub anvil: EvmToolStatusV1,
    pub cast: EvmToolStatusV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
}

fn parse_json<T: for<'de> Deserialize<'de>>(stdout: &str, label: &str) -> Result<T, String> {
    serde_json::from_str(stdout).map_err(|error| {
        format!("failed to decode {label} JSON: {error}; stdout={stdout}")
    })
}

pub fn verifier_export(
    artifact: &Path,
    backend: &str,
    out: &Path,
    contract_name: Option<&str>,
    evm_target: &str,
    cwd: &Path,
) -> Result<EvmVerifierExportReportV1, String> {
    let mut args = vec![
        "evm".to_string(),
        "verifier".to_string(),
        "export".to_string(),
        "--artifact".to_string(),
        artifact.display().to_string(),
        "--backend".to_string(),
        backend.to_string(),
        "--out".to_string(),
        out.display().to_string(),
        "--evm-target".to_string(),
        evm_target.to_string(),
        "--json".to_string(),
    ];
    if let Some(contract_name) = contract_name {
        args.push("--contract-name".to_string());
        args.push(contract_name.to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm verifier export")
}

pub fn estimate_gas(
    backend: &str,
    artifact: Option<&Path>,
    proof_size: Option<usize>,
    evm_target: &str,
    cwd: &Path,
) -> Result<Value, String> {
    let mut args = vec![
        "evm".to_string(),
        "estimate-gas".to_string(),
        "--backend".to_string(),
        backend.to_string(),
        "--evm-target".to_string(),
        evm_target.to_string(),
        "--json".to_string(),
    ];
    if let Some(artifact) = artifact {
        args.push("--artifact".to_string());
        args.push(artifact.display().to_string());
    } else if let Some(proof_size) = proof_size {
        args.push("--proof-size".to_string());
        args.push(proof_size.to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm estimate-gas")
}

pub fn foundry_init(
    solidity: &Path,
    out: &Path,
    contract_name: Option<&str>,
    artifact: Option<&Path>,
    backend: Option<&str>,
    cwd: &Path,
) -> Result<EvmFoundryProjectBundleV1, String> {
    let mut args = vec![
        "evm".to_string(),
        "foundry".to_string(),
        "init".to_string(),
        "--solidity".to_string(),
        solidity.display().to_string(),
        "--out".to_string(),
        out.display().to_string(),
        "--json".to_string(),
    ];
    if let Some(contract_name) = contract_name {
        args.push("--contract-name".to_string());
        args.push(contract_name.to_string());
    }
    if let Some(artifact) = artifact {
        args.push("--artifact".to_string());
        args.push(artifact.display().to_string());
    }
    if let Some(backend) = backend {
        args.push("--backend".to_string());
        args.push(backend.to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm foundry init")
}

pub fn diagnose(project: Option<&Path>, cwd: &Path) -> Result<EvmDiagnoseReportV1, String> {
    let mut args = vec!["evm".to_string(), "diagnose".to_string(), "--json".to_string()];
    if let Some(project) = project {
        args.push("--project".to_string());
        args.push(project.display().to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm diagnose")
}

pub fn test(project: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "evm".to_string(),
        "test".to_string(),
        "--project".to_string(),
        project.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm test")
}

pub fn deploy(
    project: &Path,
    contract: &str,
    rpc_url: Option<&str>,
    private_key: Option<&str>,
    constructor_args: &[String],
    cwd: &Path,
) -> Result<Value, String> {
    let mut args = vec![
        "evm".to_string(),
        "deploy".to_string(),
        "--project".to_string(),
        project.display().to_string(),
        "--contract".to_string(),
        contract.to_string(),
        "--json".to_string(),
    ];
    if let Some(rpc_url) = rpc_url {
        args.push("--rpc-url".to_string());
        args.push(rpc_url.to_string());
    }
    if let Some(private_key) = private_key {
        args.push("--private-key".to_string());
        args.push(private_key.to_string());
    }
    for value in constructor_args {
        args.push("--constructor-arg".to_string());
        args.push(value.clone());
    }
    let result = run_zkf_cli(&args, cwd)?;
    parse_json(&result.stdout, "evm deploy")
}

pub fn call(
    rpc_url: &str,
    to: &str,
    signature: &str,
    args: &[String],
    private_key: Option<&str>,
    send: bool,
    cwd: &Path,
) -> Result<Value, String> {
    let mut argv = vec![
        "evm".to_string(),
        "call".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        "--to".to_string(),
        to.to_string(),
        "--signature".to_string(),
        signature.to_string(),
        "--json".to_string(),
    ];
    if let Some(private_key) = private_key {
        argv.push("--private-key".to_string());
        argv.push(private_key.to_string());
    }
    if send {
        argv.push("--send".to_string());
    }
    for value in args {
        argv.push("--arg".to_string());
        argv.push(value.clone());
    }
    let result = run_zkf_cli(&argv, cwd)?;
    parse_json(&result.stdout, "evm call")
}
