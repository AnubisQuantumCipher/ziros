use crate::shell::run_zkf_cli;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemScaffoldReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub name: String,
    pub style: String,
    pub out_dir: String,
    pub manifest_path: String,
    pub completeness_path: String,
    pub release_pin_path: String,
}

pub fn scaffold(
    name: &str,
    style: &str,
    out_dir: Option<&Path>,
    cwd: &Path,
) -> Result<SubsystemScaffoldReportV1, String> {
    let mut args = vec![
        "subsystem".to_string(),
        "scaffold".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--style".to_string(),
        style.to_string(),
        "--json".to_string(),
    ];
    if let Some(out_dir) = out_dir {
        args.push("--out".to_string());
        args.push(out_dir.display().to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem scaffold JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn verify_completeness(root: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "verify-completeness".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem completeness JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn verify_release_pin(pin: &Path, binary: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "verify-release-pin".to_string(),
        "--pin".to_string(),
        pin.display().to_string(),
        "--binary".to_string(),
        binary.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem release-pin JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn validate(root: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "validate".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem validate JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn prove(root: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "prove".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem prove JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn verify(root: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "verify".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem verify JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn bundle_public(root: &Path, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "bundle-public".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem bundle-public JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn deploy_prepare(root: &Path, network: &str, cwd: &Path) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "deploy-prepare".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--network".to_string(),
        network.to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem deploy-prepare JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn call_prepare(
    root: &Path,
    call: &str,
    inputs: &Path,
    network: &str,
    cwd: &Path,
) -> Result<Value, String> {
    let args = vec![
        "subsystem".to_string(),
        "call-prepare".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--call".to_string(),
        call.to_string(),
        "--inputs".to_string(),
        inputs.display().to_string(),
        "--network".to_string(),
        network.to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem call-prepare JSON: {error}; stdout={}",
            result.stdout
        )
    })
}

pub fn evm_export(
    root: &Path,
    evm_target: &str,
    contract_name: Option<&str>,
    cwd: &Path,
) -> Result<Value, String> {
    let mut args = vec![
        "subsystem".to_string(),
        "evm-export".to_string(),
        "--root".to_string(),
        root.display().to_string(),
        "--evm-target".to_string(),
        evm_target.to_string(),
        "--json".to_string(),
    ];
    if let Some(contract_name) = contract_name {
        args.push("--contract-name".to_string());
        args.push(contract_name.to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    serde_json::from_str(&result.stdout).map_err(|error| {
        format!(
            "failed to decode subsystem evm-export JSON: {error}; stdout={}",
            result.stdout
        )
    })
}
