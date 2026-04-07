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
