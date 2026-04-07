use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CliInvocationResult {
    pub stdout: String,
    pub stderr: String,
}

pub fn run_zkf_cli(args: &[String], cwd: &Path) -> Result<CliInvocationResult, String> {
    let binary = resolve_zkf_cli_binary()?;
    let output = Command::new(&binary)
        .current_dir(cwd)
        .args(args.iter().map(OsString::from))
        .output()
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(format!(
            "{} {} failed with status {}: stdout={stdout}; stderr={stderr}",
            binary.display(),
            args.join(" "),
            output.status,
        ));
    }
    Ok(CliInvocationResult { stdout, stderr })
}

pub fn read_json_file(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

pub fn search_path(binary_name: &str) -> Option<PathBuf> {
    let path_env = env::var_os("PATH")?;
    for entry in env::split_paths(&path_env) {
        let candidate = entry.join(binary_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn resolve_zkf_cli_binary() -> Result<PathBuf, String> {
    if let Some(override_path) = env::var_os("ZKF_AGENT_ZKF_BIN") {
        let path = PathBuf::from(override_path);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "ZKF_AGENT_ZKF_BIN points to a missing binary: {}",
            path.display()
        ));
    }

    if let Ok(current) = env::current_exe()
        && current
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name == "zkf-cli" || name == "zkf")
    {
        return Ok(current);
    }

    for candidate in [
        workspace_root().join("target-local/debug/zkf-cli"),
        workspace_root().join("target/debug/zkf-cli"),
        workspace_root().join("target-local/release/zkf-cli"),
        workspace_root().join("target/release/zkf-cli"),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    for binary_name in ["zkf-cli", "zkf"] {
        if let Some(path) = search_path(binary_name) {
            return Ok(path);
        }
    }

    Err(
        "failed to locate the zkf CLI binary; build the workspace or set ZKF_AGENT_ZKF_BIN"
            .to_string(),
    )
}

pub fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
}
