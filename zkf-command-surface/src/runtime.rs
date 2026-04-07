use crate::shell::{read_json_file, run_zkf_cli};
use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeBenchmarkReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub out_path: String,
    pub report: Value,
    pub stdout: String,
    pub stderr: String,
}

pub fn benchmark(
    out_path: &Path,
    cwd: &Path,
    parallel: bool,
    distributed: bool,
) -> Result<RuntimeBenchmarkReportV1, String> {
    let mut args = vec![
        "benchmark".to_string(),
        "--out".to_string(),
        out_path.display().to_string(),
    ];
    if parallel {
        args.push("--parallel".to_string());
    }
    if distributed {
        args.push("--distributed".to_string());
    }
    let result = run_zkf_cli(&args, cwd)?;
    Ok(RuntimeBenchmarkReportV1 {
        schema: "zkf-runtime-benchmark-v1".to_string(),
        generated_at: now_rfc3339(),
        out_path: out_path.display().to_string(),
        report: read_json_file(out_path)?,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
