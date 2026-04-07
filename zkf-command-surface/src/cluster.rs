use crate::shell::{read_json_file, run_zkf_cli, workspace_root};
use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatusReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub status: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterBenchmarkReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub out_path: String,
    pub report: Value,
}

pub fn status() -> Result<ClusterStatusReportV1, String> {
    let out_path = workspace_root().join("target-local/agent-cluster-status.json");
    let args = vec![
        "cluster".to_string(),
        "status".to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, workspace_root())?;
    let status: Value = serde_json::from_str(&result.stdout).map_err(|error| error.to_string())?;
    Ok(ClusterStatusReportV1 {
        schema: "zkf-cluster-status-v1".to_string(),
        generated_at: now_rfc3339(),
        status: status
            .as_object()
            .cloned()
            .map(Value::Object)
            .unwrap_or_else(|| serde_json::json!({ "raw": result.stdout, "cache_hint": out_path })),
    })
}

pub fn benchmark(out_path: &Path) -> Result<ClusterBenchmarkReportV1, String> {
    let args = vec![
        "cluster".to_string(),
        "benchmark".to_string(),
        "--json".to_string(),
        "--out".to_string(),
        out_path.display().to_string(),
    ];
    run_zkf_cli(&args, workspace_root())?;
    Ok(ClusterBenchmarkReportV1 {
        schema: "zkf-cluster-benchmark-v1".to_string(),
        generated_at: now_rfc3339(),
        out_path: out_path.display().to_string(),
        report: read_json_file(out_path)?,
    })
}
