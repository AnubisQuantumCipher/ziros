use crate::shell::{run_zkf_cli, workspace_root};
use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmStatusReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub status: Value,
}

pub fn status() -> Result<SwarmStatusReportV1, String> {
    let args = vec![
        "swarm".to_string(),
        "status".to_string(),
        "--json".to_string(),
    ];
    let result = run_zkf_cli(&args, workspace_root())?;
    Ok(SwarmStatusReportV1 {
        schema: "zkf-swarm-status-v1".to_string(),
        generated_at: now_rfc3339(),
        status: serde_json::from_str(&result.stdout).map_err(|error| error.to_string())?,
    })
}
