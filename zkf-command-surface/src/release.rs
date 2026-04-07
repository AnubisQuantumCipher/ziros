use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseEvidenceBundleV1 {
    pub schema: String,
    pub generated_at: String,
    pub session_id: String,
    pub artifact_count: usize,
    pub artifact_paths: Vec<String>,
}

pub fn evidence_bundle(session_id: &str, artifact_paths: &[PathBuf]) -> ReleaseEvidenceBundleV1 {
    ReleaseEvidenceBundleV1 {
        schema: "zkf-release-evidence-bundle-v1".to_string(),
        generated_at: now_rfc3339(),
        session_id: session_id.to_string(),
        artifact_count: artifact_paths.len(),
        artifact_paths: artifact_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    }
}
