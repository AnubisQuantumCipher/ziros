use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zkf_backends::{
    capabilities_report, metal_runtime_report, runtime_hardware_profile,
    strict_bn254_auto_route_ready_with_runtime, strict_bn254_gpu_stage_coverage,
};
use zkf_keymanager::KeyManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportMatrixRowV1 {
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruthSnapshotV1 {
    pub schema: String,
    pub generated_at: String,
    pub strict_bn254_auto_route_ready: bool,
    pub strict_gpu_stage_coverage: String,
    pub capabilities: Value,
    pub metal: Value,
    pub storage: Value,
    pub keychain: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_matrix_midnight_compact: Option<SupportMatrixRowV1>,
    #[serde(default)]
    pub truth_surfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn collect_truth_snapshot() -> Result<TruthSnapshotV1, String> {
    let metal_report = metal_runtime_report();
    let _runtime_profile = runtime_hardware_profile(&metal_report);
    let strict_bn254_auto_route_ready =
        strict_bn254_auto_route_ready_with_runtime(&metal_report);
    let strict_gpu_stage_coverage = strict_bn254_gpu_stage_coverage(&metal_report);
    let capabilities =
        serde_json::to_value(capabilities_report()).map_err(|error| error.to_string())?;
    let metal = serde_json::to_value(&metal_report).map_err(|error| error.to_string())?;
    let mut warnings = Vec::new();
    let storage = match collect_with_timeout("storage status", || {
        let status = zkf_storage::status().map_err(|error| error.to_string())?;
        serde_json::to_value(status).map_err(|error| error.to_string())
    }) {
        Ok(status) => status,
        Err(error) => {
            warnings.push(format!("storage diagnostics degraded: {error}"));
            json!({
                "status": "degraded",
                "ready": false,
                "error": error,
            })
        }
    };
    let keychain = match collect_with_timeout("keychain audit", || {
        let key_manager = KeyManager::new().map_err(|error| error.to_string())?;
        let audit = key_manager.audit().map_err(|error| error.to_string())?;
        serde_json::to_value(audit).map_err(|error| error.to_string())
    }) {
        Ok(audit) => audit,
        Err(error) => {
            warnings.push(format!("keychain diagnostics degraded: {error}"));
            json!({
                "status": "degraded",
                "healthy": false,
                "error": error,
            })
        }
    };
    let truth_root = locate_truth_root(std::env::current_dir().ok().as_deref());
    let support_matrix_midnight_compact = truth_root
        .as_ref()
        .and_then(|root| read_support_matrix_row(root, "midnight-compact").ok())
        .flatten();
    let truth_surfaces = truth_root
        .as_ref()
        .map(|root| {
            [
                root.join("zkf-ir-spec/verification-ledger.json"),
                root.join(".zkf-completion-status.json"),
                root.join("docs/CANONICAL_TRUTH.md"),
                root.join("support-matrix.json"),
                root.join("forensics"),
            ]
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(TruthSnapshotV1 {
        schema: "zkf-truth-snapshot-v1".to_string(),
        generated_at: now_rfc3339(),
        strict_bn254_auto_route_ready,
        strict_gpu_stage_coverage: format!(
            "{:.0}% strict GPU stage coverage (metal stages: {}; cpu stages: {})",
            strict_gpu_stage_coverage.coverage_ratio * 100.0,
            strict_gpu_stage_coverage.metal_stages.len(),
            strict_gpu_stage_coverage.cpu_stages.len()
        ),
        capabilities,
        metal,
        storage,
        keychain,
        support_matrix_midnight_compact,
        truth_surfaces,
        warnings,
    })
}

fn collect_with_timeout<T, F>(label: &str, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let timeout = diagnostic_timeout();
    thread::spawn(move || {
        let _ = sender.send(operation());
    });
    receiver.recv_timeout(timeout).map_err(|_| {
        format!(
            "{label} timed out after {}s",
            timeout.as_secs()
        )
    })?
}

fn diagnostic_timeout() -> Duration {
    let seconds = std::env::var("ZIROS_TRUTH_DIAGNOSTIC_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3);
    Duration::from_secs(seconds)
}

fn locate_truth_root(start: Option<&Path>) -> Option<PathBuf> {
    let mut current = start.map(Path::to_path_buf);
    while let Some(path) = current {
        if path.join("support-matrix.json").exists()
            && path.join("docs/CANONICAL_TRUTH.md").exists()
            && path.join("zkf-ir-spec/verification-ledger.json").exists()
        {
            return Some(path);
        }
        current = path.parent().map(Path::to_path_buf);
    }
    None
}

fn read_support_matrix_row(root: &Path, id: &str) -> Result<Option<SupportMatrixRowV1>, String> {
    let path = root.join("support-matrix.json");
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let Some(backends) = value.get("backends").and_then(Value::as_array) else {
        return Ok(None);
    };
    let row = backends.iter().find(|candidate| {
        candidate
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|candidate_id| candidate_id == id)
    });
    Ok(row.map(|candidate| SupportMatrixRowV1 {
        id: id.to_string(),
        status: candidate
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        assurance_lane: candidate
            .get("assurance_lane")
            .and_then(Value::as_str)
            .map(str::to_string),
        proof_semantics: candidate
            .get("proof_semantics")
            .and_then(Value::as_str)
            .map(str::to_string),
        notes: candidate.get("notes").and_then(Value::as_str).map(str::to_string),
    }))
}
