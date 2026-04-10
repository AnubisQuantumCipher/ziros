use crate::telemetry::GraphExecutionReport;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zkf_core::artifact::ProofArtifact;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct BackendDelegatedGpuSummary {
    pub classification: &'static str,
    pub direct_gpu_busy_ratio: f64,
    pub artifact_gpu_busy_ratio: f64,
    pub effective_gpu_busy_ratio: f64,
    pub realized_gpu_capable_stages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groth16_msm_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qap_witness_map_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_no_cpu_fallback: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ArtifactStageTelemetry {
    #[serde(default)]
    accelerator: String,
}

fn runtime_direct_gpu_stages(report: &GraphExecutionReport) -> Vec<String> {
    report
        .stage_breakdown()
        .into_iter()
        .filter(|(_, telemetry)| telemetry.gpu_nodes > 0)
        .map(|(stage, _)| stage)
        .collect()
}

fn metadata_value_contains_metal(artifact: &ProofArtifact, key: &str) -> bool {
    artifact
        .metadata
        .get(key)
        .map(|value| value.to_ascii_lowercase().contains("metal"))
        .unwrap_or(false)
}

fn artifact_stage_breakdown(artifact: &ProofArtifact) -> BTreeMap<String, ArtifactStageTelemetry> {
    artifact
        .metadata
        .get("metal_stage_breakdown")
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

fn stage_accelerator_is_metal(
    breakdown: &BTreeMap<String, ArtifactStageTelemetry>,
    stage: &str,
) -> bool {
    breakdown
        .get(stage)
        .map(|telemetry| telemetry.accelerator.starts_with("metal"))
        .unwrap_or(false)
}

pub(crate) fn artifact_gpu_busy_ratio(artifact: Option<&ProofArtifact>) -> f64 {
    artifact
        .and_then(|artifact| artifact.metadata.get("metal_gpu_busy_ratio"))
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
        .max(0.0)
}

pub(crate) fn artifact_realized_gpu_capable_stages(
    artifact: Option<&ProofArtifact>,
) -> Vec<String> {
    let Some(artifact) = artifact else {
        return Vec::new();
    };

    let breakdown = artifact_stage_breakdown(artifact);
    let mut stages = BTreeSet::new();

    let witness_map_metal = stage_accelerator_is_metal(&breakdown, "witness_map")
        || metadata_value_contains_metal(artifact, "qap_witness_map_engine");
    if witness_map_metal {
        stages.insert("fft-ntt".to_string());
        stages.insert("qap-witness-map".to_string());
    }

    let msm_metal = stage_accelerator_is_metal(&breakdown, "msm")
        || stage_accelerator_is_metal(&breakdown, "msm_window")
        || stage_accelerator_is_metal(&breakdown, "groth16_prove_core")
        || metadata_value_contains_metal(artifact, "groth16_msm_engine")
        || metadata_value_contains_metal(artifact, "nova_msm_engine")
        || artifact
            .metadata
            .get("msm_accelerator")
            .is_some_and(|value| value == "metal");
    if msm_metal {
        stages.insert("msm".to_string());
    }

    stages.into_iter().collect()
}

pub(crate) fn effective_realized_gpu_capable_stages(
    report: &GraphExecutionReport,
    artifact: Option<&ProofArtifact>,
) -> Vec<String> {
    let mut stages = BTreeSet::new();
    stages.extend(runtime_direct_gpu_stages(report));
    stages.extend(artifact_realized_gpu_capable_stages(artifact));
    stages.into_iter().collect()
}

pub(crate) fn effective_gpu_stage_busy_ratio(
    report: &GraphExecutionReport,
    artifact: Option<&ProofArtifact>,
) -> f64 {
    report
        .gpu_stage_busy_ratio()
        .max(artifact_gpu_busy_ratio(artifact))
}

pub(crate) fn backend_delegated_gpu_summary(
    report: &GraphExecutionReport,
    artifact: Option<&ProofArtifact>,
) -> Option<BackendDelegatedGpuSummary> {
    let stages = effective_realized_gpu_capable_stages(report, artifact);
    let direct_gpu_busy_ratio = report.gpu_stage_busy_ratio();
    let artifact_gpu_busy_ratio = artifact_gpu_busy_ratio(artifact);
    let effective_gpu_busy_ratio = direct_gpu_busy_ratio.max(artifact_gpu_busy_ratio);

    let classification = if report.gpu_nodes > 0 || direct_gpu_busy_ratio > 0.0 {
        "runtime-direct"
    } else if !stages.is_empty() || artifact_gpu_busy_ratio > 0.0 {
        "backend-delegated"
    } else {
        "none"
    };

    if classification == "none" {
        return None;
    }

    Some(BackendDelegatedGpuSummary {
        classification,
        direct_gpu_busy_ratio,
        artifact_gpu_busy_ratio,
        effective_gpu_busy_ratio,
        realized_gpu_capable_stages: stages,
        groth16_msm_engine: artifact
            .and_then(|value| value.metadata.get("groth16_msm_engine"))
            .cloned(),
        qap_witness_map_engine: artifact
            .and_then(|value| value.metadata.get("qap_witness_map_engine"))
            .cloned(),
        metal_no_cpu_fallback: artifact
            .and_then(|value| value.metadata.get("metal_no_cpu_fallback"))
            .and_then(|value| value.parse::<bool>().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DevicePlacement;
    use crate::memory::NodeId;
    use crate::telemetry::NodeTrace;
    use crate::trust::TrustModel;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use zkf_core::artifact::{BackendKind, ProofArtifact};

    fn report_without_runtime_gpu() -> GraphExecutionReport {
        GraphExecutionReport {
            node_traces: vec![NodeTrace {
                node_id: NodeId::new(),
                op_name: "BackendProve",
                stage_key: "backend-prove".to_string(),
                placement: DevicePlacement::Cpu,
                trust_model: TrustModel::Cryptographic,
                wall_time: Duration::from_secs(1),
                problem_size: None,
                input_bytes: 32,
                output_bytes: 32,
                predicted_cpu_ms: None,
                predicted_gpu_ms: None,
                prediction_confidence: None,
                prediction_observation_count: None,
                input_digest: [0; 8],
                output_digest: [1; 8],
                allocated_bytes_after: 0,
                accelerator_name: Some("BackendProve-arkworks-groth16".to_string()),
                fell_back: false,
                buffer_residency: None,
                delegated: true,
                delegated_backend: Some("arkworks-groth16".to_string()),
            }],
            total_wall_time: Duration::from_secs(1),
            peak_memory_bytes: 0,
            gpu_nodes: 0,
            cpu_nodes: 1,
            delegated_nodes: 1,
            final_trust_model: TrustModel::Cryptographic,
            fallback_nodes: 0,
            watchdog_alerts: Vec::new(),
        }
    }

    fn delegated_artifact() -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt+streamed-reduction".to_string(),
        );
        metadata.insert("metal_gpu_busy_ratio".to_string(), "0.625".to_string());
        metadata.insert("metal_no_cpu_fallback".to_string(), "true".to_string());
        metadata.insert(
            "metal_stage_breakdown".to_string(),
            serde_json::json!({
                "witness_map": {"accelerator": "metal-bn254-ntt+streamed-reduction"},
                "msm_window": {"accelerator": "metal"}
            })
            .to_string(),
        );
        ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "test".to_string(),
            proof: Vec::new(),
            verification_key: Vec::new(),
            public_inputs: Vec::new(),
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        }
    }

    fn delegated_nova_artifact() -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "nova_msm_engine".to_string(),
            "metal-pasta-msm/pallas+vesta".to_string(),
        );
        metadata.insert("msm_accelerator".to_string(), "metal".to_string());
        metadata.insert("metal_gpu_busy_ratio".to_string(), "0.5".to_string());
        metadata.insert("metal_no_cpu_fallback".to_string(), "true".to_string());
        metadata.insert(
            "metal_stage_breakdown".to_string(),
            serde_json::json!({
                "msm": {"accelerator": "metal-pasta-msm"}
            })
            .to_string(),
        );
        ProofArtifact {
            backend: BackendKind::Nova,
            program_digest: "test-nova".to_string(),
            proof: Vec::new(),
            verification_key: Vec::new(),
            public_inputs: Vec::new(),
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        }
    }

    #[test]
    fn delegated_artifact_contributes_realized_gpu_stages() {
        let artifact = delegated_artifact();
        let stages = artifact_realized_gpu_capable_stages(Some(&artifact));
        assert_eq!(stages, vec!["fft-ntt", "msm", "qap-witness-map"]);
        assert_eq!(artifact_gpu_busy_ratio(Some(&artifact)), 0.625);
    }

    #[test]
    fn delegated_nova_artifact_contributes_realized_gpu_msm() {
        let artifact = delegated_nova_artifact();
        let stages = artifact_realized_gpu_capable_stages(Some(&artifact));
        assert_eq!(stages, vec!["msm"]);
        assert_eq!(artifact_gpu_busy_ratio(Some(&artifact)), 0.5);
    }

    #[test]
    fn effective_summary_marks_backend_delegated_gpu() {
        let report = report_without_runtime_gpu();
        let artifact = delegated_artifact();
        let summary = backend_delegated_gpu_summary(&report, Some(&artifact)).expect("gpu summary");

        assert_eq!(summary.classification, "backend-delegated");
        assert_eq!(
            summary.realized_gpu_capable_stages,
            vec!["fft-ntt", "msm", "qap-witness-map"]
        );
        assert_eq!(summary.effective_gpu_busy_ratio, 0.625);
        assert_eq!(summary.metal_no_cpu_fallback, Some(true));
    }
}
