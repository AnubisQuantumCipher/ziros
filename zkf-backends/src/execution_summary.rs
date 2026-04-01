use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Groth16ExecutionClassification {
    MetalRealized,
    BelowThreshold,
    MetalDispatchFailed,
    MetalUnavailable,
    CpuSelected,
}

impl Groth16ExecutionClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetalRealized => "metal-realized",
            Self::BelowThreshold => "below-threshold",
            Self::MetalDispatchFailed => "metal-dispatch-failed",
            Self::MetalUnavailable => "metal-unavailable",
            Self::CpuSelected => "cpu-selected",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "metal-realized" => Some(Self::MetalRealized),
            "below-threshold" => Some(Self::BelowThreshold),
            "metal-dispatch-failed" => Some(Self::MetalDispatchFailed),
            "metal-unavailable" => Some(Self::MetalUnavailable),
            "cpu-selected" => Some(Self::CpuSelected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16StageExecutionSummary {
    pub engine: String,
    pub reason: String,
    pub fallback_state: String,
    pub realized_on_metal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_failure: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16MetalThresholdSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msm: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntt: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poseidon2: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_ops: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Groth16ExecutionSummary {
    pub classification: Groth16ExecutionClassification,
    pub metal_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_gpu_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_no_cpu_fallback: Option<bool>,
    pub witness_map: Groth16StageExecutionSummary,
    pub msm: Groth16StageExecutionSummary,
    pub thresholds: Groth16MetalThresholdSummary,
}

fn metadata_bool(metadata: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<bool>().ok())
}

fn metadata_f64(metadata: &BTreeMap<String, String>, key: &str) -> Option<f64> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn threshold_value(raw: &str, key: &str) -> Option<usize> {
    raw.split(',').find_map(|entry| {
        let (name, value) = entry.trim().split_once('=')?;
        (name.trim() == key)
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

fn stage_engine_realizes_metal(engine: &str, accelerator: Option<&str>) -> bool {
    accelerator.is_some_and(|value| value.eq_ignore_ascii_case("metal"))
        || engine.to_ascii_lowercase().contains("metal")
}

pub fn groth16_execution_summary_from_metadata(
    metadata: &BTreeMap<String, String>,
) -> Option<Groth16ExecutionSummary> {
    let has_surface = [
        "groth16_execution_classification",
        "groth16_msm_engine",
        "groth16_msm_reason",
        "msm_accelerator",
        "qap_witness_map_engine",
        "qap_witness_map_reason",
        "metal_thresholds",
    ]
    .iter()
    .any(|key| metadata.contains_key(*key));
    if !has_surface {
        return None;
    }

    let metal_available = metadata_bool(metadata, "metal_available").unwrap_or(false);
    let metal_complete = metadata_bool(metadata, "metal_complete");
    let metal_gpu_busy_ratio = metadata_f64(metadata, "metal_gpu_busy_ratio");
    let metal_no_cpu_fallback = metadata_bool(metadata, "metal_no_cpu_fallback");

    let msm_accelerator = metadata.get("msm_accelerator").cloned();
    let msm_engine = metadata
        .get("groth16_msm_engine")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let msm_reason = metadata
        .get("groth16_msm_reason")
        .cloned()
        .or_else(|| metadata.get("msm_fallback_reason").cloned())
        .unwrap_or_else(|| {
            if stage_engine_realizes_metal(&msm_engine, msm_accelerator.as_deref()) {
                "bn254-groth16-metal-msm".to_string()
            } else if !metal_available {
                "metal-unavailable".to_string()
            } else {
                "cpu-selected".to_string()
            }
        });
    let classification = metadata
        .get("groth16_execution_classification")
        .and_then(|value| Groth16ExecutionClassification::parse(value))
        .unwrap_or_else(|| match msm_reason.as_str() {
            "bn254-groth16-metal-msm" => Groth16ExecutionClassification::MetalRealized,
            "below-threshold" => Groth16ExecutionClassification::BelowThreshold,
            "metal-dispatch-failed" => Groth16ExecutionClassification::MetalDispatchFailed,
            "metal-unavailable" => Groth16ExecutionClassification::MetalUnavailable,
            "cpu-selected" => Groth16ExecutionClassification::CpuSelected,
            _ if stage_engine_realizes_metal(&msm_engine, msm_accelerator.as_deref()) => {
                Groth16ExecutionClassification::MetalRealized
            }
            _ if !metal_available => Groth16ExecutionClassification::MetalUnavailable,
            _ => Groth16ExecutionClassification::CpuSelected,
        });

    let witness_map_engine = metadata
        .get("qap_witness_map_engine")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let witness_map_reason = metadata
        .get("qap_witness_map_reason")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let witness_map_fallback_state = metadata
        .get("qap_witness_map_fallback_state")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let msm_fallback_state = metadata
        .get("groth16_msm_fallback_state")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let thresholds_raw = metadata.get("metal_thresholds").cloned();
    let thresholds = Groth16MetalThresholdSummary {
        profile: metadata.get("metal_threshold_profile").cloned(),
        msm: thresholds_raw
            .as_deref()
            .and_then(|raw| threshold_value(raw, "msm")),
        ntt: thresholds_raw
            .as_deref()
            .and_then(|raw| threshold_value(raw, "ntt")),
        poseidon2: thresholds_raw
            .as_deref()
            .and_then(|raw| threshold_value(raw, "poseidon2")),
        field_ops: thresholds_raw
            .as_deref()
            .and_then(|raw| threshold_value(raw, "field_ops")),
        merkle: thresholds_raw
            .as_deref()
            .and_then(|raw| threshold_value(raw, "merkle")),
        raw: thresholds_raw,
    };

    Some(Groth16ExecutionSummary {
        classification,
        metal_available,
        metal_complete,
        metal_gpu_busy_ratio,
        metal_no_cpu_fallback,
        witness_map: Groth16StageExecutionSummary {
            engine: witness_map_engine.clone(),
            reason: witness_map_reason,
            fallback_state: witness_map_fallback_state,
            realized_on_metal: stage_engine_realizes_metal(&witness_map_engine, None),
            accelerator: stage_engine_realizes_metal(&witness_map_engine, None)
                .then(|| "metal".to_string()),
            dispatch_failure: None,
        },
        msm: Groth16StageExecutionSummary {
            engine: msm_engine.clone(),
            reason: msm_reason,
            fallback_state: msm_fallback_state,
            realized_on_metal: stage_engine_realizes_metal(&msm_engine, msm_accelerator.as_deref()),
            accelerator: msm_accelerator,
            dispatch_failure: metadata.get("groth16_msm_dispatch_failure").cloned(),
        },
        thresholds,
    })
}
