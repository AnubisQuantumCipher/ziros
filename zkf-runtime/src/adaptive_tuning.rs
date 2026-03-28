use crate::swarm::current_bias;
use crate::telemetry::{GraphExecutionReport, NodeTrace};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::MetalThresholdConfig;
use zkf_core::{DeviceFormFactor, PlatformCapability, PowerMode};

const MIN_OBSERVATIONS_FOR_OVERRIDE: u64 = 20;
const EMA_ALPHA: f64 = 0.2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AdaptiveStageState {
    pub observations: u64,
    pub gpu_win_observations: u64,
    pub cpu_win_observations: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_win_size_ema: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_win_size_ema: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_threshold: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AdaptiveTuningState {
    pub schema: String,
    pub platform_key: String,
    pub updated_at_unix_ms: u128,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stages: BTreeMap<String, AdaptiveStageState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveTuningStatus {
    pub enabled: bool,
    pub platform_key: String,
    pub base_thresholds: MetalThresholdConfig,
    pub learned_thresholds: MetalThresholdConfig,
    pub runtime_thresholds: MetalThresholdConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub observation_counts: BTreeMap<String, u64>,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StageTimingPrediction {
    pub cpu_ms: f64,
    pub gpu_ms: f64,
    pub confidence: f64,
    pub observation_count: u64,
}

pub struct AdaptiveThresholdScope {
    platform: PlatformCapability,
    base_thresholds: MetalThresholdConfig,
    learned_thresholds: MetalThresholdConfig,
    runtime_thresholds: MetalThresholdConfig,
    enabled: bool,
}

impl AdaptiveThresholdScope {
    pub fn enter() -> Self {
        let platform = PlatformCapability::detect();
        let base_thresholds = zkf_backends::current_metal_thresholds();
        let enabled = !static_thresholds_disabled();
        let learned_thresholds = if enabled {
            resolved_thresholds(&platform, base_thresholds)
        } else {
            base_thresholds
        };
        let swarm_bias = current_bias();
        let runtime_thresholds = if enabled {
            apply_swarm_bias(
                apply_runtime_bias(&platform, learned_thresholds),
                swarm_bias,
            )
        } else {
            base_thresholds
        };

        if enabled {
            zkf_backends::set_learned_metal_thresholds(Some(learned_thresholds));
            zkf_backends::set_runtime_metal_threshold_override(Some(runtime_thresholds));
        } else {
            zkf_backends::set_learned_metal_thresholds(None);
            zkf_backends::set_runtime_metal_threshold_override(None);
        }

        Self {
            platform,
            base_thresholds,
            learned_thresholds,
            runtime_thresholds,
            enabled,
        }
    }

    pub fn finish(&mut self, report: &GraphExecutionReport) {
        if !self.enabled {
            return;
        }
        if let Err(err) = record_graph_observations(&self.platform, self.base_thresholds, report) {
            log::warn!("failed to update adaptive tuning state: {err}");
        }
        zkf_backends::set_runtime_metal_threshold_override(None);
    }

    pub fn status(&self) -> AdaptiveTuningStatus {
        let state = load_state(&self.platform);
        AdaptiveTuningStatus {
            enabled: self.enabled,
            platform_key: self.platform.platform_key(),
            base_thresholds: self.base_thresholds,
            learned_thresholds: self.learned_thresholds,
            runtime_thresholds: self.runtime_thresholds,
            observation_counts: state
                .stages
                .into_iter()
                .map(|(stage, state)| (stage, state.observations))
                .collect(),
            source: if self.enabled {
                "adaptive".to_string()
            } else {
                "static".to_string()
            },
        }
    }
}

impl Drop for AdaptiveThresholdScope {
    fn drop(&mut self) {
        zkf_backends::set_runtime_metal_threshold_override(None);
    }
}

pub fn adaptive_tuning_status() -> AdaptiveTuningStatus {
    let platform = PlatformCapability::detect();
    let base_thresholds = zkf_backends::current_metal_thresholds();
    let learned_thresholds = resolved_thresholds(&platform, base_thresholds);
    let runtime_thresholds = if static_thresholds_disabled() {
        base_thresholds
    } else {
        apply_swarm_bias(
            apply_runtime_bias(&platform, learned_thresholds),
            current_bias(),
        )
    };
    let state = load_state(&platform);

    AdaptiveTuningStatus {
        enabled: !static_thresholds_disabled(),
        platform_key: platform.platform_key(),
        base_thresholds,
        learned_thresholds,
        runtime_thresholds,
        observation_counts: state
            .stages
            .into_iter()
            .map(|(stage, state)| (stage, state.observations))
            .collect(),
        source: if static_thresholds_disabled() {
            "static".to_string()
        } else {
            "adaptive".to_string()
        },
    }
}

fn apply_swarm_bias(thresholds: MetalThresholdConfig, swarm_bias: f64) -> MetalThresholdConfig {
    let scale = swarm_bias.max(1.0);
    MetalThresholdConfig {
        msm: ((thresholds.msm as f64) * scale).round().max(1.0) as usize,
        ntt: ((thresholds.ntt as f64) * scale).round().max(1.0) as usize,
        poseidon2: ((thresholds.poseidon2 as f64) * scale).round().max(1.0) as usize,
        field_ops: ((thresholds.field_ops as f64) * scale).round().max(1.0) as usize,
        merkle: ((thresholds.merkle as f64) * scale).round().max(1.0) as usize,
    }
}

pub fn resolved_thresholds(
    platform: &PlatformCapability,
    base_thresholds: MetalThresholdConfig,
) -> MetalThresholdConfig {
    if static_thresholds_disabled() {
        return base_thresholds;
    }
    let state = load_state(platform);
    apply_stage_thresholds(&state, base_thresholds)
}

pub fn heuristic_stage_cpu_ms(stage: &str, problem_size: usize) -> f64 {
    stage_timing_prediction(stage, problem_size).cpu_ms
}

pub fn heuristic_stage_gpu_ms(stage: &str, problem_size: usize) -> f64 {
    stage_timing_prediction(stage, problem_size).gpu_ms
}

pub fn stage_timing_prediction(stage: &str, problem_size: usize) -> StageTimingPrediction {
    let scale = (problem_size.max(1) as f64).log2().max(1.0);
    let (cpu_fixed_ms, cpu_var_ms, gpu_fixed_ms, gpu_var_ms) = stage_cost_model(stage);
    let stage_key = threshold_stage(stage);
    let (confidence, observation_count) = if let Some(stage_key) = stage_key {
        let state = load_state(&PlatformCapability::detect());
        let observations = state
            .stages
            .get(stage_key)
            .map(|entry| entry.observations)
            .unwrap_or_default();
        (
            if observations == 0 {
                base_prediction_confidence(stage)
            } else {
                ((observations as f64) / (MIN_OBSERVATIONS_FOR_OVERRIDE as f64))
                    .clamp(base_prediction_confidence(stage), 1.0)
            },
            observations,
        )
    } else {
        (base_prediction_confidence(stage), 0)
    };

    StageTimingPrediction {
        cpu_ms: cpu_fixed_ms + (scale * cpu_var_ms),
        gpu_ms: gpu_fixed_ms + (scale * gpu_var_ms),
        confidence,
        observation_count,
    }
}

fn record_graph_observations(
    platform: &PlatformCapability,
    base_thresholds: MetalThresholdConfig,
    report: &GraphExecutionReport,
) -> Result<(), String> {
    let mut state = load_state(platform);
    for trace in &report.node_traces {
        let Some(stage) = threshold_stage(&trace.stage_key) else {
            continue;
        };
        let Some(problem_size) = trace.problem_size.or_else(|| fallback_problem_size(trace)) else {
            continue;
        };
        let observed_ms = trace.wall_time.as_secs_f64() * 1_000.0;
        let predicted_cpu_ms = trace
            .predicted_cpu_ms
            .unwrap_or_else(|| heuristic_stage_cpu_ms(&trace.stage_key, problem_size));
        let predicted_gpu_ms = trace
            .predicted_gpu_ms
            .unwrap_or_else(|| heuristic_stage_gpu_ms(&trace.stage_key, problem_size));
        let gpu_faster = if trace.placement == crate::graph::DevicePlacement::Gpu {
            observed_ms <= predicted_cpu_ms
        } else {
            predicted_gpu_ms < observed_ms
        };

        let stage_state = state.stages.entry(stage.to_string()).or_default();
        stage_state.observations += 1;
        if gpu_faster {
            stage_state.gpu_win_observations += 1;
            stage_state.gpu_win_size_ema = Some(update_ema(
                stage_state.gpu_win_size_ema,
                problem_size as f64,
            ));
        } else {
            stage_state.cpu_win_observations += 1;
            stage_state.cpu_win_size_ema = Some(update_ema(
                stage_state.cpu_win_size_ema,
                problem_size as f64,
            ));
        }
        if stage_state.observations >= MIN_OBSERVATIONS_FOR_OVERRIDE {
            let base = threshold_for_stage(base_thresholds, stage);
            stage_state.learned_threshold = Some(compute_learned_threshold(base, stage_state));
        }
    }
    state.updated_at_unix_ms = unix_time_now_ms();
    write_state(platform, &state)
}

fn apply_stage_thresholds(
    state: &AdaptiveTuningState,
    mut thresholds: MetalThresholdConfig,
) -> MetalThresholdConfig {
    for (stage, stage_state) in &state.stages {
        if stage_state.observations < MIN_OBSERVATIONS_FOR_OVERRIDE {
            continue;
        }
        let Some(learned_threshold) = stage_state.learned_threshold else {
            continue;
        };
        match stage.as_str() {
            "msm" => thresholds.msm = learned_threshold,
            "ntt" => thresholds.ntt = learned_threshold,
            "poseidon2" => thresholds.poseidon2 = learned_threshold,
            "field_ops" => thresholds.field_ops = learned_threshold,
            "merkle" => thresholds.merkle = learned_threshold,
            _ => {}
        }
    }
    thresholds
}

fn apply_runtime_bias(
    platform: &PlatformCapability,
    mut thresholds: MetalThresholdConfig,
) -> MetalThresholdConfig {
    let high_perf = platform.thermal_envelope.power_mode == PowerMode::HighPerformance;
    let mut scale = 1.0f64;
    // Low-power mode (or powermode=1) — raise thresholds significantly.
    if platform.thermal_envelope.low_power_mode {
        scale *= 1.75;
    }
    if platform.thermal_envelope.thermal_pressure.unwrap_or(0.0) >= 0.50 {
        scale *= 1.35;
    }
    if platform.thermal_envelope.cpu_speed_limit.unwrap_or(1.0) < 0.90 {
        scale *= 1.20;
    }
    if matches!(
        platform.identity.form_factor,
        DeviceFormFactor::Mobile | DeviceFormFactor::Headset
    ) {
        scale *= 1.60;
    }
    // Battery penalty only when NOT in high-performance mode.
    // High-performance mode means the user explicitly wants full clocks on battery.
    if platform.thermal_envelope.battery_present
        && !platform.thermal_envelope.on_external_power
        && !high_perf
    {
        scale *= 1.15;
    }
    if (scale - 1.0).abs() < f64::EPSILON {
        return thresholds;
    }
    thresholds.msm = scaled_threshold(thresholds.msm, scale);
    thresholds.ntt = scaled_threshold(thresholds.ntt, scale);
    thresholds.poseidon2 = scaled_threshold(thresholds.poseidon2, scale);
    thresholds.field_ops = scaled_threshold(thresholds.field_ops, scale);
    thresholds.merkle = scaled_threshold(thresholds.merkle, scale);
    thresholds
}

fn threshold_for_stage(thresholds: MetalThresholdConfig, stage: &str) -> usize {
    match stage {
        "msm" => thresholds.msm,
        "ntt" => thresholds.ntt,
        "poseidon2" => thresholds.poseidon2,
        "field_ops" => thresholds.field_ops,
        "merkle" => thresholds.merkle,
        _ => thresholds.ntt,
    }
}

fn compute_learned_threshold(base: usize, state: &AdaptiveStageState) -> usize {
    let max_threshold = base.saturating_mul(16).max(base);
    match (state.gpu_win_size_ema, state.cpu_win_size_ema) {
        (Some(gpu), Some(cpu)) => (((gpu + cpu) / 2.0).round() as usize).clamp(16, max_threshold),
        (Some(gpu), None) => (gpu.round() as usize).clamp(16, base.max(16)),
        (None, Some(cpu)) => (cpu.round() as usize).clamp(base.max(16), max_threshold),
        _ => base,
    }
}

fn update_ema(current: Option<f64>, sample: f64) -> f64 {
    match current {
        Some(current) => (current * (1.0 - EMA_ALPHA)) + (sample * EMA_ALPHA),
        None => sample,
    }
}

fn scaled_threshold(value: usize, scale: f64) -> usize {
    ((value as f64) * scale).round().max(16.0) as usize
}

/// Returns (cpu_fixed_ms, cpu_var_ms, gpu_fixed_ms, gpu_var_ms) cost model.
/// CPU cost now reflects hardware crypto/SME acceleration where applicable:
/// - SHA-256/Keccak batch: ~5-20x faster with FEAT_SHA256/FEAT_SHA3
/// - Field ops / NTT: ~2-3x faster with SME/AMX
fn stage_cost_model(stage: &str) -> (f64, f64, f64, f64) {
    // Check if CPU crypto extensions are available for adjusted cost model
    let has_crypto_ext = zkf_core::platform_identity().crypto_extensions.sha256;
    let has_sme = zkf_core::platform_identity().crypto_extensions.sme;

    match stage {
        "witness-solve" => (2.8, 0.32, 3.5, 0.34),
        "booleanize-signals" => (0.9, 0.18, 1.4, 0.16),
        "range-check-expand" => (1.1, 0.20, 1.6, 0.18),
        "lookup-expand" => (1.6, 0.22, 2.0, 0.20),
        "msm" => {
            if has_sme {
                (0.9, 1.40, 0.55, 0.84) // SME-accelerated CPU MSM
            } else {
                (1.4, 2.15, 0.55, 0.84)
            }
        }
        "ntt" | "lde" | "fri-fold" | "fri-query-open" => {
            if has_sme {
                (0.7, 1.00, 0.45, 0.78) // SME-accelerated NTT butterflies
            } else {
                (1.2, 1.65, 0.45, 0.78)
            }
        }
        "poseidon-batch" => (0.8, 1.18, 0.40, 0.64),
        "sha256-batch" => {
            if has_crypto_ext {
                (0.20, 0.25, 0.52, 0.72) // ~5x from HW SHA-256
            } else {
                (1.0, 1.24, 0.52, 0.72)
            }
        }
        "merkle-layer" => {
            if has_crypto_ext {
                (0.22, 0.28, 0.48, 0.70) // ~5x from HW hash in Merkle
            } else {
                (1.1, 1.42, 0.48, 0.70)
            }
        }
        "field-ops" => {
            if has_sme {
                (0.45, 0.51, 0.38, 0.60) // ~2x from SME batch field mul
            } else {
                (0.9, 1.02, 0.38, 0.60)
            }
        }
        "verifier-embed" => (8.0, 0.55, 8.6, 0.50),
        "backend-prove" => (14.0, 0.75, 15.0, 0.70),
        "backend-fold" => (16.0, 0.80, 17.0, 0.76),
        "outer-prove" => (24.0, 0.90, 25.0, 0.85),
        "transcript-update" => (0.7, 0.14, 0.9, 0.16),
        "proof-encode" => (0.8, 0.16, 1.0, 0.18),
        _ => (1.0, 0.95, 0.55, 0.92),
    }
}

fn base_prediction_confidence(stage: &str) -> f64 {
    match stage {
        "msm" | "ntt" | "lde" | "poseidon-batch" | "merkle-layer" | "field-ops" => 0.55,
        "fri-fold" | "fri-query-open" | "sha256-batch" => 0.50,
        "witness-solve" | "lookup-expand" | "range-check-expand" => 0.35,
        _ => 0.30,
    }
}

fn fallback_problem_size(trace: &NodeTrace) -> Option<usize> {
    let size = trace.input_bytes.max(trace.output_bytes);
    if size == 0 {
        None
    } else {
        Some((size / 8).max(1))
    }
}

fn threshold_stage(stage: &str) -> Option<&'static str> {
    match stage {
        "msm" => Some("msm"),
        "ntt" | "lde" | "fri-fold" | "fri-query-open" => Some("ntt"),
        "poseidon-batch" => Some("poseidon2"),
        "merkle-layer" => Some("merkle"),
        "field-ops" => Some("field_ops"),
        _ => None,
    }
}

fn load_state(platform: &PlatformCapability) -> AdaptiveTuningState {
    let path = state_path(platform);
    fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AdaptiveTuningState>(&bytes).ok())
        .filter(|state| state.platform_key == platform.platform_key())
        .unwrap_or_else(|| AdaptiveTuningState {
            schema: "zkf-adaptive-thresholds-v1".to_string(),
            platform_key: platform.platform_key(),
            updated_at_unix_ms: 0,
            stages: BTreeMap::new(),
        })
}

fn write_state(platform: &PlatformCapability, state: &AdaptiveTuningState) -> Result<(), String> {
    let path = state_path(platform);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("serialize adaptive tuning state: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("write {}: {err}", path.display()))
}

fn state_path(platform: &PlatformCapability) -> PathBuf {
    resolve_tuning_dir().join(format!("{}.json", platform.platform_key()))
}

fn resolve_tuning_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("tuning")
}

fn static_thresholds_disabled() -> bool {
    matches!(
        std::env::var("ZKF_STATIC_THRESHOLDS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learned_threshold_moves_toward_midpoint() {
        let state = AdaptiveStageState {
            observations: 24,
            gpu_win_observations: 12,
            cpu_win_observations: 12,
            gpu_win_size_ema: Some(512.0),
            cpu_win_size_ema: Some(2048.0),
            learned_threshold: None,
        };
        assert_eq!(compute_learned_threshold(4096, &state), 1280);
    }

    #[test]
    fn runtime_bias_raises_mobile_thresholds() {
        let platform = PlatformCapability::detect();
        let mut platform = platform;
        platform.identity.form_factor = DeviceFormFactor::Mobile;
        platform.thermal_envelope.low_power_mode = true;
        let thresholds = MetalThresholdConfig {
            msm: 100,
            ntt: 100,
            poseidon2: 100,
            field_ops: 100,
            merkle: 100,
        };
        let biased = apply_runtime_bias(&platform, thresholds);
        assert!(biased.msm > thresholds.msm);
        assert!(biased.ntt > thresholds.ntt);
    }
}
