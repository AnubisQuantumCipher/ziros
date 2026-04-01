// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use crate::swarm::{SentinelConfig, SentinelState, ThreatDigest};
use crate::telemetry::NodeTrace;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::metal_runtime_report;
use zkf_core::{DeviceFormFactor, PlatformCapability, PressureLevel, SystemResources};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchdogAlertKind {
    TimingAnomaly,
    ProofSizeAnomaly,
    ThermalThrottle,
    MemoryPressureSpike,
    GpuCircuitBreakerTripped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchdogRecommendation {
    Continue,
    AdjustDispatch,
    ReduceParallelism,
    FlushGpuBuffers,
    AbortNonEssential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchdogAlertSeverity {
    Notice,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchdogAlert {
    pub kind: WatchdogAlertKind,
    pub severity: WatchdogAlertSeverity,
    pub recommendation: WatchdogRecommendation,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_duration_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicted_duration_ms: Option<f64>,
    pub timestamp_unix_ms: u128,
}

#[derive(Debug, Clone)]
struct WatchdogObservationEnv {
    timestamp_unix_ms: u128,
    pressure_level: PressureLevel,
    thermal_pressure: f64,
    cpu_speed_limit: f64,
    gpu_dispatch_circuit_open: bool,
    gpu_dispatch_last_failure: Option<String>,
}

#[derive(Debug, Default)]
struct WatchdogCoreState {
    alerts: Vec<WatchdogAlert>,
    force_gpu_capable_to_cpu: bool,
    force_stage_cpu_only: BTreeSet<String>,
    flush_gpu_buffers: bool,
    timing_miss_counts: BTreeMap<String, u32>,
    sentinel: Option<SentinelState>,
    sentinel_config: Option<SentinelConfig>,
}

#[derive(Clone)]
pub struct ProofWatchdog {
    state: Arc<Mutex<WatchdogCoreState>>,
    deterministic_mode: bool,
    mobile_mode: bool,
}

impl ProofWatchdog {
    pub fn new(
        platform: &PlatformCapability,
        deterministic_mode: bool,
        sentinel_config: Option<SentinelConfig>,
    ) -> Self {
        let mobile_mode = matches!(
            platform.identity.form_factor,
            DeviceFormFactor::Mobile | DeviceFormFactor::Headset
        );
        let sentinel = sentinel_config.clone().and_then(|config| {
            (config.enabled && crate::swarm::SwarmConfig::is_enabled())
                .then_some(SentinelState::new(&config, [0; 32]))
        });
        Self {
            state: Arc::new(Mutex::new(WatchdogCoreState {
                alerts: Vec::new(),
                force_gpu_capable_to_cpu: false,
                force_stage_cpu_only: BTreeSet::new(),
                flush_gpu_buffers: false,
                timing_miss_counts: BTreeMap::new(),
                sentinel,
                sentinel_config,
            })),
            deterministic_mode,
            mobile_mode,
        }
    }

    pub fn node_hook(&self) -> crate::scheduler::NodeHook {
        let this = self.clone();
        Box::new(move |trace| {
            this.observe_trace(trace);
        })
    }

    pub fn should_force_gpu_capable_to_cpu(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.should_force_gpu_capable_to_cpu(self.deterministic_mode))
            .unwrap_or(false)
    }

    pub fn should_force_stage_to_cpu(&self, stage_key: &str) -> bool {
        self.state
            .lock()
            .map(|state| state.should_force_stage_to_cpu(self.deterministic_mode, stage_key))
            .unwrap_or(false)
    }

    pub fn take_flush_gpu_buffers(&self) -> bool {
        self.state
            .lock()
            .map(|mut state| state.take_flush_gpu_buffers(self.deterministic_mode))
            .unwrap_or(false)
    }

    pub fn finalize(
        &self,
        expected_proof_size_bytes: Option<u64>,
        observed_proof_size_bytes: Option<u64>,
    ) -> Vec<WatchdogAlert> {
        self.finalize_with_digests(expected_proof_size_bytes, observed_proof_size_bytes)
            .0
    }

    pub fn finalize_with_digests(
        &self,
        expected_proof_size_bytes: Option<u64>,
        observed_proof_size_bytes: Option<u64>,
    ) -> (Vec<WatchdogAlert>, Vec<ThreatDigest>) {
        self.state
            .lock()
            .map(|mut state| {
                state.finalize_with_digests(
                    expected_proof_size_bytes,
                    observed_proof_size_bytes,
                    unix_time_now_ms(),
                )
            })
            .unwrap_or_default()
    }

    fn observe_trace(&self, trace: &NodeTrace) {
        if let Ok(mut state) = self.state.lock() {
            state.observe_trace(
                trace,
                &detect_observation_env(),
                self.deterministic_mode,
                self.mobile_mode,
            );
        }
    }
}

impl WatchdogCoreState {
    fn should_force_gpu_capable_to_cpu(&self, deterministic_mode: bool) -> bool {
        if deterministic_mode {
            return false;
        }
        self.force_gpu_capable_to_cpu
    }

    fn should_force_stage_to_cpu(&self, deterministic_mode: bool, stage_key: &str) -> bool {
        if deterministic_mode {
            return false;
        }
        self.force_stage_cpu_only.contains(stage_key)
    }

    fn take_flush_gpu_buffers(&mut self, deterministic_mode: bool) -> bool {
        if deterministic_mode {
            return false;
        }
        let should_flush = self.flush_gpu_buffers;
        self.flush_gpu_buffers = false;
        should_flush
    }

    fn finalize_with_digests(
        &mut self,
        expected_proof_size_bytes: Option<u64>,
        observed_proof_size_bytes: Option<u64>,
        timestamp_unix_ms: u128,
    ) -> (Vec<WatchdogAlert>, Vec<ThreatDigest>) {
        if let (Some(expected), Some(observed)) =
            (expected_proof_size_bytes, observed_proof_size_bytes)
            && expected > 0
            && observed as f64 / expected as f64 >= 2.0
        {
            self.push_alert(WatchdogAlert {
                kind: WatchdogAlertKind::ProofSizeAnomaly,
                severity: WatchdogAlertSeverity::Warning,
                recommendation: WatchdogRecommendation::Continue,
                message: format!(
                    "proof size anomaly: observed {} bytes versus expected {} bytes",
                    observed, expected
                ),
                stage_key: None,
                observed_duration_ms: None,
                predicted_duration_ms: None,
                timestamp_unix_ms,
            });
        }
        let alerts = self.alerts.clone();
        let digests = self
            .sentinel
            .as_mut()
            .map(SentinelState::drain_digests)
            .unwrap_or_default();
        (alerts, digests)
    }

    fn observe_trace(
        &mut self,
        trace: &NodeTrace,
        env: &WatchdogObservationEnv,
        deterministic_mode: bool,
        mobile_mode: bool,
    ) {
        self.observe_timing(trace, env, deterministic_mode, mobile_mode);
        self.observe_pressure(trace, env, deterministic_mode);
        self.observe_thermal(trace, env, deterministic_mode);
        self.observe_gpu_circuit_breaker(trace, env, deterministic_mode);

        let Some(config) = self.sentinel_config.clone() else {
            return;
        };
        let Some(sentinel) = self.sentinel.as_mut() else {
            return;
        };
        if sentinel.observe(trace, &config).is_some()
            && sentinel.stage_anomaly_streak(&trace.stage_key) >= 3
            && trace.placement == crate::graph::DevicePlacement::Gpu
        {
            self.force_stage_cpu_only.insert(trace.stage_key.clone());
        }
    }

    fn observe_timing(
        &mut self,
        trace: &NodeTrace,
        env: &WatchdogObservationEnv,
        deterministic_mode: bool,
        mobile_mode: bool,
    ) {
        let limit = if mobile_mode { 1.25 } else { 1.50 };
        let expected = match trace.placement {
            crate::graph::DevicePlacement::Gpu => trace.predicted_gpu_ms,
            _ => trace.predicted_cpu_ms,
        };
        let Some(expected) = expected else {
            return;
        };
        let observed = trace.wall_time.as_secs_f64() * 1_000.0;
        if observed <= expected * limit {
            return;
        }

        let confidence = trace.prediction_confidence.unwrap_or(0.0);
        let observation_count = trace.prediction_observation_count.unwrap_or(0);
        let undertrained = confidence < 0.75 || observation_count < 20;
        let repeated_misses = self
            .timing_miss_counts
            .entry(trace.stage_key.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        let repeated_misses = *repeated_misses;
        let should_force_dispatch = trace.placement == crate::graph::DevicePlacement::Gpu
            && !undertrained
            && (repeated_misses >= 2 || observed >= expected * 2.25);
        let recommendation = if should_force_dispatch {
            WatchdogRecommendation::AdjustDispatch
        } else {
            WatchdogRecommendation::Continue
        };
        self.push_alert(WatchdogAlert {
            kind: WatchdogAlertKind::TimingAnomaly,
            severity: if undertrained {
                WatchdogAlertSeverity::Notice
            } else if should_force_dispatch || observed >= expected * 3.0 {
                WatchdogAlertSeverity::Critical
            } else {
                WatchdogAlertSeverity::Warning
            },
            recommendation,
            message: format!(
                "stage '{}' exceeded watchdog timing budget ({:.2} ms observed vs {:.2} ms predicted, confidence {:.2}, observations {})",
                trace.stage_key, observed, expected, confidence, observation_count
            ),
            stage_key: Some(trace.stage_key.clone()),
            observed_duration_ms: Some(observed),
            predicted_duration_ms: Some(expected),
            timestamp_unix_ms: env.timestamp_unix_ms,
        });

        if !deterministic_mode && should_force_dispatch {
            self.force_gpu_capable_to_cpu = true;
        }
    }

    fn observe_pressure(
        &mut self,
        trace: &NodeTrace,
        env: &WatchdogObservationEnv,
        deterministic_mode: bool,
    ) {
        if !matches!(
            env.pressure_level,
            PressureLevel::High | PressureLevel::Critical
        ) {
            return;
        }
        self.push_alert(WatchdogAlert {
            kind: WatchdogAlertKind::MemoryPressureSpike,
            severity: WatchdogAlertSeverity::Critical,
            recommendation: WatchdogRecommendation::FlushGpuBuffers,
            message: format!(
                "memory pressure spiked to {} after stage '{}'",
                env.pressure_level, trace.stage_key
            ),
            stage_key: Some(trace.stage_key.clone()),
            observed_duration_ms: None,
            predicted_duration_ms: None,
            timestamp_unix_ms: env.timestamp_unix_ms,
        });
        if !deterministic_mode {
            self.flush_gpu_buffers = true;
            self.force_gpu_capable_to_cpu = true;
        }
    }

    fn observe_thermal(
        &mut self,
        trace: &NodeTrace,
        env: &WatchdogObservationEnv,
        deterministic_mode: bool,
    ) {
        if env.thermal_pressure < 0.55 && env.cpu_speed_limit >= 0.90 {
            return;
        }
        self.push_alert(WatchdogAlert {
            kind: WatchdogAlertKind::ThermalThrottle,
            severity: WatchdogAlertSeverity::Warning,
            recommendation: WatchdogRecommendation::AdjustDispatch,
            message: format!(
                "thermal throttle detected after stage '{}' (thermal_pressure={:.2}, cpu_speed_limit={:.2})",
                trace.stage_key, env.thermal_pressure, env.cpu_speed_limit
            ),
            stage_key: Some(trace.stage_key.clone()),
            observed_duration_ms: None,
            predicted_duration_ms: None,
            timestamp_unix_ms: env.timestamp_unix_ms,
        });
        if !deterministic_mode {
            self.flush_gpu_buffers = true;
            self.force_gpu_capable_to_cpu = true;
        }
    }

    fn observe_gpu_circuit_breaker(
        &mut self,
        trace: &NodeTrace,
        env: &WatchdogObservationEnv,
        deterministic_mode: bool,
    ) {
        if !env.gpu_dispatch_circuit_open {
            return;
        }
        self.push_alert(WatchdogAlert {
            kind: WatchdogAlertKind::GpuCircuitBreakerTripped,
            severity: WatchdogAlertSeverity::Critical,
            recommendation: WatchdogRecommendation::AdjustDispatch,
            message: format!(
                "GPU dispatch circuit breaker is open after stage '{}'{}",
                trace.stage_key,
                env.gpu_dispatch_last_failure
                    .as_deref()
                    .map(|value| format!(" ({value})"))
                    .unwrap_or_default()
            ),
            stage_key: Some(trace.stage_key.clone()),
            observed_duration_ms: None,
            predicted_duration_ms: None,
            timestamp_unix_ms: env.timestamp_unix_ms,
        });
        if !deterministic_mode {
            self.force_gpu_capable_to_cpu = true;
        }
    }

    fn push_alert(&mut self, alert: WatchdogAlert) {
        self.alerts.push(alert);
    }
}

fn detect_observation_env() -> WatchdogObservationEnv {
    let resources = SystemResources::detect();
    let platform = PlatformCapability::detect();
    let runtime = metal_runtime_report();
    WatchdogObservationEnv {
        timestamp_unix_ms: unix_time_now_ms(),
        pressure_level: resources.pressure.level,
        thermal_pressure: platform.thermal_envelope.thermal_pressure.unwrap_or(0.0),
        cpu_speed_limit: platform.thermal_envelope.cpu_speed_limit.unwrap_or(1.0),
        gpu_dispatch_circuit_open: runtime.metal_dispatch_circuit_open,
        gpu_dispatch_last_failure: runtime.metal_dispatch_last_failure,
    }
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
    use crate::graph::DevicePlacement;
    use crate::memory::NodeId;
    use crate::trust::TrustModel;
    use std::time::Duration;

    fn stable_test_env() -> WatchdogObservationEnv {
        WatchdogObservationEnv {
            timestamp_unix_ms: 42,
            pressure_level: PressureLevel::Normal,
            thermal_pressure: 0.0,
            cpu_speed_limit: 1.0,
            gpu_dispatch_circuit_open: false,
            gpu_dispatch_last_failure: None,
        }
    }

    fn test_watchdog_state() -> WatchdogCoreState {
        WatchdogCoreState::default()
    }

    #[test]
    fn watchdog_flags_gpu_timing_drift() {
        let mut state = test_watchdog_state();
        let trace = NodeTrace {
            node_id: NodeId::new(),
            op_name: "NTT",
            stage_key: "ntt".to_string(),
            placement: DevicePlacement::Gpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(40),
            problem_size: Some(1024),
            input_bytes: 128,
            output_bytes: 128,
            predicted_cpu_ms: Some(60.0),
            predicted_gpu_ms: Some(10.0),
            prediction_confidence: Some(0.95),
            prediction_observation_count: Some(40),
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after: 0,
            accelerator_name: None,
            fell_back: false,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        };
        let env = stable_test_env();
        state.observe_trace(&trace, &env, false, false);
        state.observe_trace(&trace, &env, false, false);

        assert!(state.should_force_gpu_capable_to_cpu(false));
        assert!(
            !state
                .finalize_with_digests(None, None, env.timestamp_unix_ms)
                .0
                .is_empty()
        );
    }

    #[test]
    fn watchdog_keeps_low_confidence_timing_miss_as_notice() {
        let mut state = test_watchdog_state();
        let trace = NodeTrace {
            node_id: NodeId::new(),
            op_name: "NTT",
            stage_key: "ntt".to_string(),
            placement: DevicePlacement::Gpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(40),
            problem_size: Some(1024),
            input_bytes: 128,
            output_bytes: 128,
            predicted_cpu_ms: Some(60.0),
            predicted_gpu_ms: Some(10.0),
            prediction_confidence: Some(0.40),
            prediction_observation_count: Some(4),
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after: 0,
            accelerator_name: None,
            fell_back: false,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        };
        let env = stable_test_env();
        state.observe_trace(&trace, &env, false, false);

        assert!(!state.should_force_gpu_capable_to_cpu(false));
        let alerts = state
            .finalize_with_digests(None, None, env.timestamp_unix_ms)
            .0;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, WatchdogAlertSeverity::Notice);
        assert_eq!(alerts[0].recommendation, WatchdogRecommendation::Continue);
    }

    #[test]
    fn repeated_sentinel_anomalies_force_only_the_stage_to_cpu() {
        let config = SentinelConfig {
            min_baseline_observations: 3,
            z_threshold: 1.0,
            multivariate_threshold: 1.0,
            digest_rate_limit_per_sec: 1_000,
            jitter_detection_enabled: false,
            cache_flush_detection_enabled: false,
            ..SentinelConfig::default()
        };
        let mut state = WatchdogCoreState {
            sentinel: Some(SentinelState::new(&config, [0; 32])),
            sentinel_config: Some(config),
            ..WatchdogCoreState::default()
        };
        let stable = NodeTrace {
            node_id: NodeId::new(),
            op_name: "NTT",
            stage_key: "ntt".to_string(),
            placement: DevicePlacement::Gpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(10),
            problem_size: Some(1024),
            input_bytes: 128,
            output_bytes: 128,
            predicted_cpu_ms: Some(60.0),
            predicted_gpu_ms: Some(10.0),
            prediction_confidence: Some(0.95),
            prediction_observation_count: Some(40),
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after: 0,
            accelerator_name: None,
            fell_back: false,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        };
        let env = stable_test_env();
        for _ in 0..8 {
            state.observe_trace(&stable, &env, false, false);
        }
        let mut anomalous = stable.clone();
        anomalous.wall_time = Duration::from_millis(300);
        for _ in 0..3 {
            state.observe_trace(&anomalous, &env, false, false);
        }
        assert!(state.should_force_stage_to_cpu(false, "ntt"));
        assert!(!state.should_force_stage_to_cpu(false, "msm"));
    }

    #[test]
    fn sentinel_uses_configured_minimum_baseline_before_forcing_stage_cpu() {
        let mut state = WatchdogCoreState {
            sentinel: Some(SentinelState::new(
                &SentinelConfig {
                    min_baseline_observations: 25,
                    ..SentinelConfig::default()
                },
                [0; 32],
            )),
            sentinel_config: Some(SentinelConfig {
                min_baseline_observations: 25,
                ..SentinelConfig::default()
            }),
            ..WatchdogCoreState::default()
        };
        let stable = NodeTrace {
            node_id: NodeId::new(),
            op_name: "NTT",
            stage_key: "ntt".to_string(),
            placement: DevicePlacement::Gpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(10),
            problem_size: Some(1024),
            input_bytes: 128,
            output_bytes: 128,
            predicted_cpu_ms: Some(60.0),
            predicted_gpu_ms: Some(10.0),
            prediction_confidence: Some(0.95),
            prediction_observation_count: Some(40),
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after: 0,
            accelerator_name: None,
            fell_back: false,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        };
        let env = stable_test_env();
        for _ in 0..24 {
            state.observe_trace(&stable, &env, false, false);
        }
        let mut anomalous = stable.clone();
        anomalous.wall_time = Duration::from_millis(100);
        for _ in 0..3 {
            state.observe_trace(&anomalous, &env, false, false);
        }
        assert!(!state.should_force_stage_to_cpu(false, "ntt"));
    }

    #[test]
    fn watchdog_pressure_spike_requests_gpu_flush() {
        let mut state = test_watchdog_state();
        let env = WatchdogObservationEnv {
            pressure_level: PressureLevel::High,
            ..stable_test_env()
        };
        let trace = NodeTrace {
            node_id: NodeId::new(),
            op_name: "MSM",
            stage_key: "msm".to_string(),
            placement: DevicePlacement::Gpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(10),
            problem_size: Some(256),
            input_bytes: 64,
            output_bytes: 64,
            predicted_cpu_ms: Some(20.0),
            predicted_gpu_ms: Some(8.0),
            prediction_confidence: Some(0.9),
            prediction_observation_count: Some(32),
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after: 0,
            accelerator_name: None,
            fell_back: false,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        };

        state.observe_trace(&trace, &env, false, false);

        assert!(state.take_flush_gpu_buffers(false));
        let alerts = state
            .finalize_with_digests(None, None, env.timestamp_unix_ms)
            .0;
        assert!(
            alerts
                .iter()
                .any(|alert| alert.kind == WatchdogAlertKind::MemoryPressureSpike)
        );
    }
}
