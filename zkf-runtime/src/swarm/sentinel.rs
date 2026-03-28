use crate::graph::gpu_capable_stage_keys;
use crate::security::{ThreatSeverity, ThreatSignalKind};
use crate::swarm_sentinel_core;
use crate::telemetry::NodeTrace;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::wrapping::fri_gadgets::poseidon_native_hash_two;
use zkf_core::SignatureBundle;

const FEATURE_DIM: usize = 6;
const MAHALANOBIS_REGULARIZATION: f64 = 1e-6;
const MAX_BASELINE_HISTORY: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub z_threshold: f64,
    pub multivariate_threshold: f64,
    pub min_baseline_observations: u64,
    pub digest_rate_limit_per_sec: u32,
    pub seal_every_observations: u64,
    pub baseline_drift_threshold: f64,
    pub fingerprint_z_threshold: f64,
    pub canary_min_interval_ms: u128,
    pub canary_jitter_ms: u128,
    #[serde(default = "default_true")]
    pub jitter_detection_enabled: bool,
    #[serde(default = "default_cache_flush_detection_enabled")]
    pub cache_flush_detection_enabled: bool,
    pub enabled: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            z_threshold: 3.0,
            multivariate_threshold: 4.5,
            min_baseline_observations: 10,
            digest_rate_limit_per_sec: 5,
            seal_every_observations: 1_000,
            baseline_drift_threshold: 6.0,
            fingerprint_z_threshold: 4.0,
            canary_min_interval_ms: 300_000,
            canary_jitter_ms: 60_000,
            jitter_detection_enabled: true,
            cache_flush_detection_enabled: default_cache_flush_detection_enabled(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct WelfordState {
    pub count: u64,
    pub mean: f64,
    pub m2: f64,
}

impl WelfordState {
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / (self.count - 1) as f64
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let std_dev = self.variance().sqrt();
        if std_dev < f64::EPSILON {
            return if (value - self.mean).abs() > f64::EPSILON {
                f64::INFINITY
            } else {
                0.0
            };
        }
        (value - self.mean).abs() / std_dev
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct JitterState {
    pub variance_of_variance: WelfordState,
    pub probe_baseline: WelfordState,
    pub last_variance: f64,
    pub observation_count: u64,
}

impl JitterState {
    pub fn observe_variance_delta(&mut self, current_variance: f64) -> f64 {
        let delta = if self.observation_count == 0 {
            0.0
        } else {
            (current_variance - self.last_variance).abs()
        };
        let pre_update = self.variance_of_variance;
        self.variance_of_variance.update(delta);
        self.last_variance = current_variance;
        self.observation_count += 1;

        if pre_update.count < 2 {
            delta
        } else {
            pre_update.z_score(delta)
        }
    }

    pub fn observe_probe_duration(&mut self, duration_ns: f64) -> f64 {
        let pre_update = self.probe_baseline;
        self.probe_baseline.update(duration_ns);
        if pre_update.count < 2 {
            duration_ns
        } else {
            pre_update.z_score(duration_ns)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MultivariateBaseline {
    pub count: u64,
    pub mean: [f64; FEATURE_DIM],
    pub covariance_m2: [[f64; FEATURE_DIM]; FEATURE_DIM],
}

impl Default for MultivariateBaseline {
    fn default() -> Self {
        Self {
            count: 0,
            mean: [0.0; FEATURE_DIM],
            covariance_m2: [[0.0; FEATURE_DIM]; FEATURE_DIM],
        }
    }
}

impl MultivariateBaseline {
    pub fn update(&mut self, values: [f64; FEATURE_DIM]) {
        self.count += 1;
        let n = self.count as f64;
        let mut delta = [0.0; FEATURE_DIM];
        for (index, mean) in self.mean.iter_mut().enumerate() {
            delta[index] = values[index] - *mean;
            *mean += delta[index] / n;
        }
        let mut delta2 = [0.0; FEATURE_DIM];
        for (index, value) in delta2.iter_mut().enumerate() {
            *value = values[index] - self.mean[index];
        }
        for (row, delta_row) in delta.iter().enumerate() {
            for (col, delta2_col) in delta2.iter().enumerate() {
                self.covariance_m2[row][col] += *delta_row * *delta2_col;
            }
        }
    }

    pub fn covariance(&self) -> [[f64; FEATURE_DIM]; FEATURE_DIM] {
        if self.count < 2 {
            return [[0.0; FEATURE_DIM]; FEATURE_DIM];
        }
        let mut covariance = [[0.0; FEATURE_DIM]; FEATURE_DIM];
        let scale = 1.0 / (self.count - 1) as f64;
        for (row, covariance_row) in covariance.iter_mut().enumerate() {
            for (col, value) in covariance_row.iter_mut().enumerate() {
                *value = self.covariance_m2[row][col] * scale;
            }
        }
        covariance
    }

    pub fn mahalanobis_distance(&self, values: [f64; FEATURE_DIM]) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let covariance = regularize_covariance(self.covariance());
        let Some(inverse) = invert_matrix(covariance) else {
            return 0.0;
        };
        let mut delta = [0.0; FEATURE_DIM];
        for (index, value) in delta.iter_mut().enumerate() {
            *value = values[index] - self.mean[index];
        }
        let mut projected = [0.0; FEATURE_DIM];
        for row in 0..FEATURE_DIM {
            projected[row] = dot(&inverse[row], &delta);
        }
        let value = dot(&delta, &projected).max(0.0);
        value.sqrt()
    }

    pub fn drift_distance_to(&self, other: &BaselineSeal) -> f64 {
        let covariance = regularize_covariance(other.covariance);
        let Some(inverse) = invert_matrix(covariance) else {
            return 0.0;
        };
        let mut delta = [0.0; FEATURE_DIM];
        for (index, value) in delta.iter_mut().enumerate() {
            *value = self.mean[index] - other.mean[index];
        }
        let mut projected = [0.0; FEATURE_DIM];
        for row in 0..FEATURE_DIM {
            projected[row] = dot(&inverse[row], &delta);
        }
        dot(&delta, &projected).max(0.0).sqrt()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineSeal {
    pub stage_key: String,
    pub observation_count: u64,
    pub timestamp_unix_ms: u128,
    pub mean: [f64; FEATURE_DIM],
    pub covariance: [[f64; FEATURE_DIM]; FEATURE_DIM],
    pub commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExecutionFingerprintRecord {
    pub structure_fingerprint: String,
    pub timing_baseline: WelfordState,
    pub last_seen_unix_ms: u128,
    pub observation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CanaryState {
    pub last_run_unix_ms: u128,
    pub next_due_unix_ms: u128,
    pub total_runs: u64,
    pub failures: u64,
    pub performance_baseline: WelfordState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatDigest {
    pub source_peer: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_peer_id: Option<String>,
    pub timestamp_unix_ms: u64,
    pub stage_key_hash: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_key: Option<String>,
    pub severity: ThreatSeverity,
    pub kind: ThreatSignalKind,
    pub z_score: f32,
    pub observation_count: u32,
    #[serde(default)]
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_bundle: Option<SignatureBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ThreatDigest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.source_peer);
        push_opt_string(&mut bytes, self.source_peer_id.as_deref());
        bytes.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&self.stage_key_hash.to_le_bytes());
        push_opt_string(&mut bytes, self.stage_key.as_deref());
        bytes.push(self.severity as u8);
        push_string(&mut bytes, threat_kind_label(self.kind));
        bytes.extend_from_slice(&self.z_score.to_le_bytes());
        bytes.extend_from_slice(&self.observation_count.to_le_bytes());
        push_opt_string(&mut bytes, self.baseline_commitment.as_deref());
        push_opt_string(&mut bytes, self.execution_fingerprint.as_deref());
        push_opt_string(&mut bytes, self.detail.as_deref());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentinelState {
    pub stage_baselines: BTreeMap<String, WelfordState>,
    #[serde(default)]
    pub stage_manifolds: BTreeMap<String, MultivariateBaseline>,
    #[serde(default)]
    pub stage_seals: BTreeMap<String, Vec<BaselineSeal>>,
    #[serde(default)]
    pub stage_jitter: BTreeMap<String, JitterState>,
    #[serde(default)]
    pub fingerprint_registry: BTreeMap<String, ExecutionFingerprintRecord>,
    #[serde(default)]
    pub canary_state: CanaryState,
    pub anomaly_count: u64,
    pub last_digest_unix_ms: u128,
    pub pending_digests: Vec<ThreatDigest>,
    #[serde(default)]
    pub digest_window_unix_ms: u128,
    #[serde(default)]
    pub digests_emitted_in_window: u32,
    #[serde(default)]
    pub stage_anomaly_streaks: BTreeMap<String, u32>,
    pub source_peer: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_peer_id: Option<String>,
}

impl SentinelState {
    pub fn new(config: &SentinelConfig, source_peer: [u8; 32]) -> Self {
        let mut stage_baselines = runtime_stage_seed_state();
        if !config.enabled {
            stage_baselines.clear();
        }
        Self {
            stage_baselines,
            stage_manifolds: BTreeMap::new(),
            stage_seals: BTreeMap::new(),
            stage_jitter: BTreeMap::new(),
            fingerprint_registry: BTreeMap::new(),
            canary_state: CanaryState::default(),
            anomaly_count: 0,
            last_digest_unix_ms: 0,
            pending_digests: Vec::new(),
            digest_window_unix_ms: 0,
            digests_emitted_in_window: 0,
            stage_anomaly_streaks: BTreeMap::new(),
            source_peer,
            source_peer_id: None,
        }
    }

    pub fn set_source_peer_id(&mut self, source_peer_id: impl Into<String>) {
        self.source_peer_id = Some(source_peer_id.into());
    }

    pub fn observe(&mut self, trace: &NodeTrace, config: &SentinelConfig) -> Option<ThreatDigest> {
        if !config.enabled {
            return None;
        }

        let observed_ms = trace.wall_time.as_secs_f64() * 1_000.0;
        let stage = self
            .stage_baselines
            .entry(trace.stage_key.clone())
            .or_default();
        let pre_update = *stage;
        stage.update(observed_ms);

        let features = feature_vector_for_trace(trace);
        let manifold = self
            .stage_manifolds
            .entry(trace.stage_key.clone())
            .or_default();
        let pre_manifold = *manifold;
        manifold.update(features);

        let current_variance = stage.variance();
        let mut jitter_score = 0.0;
        if config.jitter_detection_enabled {
            let jitter = self
                .stage_jitter
                .entry(trace.stage_key.clone())
                .or_default();
            let variance_score = jitter.observe_variance_delta(current_variance);
            if jitter.observation_count >= config.min_baseline_observations {
                jitter_score = variance_score;
            }
            if config.cache_flush_detection_enabled
                && let Some(duration_ns) = cache_flush_probe_duration_ns(&trace.stage_key)
            {
                let probe_score = jitter.observe_probe_duration(duration_ns);
                if jitter.probe_baseline.count >= config.min_baseline_observations {
                    jitter_score = jitter_score.max(probe_score);
                }
            }
        }

        self.maybe_seal_baseline(&trace.stage_key, config);
        let drift_digest = self
            .maybe_detect_baseline_drift(&trace.stage_key, config)
            .inspect(|digest| self.pending_digests.push(digest.clone()));

        let ready_for_univariate = pre_update.count >= config.min_baseline_observations;
        let ready_for_multivariate = pre_manifold.count >= config.min_baseline_observations;
        if !ready_for_univariate && !ready_for_multivariate {
            self.stage_anomaly_streaks
                .insert(trace.stage_key.clone(), 0);
            return drift_digest;
        }

        let z_score = if ready_for_univariate {
            pre_update.z_score(observed_ms)
        } else {
            0.0
        };
        let manifold_score = if ready_for_multivariate {
            pre_manifold.mahalanobis_distance(features)
        } else {
            0.0
        };
        let score = z_score.max(jitter_score).max(manifold_score);
        let threshold = config
            .z_threshold
            .max(config.multivariate_threshold.min(score));

        if score <= threshold {
            self.stage_anomaly_streaks
                .insert(trace.stage_key.clone(), 0);
            return drift_digest;
        }

        let now_ms = unix_time_now_ms();
        if !self.allow_digest(now_ms, config.digest_rate_limit_per_sec) {
            return drift_digest;
        }

        self.anomaly_count += 1;
        let streak = self
            .stage_anomaly_streaks
            .entry(trace.stage_key.clone())
            .or_insert(0);
        *streak += 1;

        let detail = format!(
            "mahalanobis={manifold_score:.3}; wall_z={z_score:.3}; jitter_z={jitter_score:.3}"
        );
        let digest = ThreatDigest {
            source_peer: self.source_peer,
            source_peer_id: self.source_peer_id.clone(),
            timestamp_unix_ms: now_ms as u64,
            stage_key_hash: stage_hash(&trace.stage_key),
            stage_key: Some(trace.stage_key.clone()),
            severity: severity_for_score(score),
            kind: ThreatSignalKind::RuntimeAnomaly,
            z_score: score as f32,
            observation_count: pre_update.count.max(pre_manifold.count) as u32,
            signature: vec![],
            signature_bundle: None,
            baseline_commitment: self
                .latest_commitment_for(&trace.stage_key)
                .map(ToString::to_string),
            execution_fingerprint: None,
            detail: Some(detail),
        };
        self.last_digest_unix_ms = now_ms;
        self.pending_digests.push(digest.clone());
        Some(digest)
    }

    pub fn observe_execution_fingerprint(
        &mut self,
        structure_fingerprint: impl Into<String>,
        elapsed_ms: f64,
        stage_key: Option<&str>,
        config: &SentinelConfig,
    ) -> Option<ThreatDigest> {
        if !config.enabled {
            return None;
        }
        let structure_fingerprint = structure_fingerprint.into();
        let record = self
            .fingerprint_registry
            .entry(structure_fingerprint.clone())
            .or_insert_with(|| ExecutionFingerprintRecord {
                structure_fingerprint: structure_fingerprint.clone(),
                ..ExecutionFingerprintRecord::default()
            });
        let pre_update = record.timing_baseline;
        record.timing_baseline.update(elapsed_ms);
        record.last_seen_unix_ms = unix_time_now_ms();
        record.observation_count += 1;
        if pre_update.count < config.min_baseline_observations {
            return None;
        }
        let z_score = pre_update.z_score(elapsed_ms);
        if z_score <= config.fingerprint_z_threshold {
            return None;
        }
        let now_ms = unix_time_now_ms();
        if !self.allow_digest(now_ms, config.digest_rate_limit_per_sec) {
            return None;
        }
        let digest = ThreatDigest {
            source_peer: self.source_peer,
            source_peer_id: self.source_peer_id.clone(),
            timestamp_unix_ms: now_ms as u64,
            stage_key_hash: stage_key.map(stage_hash).unwrap_or_default(),
            stage_key: stage_key.map(ToString::to_string),
            severity: severity_for_score(z_score),
            kind: ThreatSignalKind::ExecutionFingerprintMismatch,
            z_score: z_score as f32,
            observation_count: pre_update.count as u32,
            signature: vec![],
            signature_bundle: None,
            baseline_commitment: None,
            execution_fingerprint: Some(structure_fingerprint),
            detail: Some(format!(
                "elapsed_ms={elapsed_ms:.3}; expected_mean_ms={:.3}",
                pre_update.mean
            )),
        };
        self.pending_digests.push(digest.clone());
        Some(digest)
    }

    pub fn record_canary_result(
        &mut self,
        duration_ms: f64,
        success: bool,
        config: &SentinelConfig,
    ) -> Option<ThreatDigest> {
        if !config.enabled {
            return None;
        }
        let now_ms = unix_time_now_ms();
        self.canary_state.total_runs += 1;
        self.canary_state.last_run_unix_ms = now_ms;
        self.canary_state.next_due_unix_ms =
            now_ms + config.canary_min_interval_ms + deterministic_jitter(now_ms, config);

        let pre_update = self.canary_state.performance_baseline;
        self.canary_state.performance_baseline.update(duration_ms);
        let z_score = if pre_update.count < config.min_baseline_observations {
            0.0
        } else {
            pre_update.z_score(duration_ms)
        };
        if success && z_score <= config.fingerprint_z_threshold {
            return None;
        }
        self.canary_state.failures += 1;
        if !self.allow_digest(now_ms, config.digest_rate_limit_per_sec) {
            return None;
        }
        let digest = ThreatDigest {
            source_peer: self.source_peer,
            source_peer_id: self.source_peer_id.clone(),
            timestamp_unix_ms: now_ms as u64,
            stage_key_hash: stage_hash("swarm-canary"),
            stage_key: Some("swarm-canary".to_string()),
            severity: ThreatSeverity::Critical,
            kind: ThreatSignalKind::CanaryFailure,
            z_score: z_score as f32,
            observation_count: pre_update.count as u32,
            signature: vec![],
            signature_bundle: None,
            baseline_commitment: None,
            execution_fingerprint: Some("swarm-canary".to_string()),
            detail: Some(if success {
                format!(
                    "canary timing drift detected; duration_ms={duration_ms:.3}; z={z_score:.3}"
                )
            } else {
                "canary proof failed or produced an invalid result".to_string()
            }),
        };
        self.pending_digests.push(digest.clone());
        Some(digest)
    }

    pub fn canary_due(&self, now_ms: u128) -> bool {
        swarm_sentinel_core::canary_due(now_ms, self.canary_state.next_due_unix_ms)
    }

    pub fn drain_digests(&mut self) -> Vec<ThreatDigest> {
        let mut drained = Vec::new();
        std::mem::swap(&mut drained, &mut self.pending_digests);
        drained
    }

    pub fn stage_anomaly_streak(&self, stage_key: &str) -> u32 {
        self.stage_anomaly_streaks
            .get(stage_key)
            .copied()
            .unwrap_or_default()
    }

    pub fn latest_commitment_for(&self, stage_key: &str) -> Option<&str> {
        self.stage_seals
            .get(stage_key)
            .and_then(|seals| seals.last())
            .map(|seal| seal.commitment.as_str())
    }

    fn maybe_seal_baseline(&mut self, stage_key: &str, config: &SentinelConfig) {
        let Some(manifold) = self.stage_manifolds.get(stage_key) else {
            return;
        };
        let commitment = baseline_commitment(stage_key, manifold);
        let seals = self.stage_seals.entry(stage_key.to_string()).or_default();
        let last = seals.last();
        if !swarm_sentinel_core::should_seal_baseline(
            manifold.count,
            config.seal_every_observations,
            last.map(|seal| seal.observation_count),
            last.map(|seal| seal.commitment == commitment)
                .unwrap_or(false),
        ) {
            return;
        }
        let seal = BaselineSeal {
            stage_key: stage_key.to_string(),
            observation_count: manifold.count,
            timestamp_unix_ms: unix_time_now_ms(),
            mean: manifold.mean,
            covariance: manifold.covariance(),
            commitment,
        };
        seals.push(seal.clone());
        if seals.len() > MAX_BASELINE_HISTORY {
            seals.remove(0);
        }
        let _ = persist_baseline_seals(stage_key, seals);
    }

    fn maybe_detect_baseline_drift(
        &mut self,
        stage_key: &str,
        config: &SentinelConfig,
    ) -> Option<ThreatDigest> {
        let current = *self.stage_manifolds.get(stage_key)?;
        let reference = self.stage_seals.get(stage_key)?.last().cloned()?;
        let drift = current.drift_distance_to(&reference);
        if !swarm_sentinel_core::should_emit_drift_digest(
            current.count,
            reference.observation_count,
            (drift * 1000.0).round() as u32,
            (config.baseline_drift_threshold * 1000.0).round() as u32,
        ) {
            return None;
        }
        let now_ms = unix_time_now_ms();
        if !self.allow_digest(now_ms, config.digest_rate_limit_per_sec) {
            return None;
        }
        Some(ThreatDigest {
            source_peer: self.source_peer,
            source_peer_id: self.source_peer_id.clone(),
            timestamp_unix_ms: now_ms as u64,
            stage_key_hash: stage_hash(stage_key),
            stage_key: Some(stage_key.to_string()),
            severity: severity_for_score(drift.max(config.multivariate_threshold)),
            kind: ThreatSignalKind::BaselineDriftDetected,
            z_score: drift as f32,
            observation_count: current.count as u32,
            signature: vec![],
            signature_bundle: None,
            baseline_commitment: Some(reference.commitment),
            execution_fingerprint: None,
            detail: Some(format!(
                "baseline drift distance {drift:.3} exceeded threshold {:.3}",
                config.baseline_drift_threshold
            )),
        })
    }

    fn allow_digest(&mut self, now_ms: u128, rate_limit_per_sec: u32) -> bool {
        let Some((window_start, emitted)) = swarm_sentinel_core::allow_digest(
            self.digest_window_unix_ms,
            self.digests_emitted_in_window,
            now_ms,
            rate_limit_per_sec,
        ) else {
            return false;
        };
        self.digest_window_unix_ms = window_start;
        self.digests_emitted_in_window = emitted;
        true
    }
}

fn dot(lhs: &[f64; FEATURE_DIM], rhs: &[f64; FEATURE_DIM]) -> f64 {
    lhs.iter().zip(rhs.iter()).map(|(l, r)| l * r).sum()
}

fn invert_matrix(
    mut matrix: [[f64; FEATURE_DIM]; FEATURE_DIM],
) -> Option<[[f64; FEATURE_DIM]; FEATURE_DIM]> {
    let mut inverse = [[0.0; FEATURE_DIM]; FEATURE_DIM];
    for (index, inverse_row) in inverse.iter_mut().enumerate() {
        inverse_row[index] = 1.0;
    }

    for pivot_index in 0..FEATURE_DIM {
        let mut pivot_row = pivot_index;
        let mut pivot_value = matrix[pivot_index][pivot_index].abs();
        for (row, matrix_row) in matrix.iter().enumerate().skip(pivot_index + 1) {
            let candidate = matrix_row[pivot_index].abs();
            if candidate > pivot_value {
                pivot_value = candidate;
                pivot_row = row;
            }
        }
        if pivot_value <= f64::EPSILON {
            return None;
        }
        if pivot_row != pivot_index {
            matrix.swap(pivot_row, pivot_index);
            inverse.swap(pivot_row, pivot_index);
        }
        let pivot = matrix[pivot_index][pivot_index];
        for col in 0..FEATURE_DIM {
            matrix[pivot_index][col] /= pivot;
            inverse[pivot_index][col] /= pivot;
        }
        for row in 0..FEATURE_DIM {
            if row == pivot_index {
                continue;
            }
            let factor = matrix[row][pivot_index];
            if factor.abs() <= f64::EPSILON {
                continue;
            }
            for col in 0..FEATURE_DIM {
                matrix[row][col] -= factor * matrix[pivot_index][col];
                inverse[row][col] -= factor * inverse[pivot_index][col];
            }
        }
    }

    Some(inverse)
}

fn regularize_covariance(
    mut covariance: [[f64; FEATURE_DIM]; FEATURE_DIM],
) -> [[f64; FEATURE_DIM]; FEATURE_DIM] {
    for (index, covariance_row) in covariance.iter_mut().enumerate() {
        covariance_row[index] += MAHALANOBIS_REGULARIZATION;
    }
    covariance
}

fn feature_vector_for_trace(trace: &NodeTrace) -> [f64; FEATURE_DIM] {
    [
        trace.wall_time.as_secs_f64() * 1_000.0,
        trace.allocated_bytes_after as f64,
        trace.problem_size.unwrap_or_default() as f64,
        trace.input_bytes as f64,
        trace.output_bytes as f64,
        if trace.fell_back { 1.0 } else { 0.0 },
    ]
}

fn default_true() -> bool {
    true
}

fn default_cache_flush_detection_enabled() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        true
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn cache_flush_probe_duration_ns(stage_key: &str) -> Option<f64> {
    use std::arch::asm;
    use std::sync::OnceLock;
    use std::time::Instant;

    static PROBE_BUFFER: OnceLock<Box<[u8; 64]>> = OnceLock::new();
    let buffer = PROBE_BUFFER.get_or_init(|| Box::new([0u8; 64]));
    let ptr = buffer.as_ptr();

    let started = Instant::now();
    let _ = std::hint::black_box(buffer[stage_key.len() % buffer.len()]);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    unsafe {
        asm!("dc civac, {}", in(reg) ptr, options(nostack, preserves_flags));
        asm!("dsb ish", options(nostack, preserves_flags));
        asm!("isb", options(nostack, preserves_flags));
    }
    let _ = std::hint::black_box(buffer[(stage_key.len() + 1) % buffer.len()]);
    Some(started.elapsed().as_secs_f64() * 1_000_000_000.0)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn cache_flush_probe_duration_ns(_stage_key: &str) -> Option<f64> {
    None
}

pub fn default_stage_keys() -> Vec<String> {
    let mut keys = gpu_capable_stage_keys()
        .iter()
        .map(|stage| (*stage).to_string())
        .collect::<Vec<_>>();
    for stage in [
        "witness-solve",
        "witness-check",
        "backend-prove",
        "backend-fold",
        "wrap",
        "serialize-proof",
        "buffer-transfer",
    ] {
        if !keys.iter().any(|candidate| candidate == stage) {
            keys.push(stage.to_string());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

pub fn runtime_stage_seed_state() -> BTreeMap<String, WelfordState> {
    default_stage_keys()
        .into_iter()
        .map(|stage| (stage, WelfordState::default()))
        .collect()
}

fn severity_for_score(score: f64) -> ThreatSeverity {
    if score >= 8.0 {
        ThreatSeverity::Critical
    } else if score >= 5.5 {
        ThreatSeverity::High
    } else if score >= 3.5 {
        ThreatSeverity::Moderate
    } else {
        ThreatSeverity::Low
    }
}

fn stage_hash(stage_key: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in stage_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn deterministic_jitter(now_ms: u128, config: &SentinelConfig) -> u128 {
    if config.canary_jitter_ms == 0 {
        return 0;
    }
    let span = config.canary_jitter_ms + 1;
    (now_ms ^ now_ms.rotate_left(7)) % span
}

fn baseline_commitment(stage_key: &str, baseline: &MultivariateBaseline) -> String {
    let payload = serde_json::to_vec(&(
        stage_key,
        baseline.count,
        baseline.mean,
        baseline.covariance(),
    ))
    .unwrap_or_default();
    poseidon_commitment_hex(&payload)
}

fn poseidon_commitment_hex(payload: &[u8]) -> String {
    let mut acc = Fr::from(payload.len().max(1) as u64);
    for chunk in payload.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        acc = poseidon_native_hash_two(acc, Fr::from(u64::from_le_bytes(word)));
    }
    hex_string(&acc.into_bigint().to_bytes_le())
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        output.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    output
}

fn threat_kind_label(kind: ThreatSignalKind) -> &'static str {
    match kind {
        ThreatSignalKind::WatchdogTimingAnomaly => "watchdog-timing-anomaly",
        ThreatSignalKind::WatchdogThermalThrottle => "watchdog-thermal-throttle",
        ThreatSignalKind::WatchdogMemoryPressure => "watchdog-memory-pressure",
        ThreatSignalKind::WatchdogGpuCircuitBreaker => "watchdog-gpu-circuit-breaker",
        ThreatSignalKind::RepeatedFallback => "repeated-fallback",
        ThreatSignalKind::RuntimeAnomaly => "runtime-anomaly",
        ThreatSignalKind::BaselineDriftDetected => "baseline-drift-detected",
        ThreatSignalKind::ExecutionFingerprintMismatch => "execution-fingerprint-mismatch",
        ThreatSignalKind::CanaryFailure => "canary-failure",
        ThreatSignalKind::ModelIntegrityFailure => "model-integrity-failure",
        ThreatSignalKind::ModelFreshnessDrift => "model-freshness-drift",
        ThreatSignalKind::ModelQuarantined => "model-quarantined",
        ThreatSignalKind::RateLimitViolation => "rate-limit-violation",
        ThreatSignalKind::AuthFailure => "auth-failure",
        ThreatSignalKind::MalformedRequestBurst => "malformed-request-burst",
        ThreatSignalKind::BackendIncompatibilityAttempt => "backend-incompatibility-attempt",
        ThreatSignalKind::TelemetryReplayIndicator => "telemetry-replay-indicator",
        ThreatSignalKind::TelemetryIntegrityMismatch => "telemetry-integrity-mismatch",
        ThreatSignalKind::AnonymousBurst => "anonymous-burst",
        ThreatSignalKind::SwarmThreatDigest => "swarm-threat-digest",
        ThreatSignalKind::SwarmConsensusAlert => "swarm-consensus-alert",
        ThreatSignalKind::SwarmReputationDrop => "swarm-reputation-drop",
        ThreatSignalKind::CorroboratedThreat => "corroborated-threat",
        ThreatSignalKind::ContradictionReport => "contradiction-report",
        ThreatSignalKind::AttackGenomePrefixMatch => "attack-genome-prefix-match",
        ThreatSignalKind::HoneypotAccepted => "honeypot-accepted",
    }
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn push_opt_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            push_string(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn baseline_seal_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("swarm")
        .join("baselines")
}

fn sanitize_file_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }
    sanitized.trim_matches('-').to_string()
}

fn persist_baseline_seals(stage_key: &str, seals: &[BaselineSeal]) -> std::io::Result<()> {
    let dir = baseline_seal_dir();
    fs::create_dir_all(&dir)?;
    let payload = serde_json::to_vec_pretty(seals)
        .map_err(|err| std::io::Error::other(format!("serialize baseline seals: {err}")))?;
    fs::write(
        dir.join(format!("{}.json", sanitize_file_component(stage_key))),
        payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DevicePlacement;
    use crate::memory::NodeId;
    use crate::trust::TrustModel;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", temp.path());
        }
        let result = f();
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
        }
        result
    }

    fn trace(stage_key: &str, millis: u64) -> NodeTrace {
        trace_with_features(stage_key, millis, 0, 0, 0, false)
    }

    fn trace_with_features(
        stage_key: &str,
        millis: u64,
        input_bytes: usize,
        output_bytes: usize,
        allocated_bytes_after: usize,
        fell_back: bool,
    ) -> NodeTrace {
        NodeTrace {
            node_id: NodeId::new(),
            op_name: "TestOp",
            stage_key: stage_key.to_string(),
            placement: DevicePlacement::Cpu,
            trust_model: TrustModel::Cryptographic,
            wall_time: Duration::from_millis(millis),
            problem_size: Some(1),
            input_bytes,
            output_bytes,
            predicted_cpu_ms: None,
            predicted_gpu_ms: None,
            prediction_confidence: None,
            prediction_observation_count: None,
            input_digest: [0; 8],
            output_digest: [0; 8],
            allocated_bytes_after,
            accelerator_name: None,
            fell_back,
            buffer_residency: None,
            delegated: false,
            delegated_backend: None,
        }
    }

    #[test]
    fn welford_detects_anomaly() {
        let mut state = SentinelState::new(&SentinelConfig::default(), [7; 32]);
        let config = SentinelConfig::default();
        for _ in 0..20 {
            let _ = state.observe(&trace("ntt", 10), &config);
        }
        let digest = state.observe(&trace("ntt", 40), &config);
        assert!(digest.is_some());
        assert_eq!(
            digest.expect("anomaly digest").kind,
            ThreatSignalKind::RuntimeAnomaly
        );
    }

    #[test]
    fn sentinel_respects_min_observations() {
        let config = SentinelConfig {
            min_baseline_observations: 50,
            ..SentinelConfig::default()
        };
        let mut state = SentinelState::new(&config, [9; 32]);
        for _ in 0..20 {
            let _ = state.observe(&trace("ntt", 10), &config);
        }
        assert!(state.observe(&trace("ntt", 40), &config).is_none());
    }

    #[test]
    fn sentinel_rate_limits_digests() {
        let config = SentinelConfig {
            digest_rate_limit_per_sec: 1,
            jitter_detection_enabled: false,
            cache_flush_detection_enabled: false,
            ..SentinelConfig::default()
        };
        let mut state = SentinelState::new(&config, [1; 32]);
        for _ in 0..20 {
            let _ = state.observe(&trace("ntt", 10), &config);
        }
        assert!(state.observe(&trace("ntt", 40), &config).is_some());
        assert!(state.observe(&trace("ntt", 50), &config).is_none());
    }

    #[test]
    fn sentinel_emits_digest_on_anomaly_and_buffers_it() {
        let config = SentinelConfig {
            jitter_detection_enabled: false,
            cache_flush_detection_enabled: false,
            ..SentinelConfig::default()
        };
        let mut state = SentinelState::new(&config, [3; 32]);
        for _ in 0..20 {
            let _ = state.observe(&trace("ntt", 10), &config);
        }
        let digest = state.observe(&trace("ntt", 40), &config).unwrap();
        assert_eq!(state.pending_digests.len(), 1);
        assert_eq!(
            state.pending_digests[0].stage_key_hash,
            digest.stage_key_hash
        );
    }

    #[test]
    fn jitter_state_stays_finite_for_stable_variance() {
        let mut jitter = JitterState::default();
        assert!(jitter.observe_variance_delta(0.0).is_finite());
        assert!(jitter.observe_variance_delta(0.0).is_finite());
        assert!(jitter.observe_variance_delta(0.0).is_finite());
    }

    #[test]
    fn jitter_state_detects_unstable_variance() {
        let mut jitter = JitterState::default();
        for value in [0.01, 0.01, 0.01, 0.50] {
            let _ = jitter.observe_variance_delta(value);
        }
        let z_score = jitter.observe_variance_delta(2.0);
        assert!(z_score.is_finite());
        assert!(z_score >= 0.0);
    }

    #[test]
    fn multivariate_distance_stays_non_negative() {
        let mut manifold = MultivariateBaseline::default();
        manifold.update([1.0, 10.0, 2.0, 5.0, 5.0, 0.0]);
        manifold.update([1.1, 10.2, 2.0, 5.1, 5.0, 0.0]);
        manifold.update([0.9, 9.8, 2.0, 4.9, 5.0, 0.0]);
        assert!(manifold.mahalanobis_distance([1.2, 10.1, 2.0, 5.0, 5.0, 0.0]) >= 0.0);
    }

    #[test]
    fn baseline_seal_persists_and_drift_is_detected() {
        with_temp_home(|| {
            let config = SentinelConfig {
                min_baseline_observations: 1,
                seal_every_observations: 3,
                baseline_drift_threshold: 0.5,
                jitter_detection_enabled: false,
                cache_flush_detection_enabled: false,
                ..SentinelConfig::default()
            };
            let mut state = SentinelState::new(&config, [4; 32]);
            for _ in 0..3 {
                let _ = state.observe(
                    &trace_with_features("backend-prove", 10, 32, 32, 128, false),
                    &config,
                );
            }
            let path = baseline_seal_dir().join("backend-prove.json");
            assert!(path.exists(), "baseline checkpoint should be persisted");

            for _ in 0..3 {
                let _ = state.observe(
                    &trace_with_features("backend-prove", 80, 1024, 2048, 8_192, true),
                    &config,
                );
            }
            assert!(
                state
                    .drain_digests()
                    .iter()
                    .any(|digest| digest.kind == ThreatSignalKind::BaselineDriftDetected)
            );
        });
    }

    #[test]
    fn execution_fingerprint_mismatch_emits_digest() {
        let config = SentinelConfig {
            min_baseline_observations: 3,
            fingerprint_z_threshold: 1.5,
            ..SentinelConfig::default()
        };
        let mut state = SentinelState::new(&config, [8; 32]);
        for millis in [10.0, 10.5, 9.8, 10.2] {
            let _ = state.observe_execution_fingerprint("shape-a", millis, Some("wrap"), &config);
        }
        let digest = state.observe_execution_fingerprint("shape-a", 40.0, Some("wrap"), &config);
        assert!(digest.is_some());
        assert_eq!(
            digest.expect("fingerprint mismatch").kind,
            ThreatSignalKind::ExecutionFingerprintMismatch
        );
    }

    #[test]
    fn canary_failure_is_critical() {
        let config = SentinelConfig {
            min_baseline_observations: 1,
            ..SentinelConfig::default()
        };
        let mut state = SentinelState::new(&config, [5; 32]);
        let digest = state.record_canary_result(250.0, false, &config).unwrap();
        assert_eq!(digest.kind, ThreatSignalKind::CanaryFailure);
        assert_eq!(digest.severity, ThreatSeverity::Critical);
    }

    #[test]
    fn cache_flush_probe_is_platform_safe() {
        let observed = cache_flush_probe_duration_ns("ntt");
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            assert!(
                observed
                    .expect("cache flush probe should produce a duration")
                    .is_finite()
            );
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            assert!(observed.is_none());
        }
    }
}
