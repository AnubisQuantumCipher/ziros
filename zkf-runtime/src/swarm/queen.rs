use super::config::SwarmConfig;
use super::sentinel::ThreatDigest;
use crate::security::{ThreatSeverity, ThreatSignalKind};
use crate::{swarm_artifact_core, swarm_queen_core};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActivationLevel {
    #[default]
    Dormant = 0,
    Alert = 1,
    Active = 2,
    Emergency = 3,
}

impl ActivationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Alert => "alert",
            Self::Active => "active",
            Self::Emergency => "emergency",
        }
    }
}

impl From<u8> for ActivationLevel {
    fn from(value: u8) -> Self {
        match value.min(Self::Emergency as u8) {
            0 => Self::Dormant,
            1 => Self::Alert,
            2 => Self::Active,
            _ => Self::Emergency,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueenConfig {
    pub digest_rate_threshold_per_minute: f64,
    pub cooldown_ms: u128,
    pub pressure_half_life_ms: u128,
    pub predictive_lookahead_ms: u128,
    pub escalation_memory_window_ms: u128,
    pub alert_pressure_threshold: f64,
    pub active_pressure_threshold: f64,
    pub emergency_pressure_threshold: f64,
}

impl Default for QueenConfig {
    fn default() -> Self {
        Self {
            digest_rate_threshold_per_minute: 3.0,
            cooldown_ms: 300_000,
            pressure_half_life_ms: 3_600_000,
            predictive_lookahead_ms: 300_000,
            escalation_memory_window_ms: 86_400_000,
            alert_pressure_threshold: 3.0,
            active_pressure_threshold: 6.0,
            emergency_pressure_threshold: 12.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PeerPressureReport {
    pub peer_id: String,
    pub pressure: f64,
    pub activation_level: u8,
    pub reputation: f64,
    pub reported_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EscalationMemoryRecord {
    pub incident_fingerprint: String,
    pub peak_level: ActivationLevel,
    pub peak_pressure: f64,
    pub first_seen_unix_ms: u128,
    pub last_seen_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggering_digests: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueenState {
    pub activation_level: ActivationLevel,
    pub last_escalation_unix_ms: u128,
    pub last_deescalation_unix_ms: u128,
    pub digest_rate_window: VecDeque<u128>,
    pub digest_rate_threshold: f64,
    pub cooldown_ms: u128,
    pub total_escalations: u64,
    pub total_deescalations: u64,
    pub cumulative_threat_pressure: f64,
    pub network_threat_pressure: f64,
    pub pressure_half_life_ms: u128,
    pub last_pressure_update_unix_ms: u128,
    pub predictive_lookahead_ms: u128,
    pub escalation_memory_window_ms: u128,
    pub alert_pressure_threshold: f64,
    pub active_pressure_threshold: f64,
    pub emergency_pressure_threshold: f64,
    pub pressure_history: VecDeque<(u128, f64)>,
    pub peer_pressures: BTreeMap<String, PeerPressureReport>,
    pub escalation_history: Vec<EscalationMemoryRecord>,
}

impl QueenState {
    pub fn new(config: &QueenConfig) -> Self {
        Self {
            activation_level: ActivationLevel::Dormant,
            last_escalation_unix_ms: 0,
            last_deescalation_unix_ms: 0,
            digest_rate_window: VecDeque::new(),
            digest_rate_threshold: config.digest_rate_threshold_per_minute,
            cooldown_ms: config.cooldown_ms,
            total_escalations: 0,
            total_deescalations: 0,
            cumulative_threat_pressure: 0.0,
            network_threat_pressure: 0.0,
            pressure_half_life_ms: config.pressure_half_life_ms.max(1),
            last_pressure_update_unix_ms: 0,
            predictive_lookahead_ms: config.predictive_lookahead_ms,
            escalation_memory_window_ms: config.escalation_memory_window_ms,
            alert_pressure_threshold: config.alert_pressure_threshold,
            active_pressure_threshold: config.active_pressure_threshold,
            emergency_pressure_threshold: config.emergency_pressure_threshold,
            pressure_history: VecDeque::new(),
            peer_pressures: BTreeMap::new(),
            escalation_history: Vec::new(),
        }
    }

    pub fn observe_digest(&mut self, digest: &ThreatDigest) {
        let now_ms = digest.timestamp_unix_ms as u128;
        self.tick(now_ms);
        self.digest_rate_window.push_back(now_ms);
        self.evict_old_digests(now_ms);
        self.add_pressure(
            severity_weight(digest.severity) + f64::from(digest.z_score).max(0.0) / 16.0,
            now_ms,
        );

        let incident_fingerprint = digest_incident_fingerprint(digest);
        self.apply_escalation_memory(&incident_fingerprint, now_ms);
        if matches!(
            digest.severity,
            ThreatSeverity::Critical | ThreatSeverity::ModelIntegrityCritical
        ) || matches!(digest.kind, ThreatSignalKind::CanaryFailure)
        {
            self.escalate(
                ActivationLevel::Emergency,
                now_ms,
                Some(&incident_fingerprint),
            );
            self.record_pressure_sample(now_ms);
            return;
        }

        self.update_activation(now_ms, Some(&incident_fingerprint));
    }

    pub fn observe_consensus(&mut self, confirmed: bool, severity: ThreatSeverity, now_ms: u128) {
        self.tick(now_ms);
        if confirmed {
            self.add_pressure(severity_weight(severity) + 1.0, now_ms);
            if self.activation_level <= ActivationLevel::Alert {
                self.escalate(ActivationLevel::Active, now_ms, Some("consensus"));
            }
        }
        if confirmed
            && matches!(
                severity,
                ThreatSeverity::Critical | ThreatSeverity::ModelIntegrityCritical
            )
        {
            self.escalate(ActivationLevel::Emergency, now_ms, Some("consensus"));
        } else {
            self.update_activation(now_ms, Some("consensus"));
        }
    }

    pub fn observe_peer_pressure(
        &mut self,
        peer_id: impl Into<String>,
        activation_level: u8,
        pressure: f64,
        reputation: f64,
        now_ms: u128,
    ) {
        let peer_id = peer_id.into();
        self.peer_pressures.insert(
            peer_id.clone(),
            PeerPressureReport {
                peer_id,
                pressure: pressure.max(0.0),
                activation_level,
                reputation: reputation.clamp(0.0, 1.0),
                reported_unix_ms: now_ms,
            },
        );
        self.refresh_network_pressure(now_ms);
        self.update_activation(now_ms, Some("network-pressure"));
    }

    pub fn tick(&mut self, now_ms: u128) {
        self.evict_old_digests(now_ms);
        self.decay_pressure(now_ms);
        self.refresh_network_pressure(now_ms);
        self.record_pressure_sample(now_ms);
        if self.activation_level == ActivationLevel::Dormant {
            self.update_activation(now_ms, None);
            return;
        }
        if now_ms.saturating_sub(self.last_escalation_unix_ms) < self.cooldown_ms {
            return;
        }
        self.update_activation(now_ms, None);
        self.maybe_deescalate(now_ms);
    }

    pub fn effective_pressure(&self) -> f64 {
        self.cumulative_threat_pressure
            .max(self.network_threat_pressure)
    }

    fn evict_old_digests(&mut self, now_ms: u128) {
        let cutoff = now_ms.saturating_sub(60_000);
        while let Some(front) = self.digest_rate_window.front().copied() {
            if front >= cutoff {
                break;
            }
            self.digest_rate_window.pop_front();
        }
    }

    fn decay_pressure(&mut self, now_ms: u128) {
        if self.last_pressure_update_unix_ms == 0 {
            self.last_pressure_update_unix_ms = now_ms;
            return;
        }
        let delta_ms = now_ms.saturating_sub(self.last_pressure_update_unix_ms);
        self.last_pressure_update_unix_ms = now_ms;
        if delta_ms == 0 {
            return;
        }
        let exponent = delta_ms as f64 / self.pressure_half_life_ms as f64;
        let decay = 0.5f64.powf(exponent);
        self.cumulative_threat_pressure *= decay;
        if self.cumulative_threat_pressure < 1e-6 {
            self.cumulative_threat_pressure = 0.0;
        }
    }

    fn add_pressure(&mut self, amount: f64, now_ms: u128) {
        self.decay_pressure(now_ms);
        self.cumulative_threat_pressure += amount.max(0.0);
        self.record_pressure_sample(now_ms);
    }

    fn refresh_network_pressure(&mut self, now_ms: u128) {
        let stale_cutoff = now_ms.saturating_sub(self.pressure_half_life_ms.saturating_mul(2));
        self.peer_pressures
            .retain(|_, report| report.reported_unix_ms >= stale_cutoff);
        self.network_threat_pressure = weighted_median_pressure(
            &self
                .peer_pressures
                .values()
                .map(|report| (report.pressure, report.reputation.max(0.05)))
                .collect::<Vec<_>>(),
        );
    }

    fn record_pressure_sample(&mut self, now_ms: u128) {
        let current = self.effective_pressure();
        if self
            .pressure_history
            .back()
            .map(|(timestamp, pressure)| {
                *timestamp == now_ms && (*pressure - current).abs() < f64::EPSILON
            })
            .unwrap_or(false)
        {
            return;
        }
        self.pressure_history.push_back((now_ms, current));
        while self.pressure_history.len() > 100 {
            self.pressure_history.pop_front();
        }
    }

    fn update_activation(&mut self, now_ms: u128, incident_fingerprint: Option<&str>) {
        let desired = self
            .predictive_target(now_ms)
            .max(self.level_for_pressure(self.effective_pressure()));
        if desired > self.activation_level {
            self.escalate(desired, now_ms, incident_fingerprint);
        }
    }

    fn predictive_target(&self, now_ms: u128) -> ActivationLevel {
        let Some((slope, intercept)) = pressure_regression(&self.pressure_history) else {
            return ActivationLevel::Dormant;
        };
        if slope <= 0.0 {
            return ActivationLevel::Dormant;
        }
        let lookahead_minutes = self.predictive_lookahead_ms as f64 / 60_000.0;
        let current_minutes = now_ms as f64 / 60_000.0;
        let projected = intercept + slope * (current_minutes + lookahead_minutes);
        let projected_level = self.level_for_pressure(projected);
        if projected_level > self.activation_level {
            self.next_activation_level().min(projected_level)
        } else {
            ActivationLevel::Dormant
        }
    }

    fn maybe_deescalate(&mut self, now_ms: u128) {
        let desired = self.level_for_pressure(self.effective_pressure());
        if desired >= self.activation_level {
            return;
        }
        self.deescalate(now_ms);
    }

    fn next_activation_level(&self) -> ActivationLevel {
        match self.activation_level {
            ActivationLevel::Dormant => ActivationLevel::Alert,
            ActivationLevel::Alert => ActivationLevel::Active,
            ActivationLevel::Active => ActivationLevel::Emergency,
            ActivationLevel::Emergency => ActivationLevel::Emergency,
        }
    }

    fn level_for_pressure(&self, pressure: f64) -> ActivationLevel {
        if pressure >= self.emergency_pressure_threshold {
            ActivationLevel::Emergency
        } else if pressure >= self.active_pressure_threshold {
            ActivationLevel::Active
        } else if pressure >= self.alert_pressure_threshold
            || self.digest_rate_window.len() as f64 > self.digest_rate_threshold
        {
            ActivationLevel::Alert
        } else {
            ActivationLevel::Dormant
        }
    }

    fn apply_escalation_memory(&mut self, incident_fingerprint: &str, now_ms: u128) {
        let Some(record) = self
            .escalation_history
            .iter()
            .rev()
            .find(|record| {
                record.incident_fingerprint == incident_fingerprint
                    && now_ms.saturating_sub(record.last_seen_unix_ms)
                        <= self.escalation_memory_window_ms
            })
            .cloned()
        else {
            return;
        };
        if record.peak_level > self.activation_level {
            self.escalate(record.peak_level, now_ms, Some(incident_fingerprint));
        }
    }

    fn escalate(
        &mut self,
        next: ActivationLevel,
        now_ms: u128,
        incident_fingerprint: Option<&str>,
    ) {
        if next <= self.activation_level {
            return;
        }
        self.activation_level = next;
        self.last_escalation_unix_ms = now_ms;
        self.total_escalations += 1;
        if let Some(incident_fingerprint) = incident_fingerprint {
            self.upsert_escalation_memory(incident_fingerprint, now_ms);
        }
    }

    fn deescalate(&mut self, now_ms: u128) {
        let next = match self.activation_level {
            ActivationLevel::Dormant => ActivationLevel::Dormant,
            ActivationLevel::Alert => ActivationLevel::Dormant,
            ActivationLevel::Active => ActivationLevel::Alert,
            ActivationLevel::Emergency => ActivationLevel::Active,
        };
        if next != self.activation_level {
            self.activation_level = next;
            self.last_deescalation_unix_ms = now_ms;
            self.total_deescalations += 1;
            self.last_escalation_unix_ms = now_ms;
        }
    }

    fn upsert_escalation_memory(&mut self, incident_fingerprint: &str, now_ms: u128) {
        let digest_hash = stage_hash(incident_fingerprint);
        let effective_pressure = self.effective_pressure();
        if let Some(record) = self
            .escalation_history
            .iter_mut()
            .find(|record| record.incident_fingerprint == incident_fingerprint)
        {
            record.peak_level = record.peak_level.max(self.activation_level);
            record.peak_pressure = record.peak_pressure.max(effective_pressure);
            record.last_seen_unix_ms = now_ms;
            if !record.triggering_digests.contains(&digest_hash) {
                record.triggering_digests.push(digest_hash);
            }
        } else {
            self.escalation_history.push(EscalationMemoryRecord {
                incident_fingerprint: incident_fingerprint.to_string(),
                peak_level: self.activation_level,
                peak_pressure: effective_pressure,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                triggering_digests: vec![digest_hash],
            });
        }
        self.escalation_history.retain(|record| {
            now_ms.saturating_sub(record.last_seen_unix_ms) <= self.escalation_memory_window_ms
        });
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SwarmVerdict {
    pub activation_level: ActivationLevel,
    pub threat_digest_count: u32,
    pub consensus_confirmed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub low_reputation_peers: Vec<String>,
    #[serde(default)]
    pub builder_pattern_count: u32,
    #[serde(default)]
    pub local_threat_pressure: f64,
    #[serde(default)]
    pub network_threat_pressure: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SwarmTelemetryDigest {
    pub activation_level: u8,
    pub sentinel_anomaly_count: u64,
    pub threat_digest_count: u32,
    pub builder_pattern_count: u32,
    pub gossip_peers_count: u32,
    pub queen_escalation_count: u64,
    #[serde(default)]
    pub local_threat_pressure: f64,
    #[serde(default)]
    pub network_threat_pressure: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DisabledSwarmSurfaceState {
    pub activation_level: ActivationLevel,
    pub verdict: SwarmVerdict,
    pub telemetry: Option<SwarmTelemetryDigest>,
    pub bias: f64,
}

#[derive(Debug)]
struct SwarmState {
    config: SwarmConfig,
    queen: QueenState,
    threat_digest_count: u32,
    sentinel_anomaly_count: u64,
    consensus_confirmed: bool,
    low_reputation_peers: BTreeSet<String>,
    builder_pattern_count: u32,
    gossip_peers_count: u32,
}

#[derive(Clone, Debug)]
pub struct SwarmController {
    state: Arc<Mutex<SwarmState>>,
}

impl SwarmController {
    pub fn new(config: SwarmConfig) -> Self {
        let queen = QueenState::new(&config.queen);
        set_global_activation(if config.enabled {
            queen.activation_level
        } else {
            ActivationLevel::Dormant
        });
        Self {
            state: Arc::new(Mutex::new(SwarmState {
                config,
                queen,
                threat_digest_count: 0,
                sentinel_anomaly_count: 0,
                consensus_confirmed: false,
                low_reputation_peers: BTreeSet::new(),
                builder_pattern_count: 0,
                gossip_peers_count: 0,
            })),
        }
    }

    pub fn disabled() -> Self {
        Self::new(SwarmConfig {
            enabled: false,
            ..SwarmConfig::default()
        })
    }

    pub fn config(&self) -> SwarmConfig {
        self.state
            .lock()
            .map(|state| state.config.clone())
            .unwrap_or_else(|_| SwarmConfig::default())
    }

    pub fn is_enabled(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.config.enabled)
            .unwrap_or(false)
    }

    pub fn activation_level(&self) -> ActivationLevel {
        self.state
            .lock()
            .map(|state| state.queen.activation_level)
            .unwrap_or(ActivationLevel::Dormant)
    }

    pub fn record_digests(&self, digests: &[ThreatDigest]) {
        if let Ok(mut state) = self.state.lock() {
            if !state.config.enabled {
                return;
            }
            for digest in digests {
                state.queen.observe_digest(digest);
                state.threat_digest_count = state.threat_digest_count.saturating_add(1);
                state.sentinel_anomaly_count = state.sentinel_anomaly_count.saturating_add(1);
            }
            set_global_activation(state.queen.activation_level);
        }
    }

    pub fn record_consensus_result(&self, confirmed: bool, severity: ThreatSeverity) {
        if let Ok(mut state) = self.state.lock() {
            if !state.config.enabled {
                return;
            }
            state.consensus_confirmed = confirmed;
            state
                .queen
                .observe_consensus(confirmed, severity, unix_time_now_ms());
            set_global_activation(state.queen.activation_level);
        }
    }

    pub fn record_peer_pressure(
        &self,
        peer_id: impl Into<String>,
        activation_level: u8,
        pressure: f64,
        reputation: f64,
    ) {
        if let Ok(mut state) = self.state.lock() {
            if !state.config.enabled {
                return;
            }
            state.queen.observe_peer_pressure(
                peer_id,
                activation_level,
                pressure,
                reputation,
                unix_time_now_ms(),
            );
            set_global_activation(state.queen.activation_level);
        }
    }

    pub fn note_low_reputation_peer(&self, peer_id: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.low_reputation_peers.insert(peer_id.into());
        }
    }

    pub fn note_builder_pattern_count(&self, count: u32) {
        if let Ok(mut state) = self.state.lock() {
            state.builder_pattern_count = count;
        }
    }

    pub fn note_gossip_peers_count(&self, count: u32) {
        if let Ok(mut state) = self.state.lock() {
            state.gossip_peers_count = count;
        }
    }

    pub fn verdict(&self) -> SwarmVerdict {
        self.state
            .lock()
            .map(|state| {
                if !state.config.enabled {
                    return disabled_surface_state().verdict;
                }
                SwarmVerdict {
                    activation_level: state.queen.activation_level,
                    threat_digest_count: state.threat_digest_count,
                    consensus_confirmed: state.consensus_confirmed,
                    low_reputation_peers: state.low_reputation_peers.iter().cloned().collect(),
                    builder_pattern_count: state.builder_pattern_count,
                    local_threat_pressure: state.queen.cumulative_threat_pressure,
                    network_threat_pressure: state.queen.network_threat_pressure,
                }
            })
            .unwrap_or_default()
    }

    pub fn telemetry_digest(&self) -> Option<SwarmTelemetryDigest> {
        self.state.lock().ok().and_then(|state| {
            if !state.config.enabled {
                return disabled_surface_state().telemetry;
            }
            Some(SwarmTelemetryDigest {
                activation_level: state.queen.activation_level as u8,
                sentinel_anomaly_count: state.sentinel_anomaly_count,
                threat_digest_count: state.threat_digest_count,
                builder_pattern_count: state.builder_pattern_count,
                gossip_peers_count: state.gossip_peers_count,
                queen_escalation_count: state.queen.total_escalations,
                local_threat_pressure: state.queen.cumulative_threat_pressure,
                network_threat_pressure: state.queen.network_threat_pressure,
            })
        })
    }

    pub fn current_bias(&self) -> f64 {
        if !self.is_enabled() {
            return disabled_surface_state().bias;
        }
        bias_for_level(self.activation_level())
    }

    pub fn sentinel_hook(&self) -> crate::scheduler::NodeHook {
        let this = self.clone();
        Box::new(move |_| {
            if let Ok(mut state) = this.state.lock() {
                state.queen.tick(unix_time_now_ms());
                set_global_activation(state.queen.activation_level);
            }
        })
    }
}

static GLOBAL_ACTIVATION: OnceLock<Mutex<ActivationLevel>> = OnceLock::new();

pub fn current_activation_level() -> ActivationLevel {
    GLOBAL_ACTIVATION
        .get_or_init(|| Mutex::new(ActivationLevel::Dormant))
        .lock()
        .map(|level| *level)
        .unwrap_or(ActivationLevel::Dormant)
}

pub fn current_bias() -> f64 {
    bias_for_level(current_activation_level())
}

pub(crate) fn disabled_surface_state() -> DisabledSwarmSurfaceState {
    DisabledSwarmSurfaceState {
        activation_level: ActivationLevel::Dormant,
        verdict: SwarmVerdict {
            activation_level: ActivationLevel::Dormant,
            threat_digest_count: 0,
            consensus_confirmed: false,
            low_reputation_peers: Vec::new(),
            builder_pattern_count: 0,
            local_threat_pressure: 0.0,
            network_threat_pressure: 0.0,
        },
        telemetry: None,
        bias: bias_for_level(ActivationLevel::Dormant),
    }
}

pub fn median_activation_level(levels: &[u8]) -> ActivationLevel {
    ActivationLevel::from(swarm_queen_core::median_activation_rank(levels))
}

pub fn weighted_median_pressure(values: &[(f64, f64)]) -> f64 {
    let weighted = values
        .iter()
        .map(|(value, weight)| {
            (
                swarm_queen_core::pressure_to_basis_points(*value),
                swarm_queen_core::pressure_to_basis_points((*weight).max(0.0)),
            )
        })
        .collect::<Vec<_>>();
    swarm_queen_core::basis_points_to_pressure(
        swarm_queen_core::weighted_median_pressure_basis_points(&weighted),
    )
}

#[allow(dead_code)]
pub(crate) fn preserve_successful_artifact<T>(artifact: T) -> T {
    swarm_artifact_core::preserve_successful_artifact(artifact)
}

#[cfg(any(test, kani))]
#[allow(dead_code)]
pub(crate) fn controller_artifact_path(
    enabled: bool,
    artifact: [u8; 4],
    reject: bool,
) -> Result<[u8; 4], ()> {
    swarm_artifact_core::controller_artifact_path(enabled, artifact, reject)
}

fn pressure_regression(history: &VecDeque<(u128, f64)>) -> Option<(f64, f64)> {
    if history.len() < 4 {
        return None;
    }
    let xs = history
        .iter()
        .map(|(timestamp, _)| *timestamp as f64 / 60_000.0)
        .collect::<Vec<_>>();
    let ys = history
        .iter()
        .map(|(_, pressure)| *pressure)
        .collect::<Vec<_>>();
    let count = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / count;
    let mean_y = ys.iter().sum::<f64>() / count;
    let numerator = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum::<f64>();
    let denominator = xs
        .iter()
        .map(|x| {
            let delta = x - mean_x;
            delta * delta
        })
        .sum::<f64>();
    if denominator <= f64::EPSILON {
        return None;
    }
    let slope = numerator / denominator;
    let intercept = mean_y - slope * mean_x;
    if !slope.is_finite() || !intercept.is_finite() {
        return None;
    }
    Some((slope, intercept))
}

fn digest_incident_fingerprint(digest: &ThreatDigest) -> String {
    format!(
        "{}:{}",
        threat_kind_label(digest.kind),
        digest.stage_key_hash
    )
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

fn severity_weight(severity: ThreatSeverity) -> f64 {
    swarm_queen_core::basis_points_to_pressure(swarm_queen_core::severity_weight_basis_points(
        severity,
    ))
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

fn set_global_activation(level: ActivationLevel) {
    if let Ok(mut guard) = GLOBAL_ACTIVATION
        .get_or_init(|| Mutex::new(ActivationLevel::Dormant))
        .lock()
    {
        *guard = level;
    }
}

fn bias_for_level(level: ActivationLevel) -> f64 {
    swarm_queen_core::bias_basis_points(level) as f64 / 1000.0
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

    fn digest(timestamp: u64, severity: ThreatSeverity) -> ThreatDigest {
        ThreatDigest {
            source_peer: [1; 32],
            source_peer_id: Some("peer-a".to_string()),
            timestamp_unix_ms: timestamp,
            stage_key_hash: 42,
            stage_key: Some("backend-prove".to_string()),
            severity,
            kind: ThreatSignalKind::RuntimeAnomaly,
            z_score: 4.0,
            observation_count: 12,
            signature: vec![0; 64],
            signature_bundle: None,
            baseline_commitment: None,
            execution_fingerprint: None,
            detail: None,
        }
    }

    #[test]
    fn queen_escalates_on_digest_rate() {
        let mut queen = QueenState::new(&QueenConfig::default());
        queen.observe_digest(&digest(1_000, ThreatSeverity::High));
        queen.observe_digest(&digest(2_000, ThreatSeverity::High));
        assert_eq!(queen.activation_level, ActivationLevel::Alert);
    }

    #[test]
    fn queen_escalates_on_consensus() {
        let mut queen = QueenState::new(&QueenConfig::default());
        queen.observe_consensus(true, ThreatSeverity::High, 10_000);
        assert_eq!(queen.activation_level, ActivationLevel::Active);
    }

    #[test]
    fn queen_deescalates_after_cooldown() {
        let mut queen = QueenState::new(&QueenConfig {
            cooldown_ms: 10,
            ..QueenConfig::default()
        });
        queen.observe_consensus(true, ThreatSeverity::High, 10_000);
        queen.cumulative_threat_pressure = 0.0;
        queen.tick(10_020);
        assert_eq!(queen.activation_level, ActivationLevel::Alert);
    }

    #[test]
    fn queen_starts_dormant() {
        let queen = QueenState::new(&QueenConfig::default());
        assert_eq!(queen.activation_level, ActivationLevel::Dormant);
    }

    #[test]
    fn queen_never_skips_deescalation_levels() {
        let mut queen = QueenState::new(&QueenConfig {
            cooldown_ms: 10,
            ..QueenConfig::default()
        });
        queen.observe_consensus(true, ThreatSeverity::Critical, 10_000);
        assert_eq!(queen.activation_level, ActivationLevel::Emergency);
        queen.cumulative_threat_pressure = 0.0;
        queen.tick(10_020);
        assert_eq!(queen.activation_level, ActivationLevel::Active);
        queen.tick(10_040);
        assert_eq!(queen.activation_level, ActivationLevel::Alert);
    }

    #[test]
    fn kill_switch_keeps_controller_dormant() {
        let mut config = SwarmConfig::default();
        config.enabled = false;
        let controller = SwarmController::new(config);
        controller.record_digests(&[digest(1_000, ThreatSeverity::Critical)]);
        assert_eq!(controller.activation_level(), ActivationLevel::Dormant);
        assert!(controller.telemetry_digest().is_none());
    }

    #[test]
    fn weighted_median_defaults_to_zero_for_empty_input() {
        assert_eq!(weighted_median_pressure(&[]), 0.0);
    }

    #[test]
    fn weighted_median_prefers_more_reputable_peer_pressure() {
        let value = weighted_median_pressure(&[(1.0, 0.2), (8.0, 0.9), (2.0, 0.3)]);
        assert_eq!(value, 8.0);
    }

    #[test]
    fn cumulative_pressure_accumulates_sub_threshold_activity() {
        let mut queen = QueenState::new(&QueenConfig {
            alert_pressure_threshold: 2.0,
            predictive_lookahead_ms: 0,
            ..QueenConfig::default()
        });
        queen.observe_digest(&digest(1_000, ThreatSeverity::Low));
        queen.observe_digest(&digest(2_000, ThreatSeverity::Low));
        queen.observe_digest(&digest(3_000, ThreatSeverity::Low));
        assert_eq!(queen.activation_level, ActivationLevel::Alert);
        assert!(queen.cumulative_threat_pressure > 0.0);
    }

    #[test]
    fn predictive_escalation_acts_before_crossing_threshold() {
        let mut queen = QueenState::new(&QueenConfig {
            predictive_lookahead_ms: 60_000,
            alert_pressure_threshold: 100.0,
            active_pressure_threshold: 10.0,
            ..QueenConfig::default()
        });
        queen
            .pressure_history
            .extend([(1_000, 5.0), (16_000, 6.0), (31_000, 7.0), (61_000, 9.5)]);
        queen.cumulative_threat_pressure = 9.5;
        queen.update_activation(61_000, Some("predictive"));
        assert_eq!(queen.activation_level, ActivationLevel::Alert);
    }

    #[test]
    fn escalation_memory_reuses_prior_peak() {
        let mut queen = QueenState::new(&QueenConfig {
            escalation_memory_window_ms: 100_000,
            ..QueenConfig::default()
        });
        let mut first = digest(1_000, ThreatSeverity::Critical);
        first.stage_key_hash = 9;
        queen.observe_digest(&first);
        queen.activation_level = ActivationLevel::Dormant;
        queen.cumulative_threat_pressure = 0.0;

        let mut second = digest(2_000, ThreatSeverity::Low);
        second.stage_key_hash = 9;
        queen.observe_digest(&second);
        assert_eq!(queen.activation_level, ActivationLevel::Emergency);
    }

    #[test]
    fn median_activation_defaults_to_dormant_for_empty_input() {
        assert_eq!(median_activation_level(&[]), ActivationLevel::Dormant);
    }

    #[test]
    fn median_activation_uses_upper_median_for_even_inputs() {
        assert_eq!(
            median_activation_level(&[0, 1, 2, 3]),
            ActivationLevel::Active
        );
    }

    #[test]
    fn median_activation_cannot_be_suppressed_by_single_dormant_outlier() {
        assert_eq!(
            median_activation_level(&[
                ActivationLevel::Dormant as u8,
                ActivationLevel::Active as u8,
                ActivationLevel::Active as u8,
            ]),
            ActivationLevel::Active
        );
    }
}
