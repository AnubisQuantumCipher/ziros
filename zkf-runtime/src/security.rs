use crate::control_plane::{
    AnomalySeverity, ControlPlaneExecutionSummary, ModelCatalog, ModelLane, SecurityFeatureInputs,
    build_security_feature_vector, predict_numeric,
};
use crate::swarm::{ActivationLevel, SwarmVerdict, builder};
use crate::telemetry::GraphExecutionReport;
use crate::watchdog::{WatchdogAlertKind, WatchdogAlertSeverity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityPolicyMode {
    Observe,
    #[default]
    Enforce,
}

impl SecurityPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatSeverity {
    Low,
    Moderate,
    High,
    Critical,
    ModelIntegrityCritical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatSignalKind {
    WatchdogTimingAnomaly,
    WatchdogThermalThrottle,
    WatchdogMemoryPressure,
    WatchdogGpuCircuitBreaker,
    RepeatedFallback,
    RuntimeAnomaly,
    BaselineDriftDetected,
    ExecutionFingerprintMismatch,
    CanaryFailure,
    ModelIntegrityFailure,
    ModelFreshnessDrift,
    ModelQuarantined,
    RateLimitViolation,
    AuthFailure,
    MalformedRequestBurst,
    BackendIncompatibilityAttempt,
    TelemetryReplayIndicator,
    TelemetryIntegrityMismatch,
    AnonymousBurst,
    SwarmThreatDigest,
    SwarmConsensusAlert,
    SwarmReputationDrop,
    CorroboratedThreat,
    ContradictionReport,
    AttackGenomePrefixMatch,
    HoneypotAccepted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatSignal {
    pub kind: ThreatSignalKind,
    pub severity: ThreatSeverity,
    pub source: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityAction {
    Continue,
    ReduceParallelism,
    ForceCpuOnly,
    RequireStrictCryptographicLane,
    DisableHeuristicShortcuts,
    RejectJob,
    QuarantineModelBundle,
    FallbackToHeuristics,
    QuorumVerify,
    RedundantExecution,
    IsolateNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityRiskLevel {
    Low,
    Moderate,
    High,
    Critical,
    ModelIntegrityCritical,
}

impl SecurityRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::Critical => "critical",
            Self::ModelIntegrityCritical => "model-integrity-critical",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSecurityContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_identity_hash: Option<String>,
    #[serde(default)]
    pub rate_limit_violation_count: u32,
    #[serde(default)]
    pub auth_failure_count: u32,
    #[serde(default)]
    pub malformed_request_count: u32,
    #[serde(default)]
    pub backend_incompatibility_attempt_count: u32,
    #[serde(default)]
    pub anonymous_burst: bool,
    #[serde(default)]
    pub telemetry_replay_detected: bool,
    #[serde(default)]
    pub integrity_mismatch_detected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModelIntegrity {
    pub policy_mode: SecurityPolicyMode,
    pub trusted: bool,
    pub pinned: bool,
    pub allow_unpinned_dev_bypass: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lane_fingerprints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lane_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub manifest_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integrity_failures: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub freshness_notices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantined_lanes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityVerdict {
    pub risk_level: SecurityRiskLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<ThreatSignal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SecurityAction>,
    pub policy_source: String,
    pub countdown_safe: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_fingerprint: Option<String>,
    pub quarantined: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvaluation {
    pub verdict: SecurityVerdict,
    pub model_integrity: RuntimeModelIntegrity,
}

pub struct SecuritySupervisor;

impl SecuritySupervisor {
    pub fn evaluate(
        report: &GraphExecutionReport,
        control_plane: Option<&ControlPlaneExecutionSummary>,
        runtime_context: Option<&RuntimeSecurityContext>,
        swarm_verdict: Option<&SwarmVerdict>,
    ) -> SecurityEvaluation {
        let policy_mode = security_policy_mode();
        let model_catalog = control_plane.map(|summary| &summary.decision.model_catalog);
        let model_integrity = summarize_model_integrity(model_catalog, policy_mode);
        let security_inputs =
            security_feature_inputs(report, control_plane, &model_integrity, runtime_context);
        let signals = collect_signals(
            report,
            control_plane,
            runtime_context,
            &model_integrity,
            &security_inputs,
            swarm_verdict,
        );
        let risk_score = security_model_score(control_plane, &security_inputs);
        let risk_level = determine_risk_level(&signals, risk_score, &model_integrity);
        let actions = actions_for_risk_level(risk_level, &signals, swarm_verdict);
        let countdown_safe = control_plane
            .map(|summary| summary.decision.duration_estimate.countdown_safe)
            .unwrap_or(false)
            && !matches!(
                risk_level,
                SecurityRiskLevel::Critical | SecurityRiskLevel::ModelIntegrityCritical
            );
        let policy_source = if risk_score.is_some() {
            "deterministic+security-detector".to_string()
        } else {
            "deterministic-only".to_string()
        };
        let verdict = SecurityVerdict {
            risk_level,
            risk_score,
            signals: signals.clone(),
            actions,
            policy_source,
            countdown_safe,
            model_fingerprint: model_integrity
                .lane_fingerprints
                .get(ModelLane::Security.as_str())
                .cloned(),
            quarantined: !model_integrity.quarantined_lanes.is_empty(),
            reason: verdict_reason(risk_level, &signals, &model_integrity),
        };
        persist_security_side_effects(&verdict, &model_integrity);
        SecurityEvaluation {
            verdict,
            model_integrity,
        }
    }
}

fn security_policy_mode() -> SecurityPolicyMode {
    match std::env::var("ZKF_SECURITY_POLICY_MODE")
        .ok()
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("observe") => SecurityPolicyMode::Observe,
        _ => SecurityPolicyMode::Enforce,
    }
}

fn summarize_model_integrity(
    model_catalog: Option<&ModelCatalog>,
    policy_mode: SecurityPolicyMode,
) -> RuntimeModelIntegrity {
    let mut summary = RuntimeModelIntegrity {
        policy_mode,
        trusted: true,
        pinned: true,
        allow_unpinned_dev_bypass: false,
        lane_fingerprints: BTreeMap::new(),
        lane_sources: BTreeMap::new(),
        manifest_hashes: BTreeMap::new(),
        integrity_failures: Vec::new(),
        freshness_notices: Vec::new(),
        quarantined_lanes: Vec::new(),
    };
    let Some(model_catalog) = model_catalog else {
        return summary;
    };

    for descriptor in [
        model_catalog.scheduler.as_ref(),
        model_catalog.backend.as_ref(),
        model_catalog.duration.as_ref(),
        model_catalog.anomaly.as_ref(),
        model_catalog.security.as_ref(),
        model_catalog.threshold_optimizer.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        summary.pinned &= descriptor.pinned || descriptor.allow_unpinned_dev_bypass;
        summary.trusted &= descriptor.trusted && !descriptor.quarantined;
        summary.allow_unpinned_dev_bypass |= descriptor.allow_unpinned_dev_bypass;
        if let Some(fingerprint) = &descriptor.model_fingerprint {
            summary
                .lane_fingerprints
                .insert(descriptor.lane.as_str().to_string(), fingerprint.clone());
        }
        summary.lane_sources.insert(
            descriptor.lane.as_str().to_string(),
            descriptor.source.as_str().to_string(),
        );
        if let Some(manifest_hash) = &descriptor.manifest_sha256 {
            summary
                .manifest_hashes
                .insert(descriptor.lane.as_str().to_string(), manifest_hash.clone());
        }
        if let Some(notice) = &descriptor.freshness_notice {
            summary
                .freshness_notices
                .push(format!("{}: {notice}", descriptor.lane.as_str()));
        }
        if descriptor.quarantined {
            summary
                .quarantined_lanes
                .push(descriptor.lane.as_str().to_string());
        }
        for failure in &descriptor.integrity_failures {
            summary
                .integrity_failures
                .push(format!("{}: {failure}", descriptor.lane.as_str()));
        }
    }

    if !model_catalog.failures.is_empty() {
        for (lane, failure) in &model_catalog.failures {
            summary
                .integrity_failures
                .push(format!("{lane}: {failure}"));
        }
        summary.trusted = false;
        summary.pinned = false;
    }

    summary
}

fn security_feature_inputs(
    report: &GraphExecutionReport,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    model_integrity: &RuntimeModelIntegrity,
    runtime_context: Option<&RuntimeSecurityContext>,
) -> SecurityFeatureInputs {
    let mut inputs = SecurityFeatureInputs::default();
    for alert in &report.watchdog_alerts {
        match alert.severity {
            WatchdogAlertSeverity::Notice => inputs.watchdog_notice_count += 1,
            WatchdogAlertSeverity::Warning => inputs.watchdog_warning_count += 1,
            WatchdogAlertSeverity::Critical => inputs.watchdog_critical_count += 1,
        }
        match alert.kind {
            WatchdogAlertKind::TimingAnomaly => inputs.timing_alert_count += 1,
            WatchdogAlertKind::ThermalThrottle => inputs.thermal_alert_count += 1,
            WatchdogAlertKind::MemoryPressureSpike => inputs.memory_alert_count += 1,
            WatchdogAlertKind::GpuCircuitBreakerTripped => inputs.gpu_circuit_breaker_count += 1,
            WatchdogAlertKind::ProofSizeAnomaly => {}
        }
    }
    inputs.repeated_fallback_count = report.fallback_nodes;
    inputs.model_integrity_failure_count = model_integrity.integrity_failures.len();
    inputs.anomaly_severity_score = control_plane
        .map(|summary| match summary.anomaly_verdict.severity {
            AnomalySeverity::Normal => 0.0,
            AnomalySeverity::Notice => 0.25,
            AnomalySeverity::Warning => 0.65,
            AnomalySeverity::Critical => 1.0,
        })
        .unwrap_or(0.0);
    if let Some(context) = runtime_context {
        inputs.rate_limit_violation_count = context.rate_limit_violation_count as usize;
        inputs.auth_failure_count = context.auth_failure_count as usize;
        inputs.malformed_request_count = context.malformed_request_count as usize;
        inputs.backend_incompatibility_attempt_count =
            context.backend_incompatibility_attempt_count as usize;
        inputs.telemetry_replay_flag = context.telemetry_replay_detected;
        inputs.integrity_mismatch_flag = context.integrity_mismatch_detected;
        inputs.anonymous_burst_flag = context.anonymous_burst;
    }
    inputs
}

fn collect_signals(
    report: &GraphExecutionReport,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    runtime_context: Option<&RuntimeSecurityContext>,
    model_integrity: &RuntimeModelIntegrity,
    security_inputs: &SecurityFeatureInputs,
    swarm_verdict: Option<&SwarmVerdict>,
) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    for alert in &report.watchdog_alerts {
        let (kind, source) = match alert.kind {
            WatchdogAlertKind::TimingAnomaly => {
                (ThreatSignalKind::WatchdogTimingAnomaly, "watchdog")
            }
            WatchdogAlertKind::ThermalThrottle => {
                (ThreatSignalKind::WatchdogThermalThrottle, "watchdog")
            }
            WatchdogAlertKind::MemoryPressureSpike => {
                (ThreatSignalKind::WatchdogMemoryPressure, "watchdog")
            }
            WatchdogAlertKind::GpuCircuitBreakerTripped => {
                (ThreatSignalKind::WatchdogGpuCircuitBreaker, "watchdog")
            }
            WatchdogAlertKind::ProofSizeAnomaly => (ThreatSignalKind::RuntimeAnomaly, "watchdog"),
        };
        signals.push(ThreatSignal {
            kind,
            severity: match alert.severity {
                WatchdogAlertSeverity::Notice => ThreatSeverity::Moderate,
                WatchdogAlertSeverity::Warning => ThreatSeverity::High,
                WatchdogAlertSeverity::Critical => ThreatSeverity::Critical,
            },
            source: source.to_string(),
            message: alert.message.clone(),
            stage_key: alert.stage_key.clone(),
            observed_value: alert.observed_duration_ms,
            count: Some(1),
        });
    }

    if security_inputs.repeated_fallback_count >= 2 {
        signals.push(ThreatSignal {
            kind: ThreatSignalKind::RepeatedFallback,
            severity: if security_inputs.repeated_fallback_count >= 4 {
                ThreatSeverity::High
            } else {
                ThreatSeverity::Moderate
            },
            source: "runtime".to_string(),
            message: format!(
                "runtime realized {} fallback nodes during execution",
                security_inputs.repeated_fallback_count
            ),
            stage_key: None,
            observed_value: Some(security_inputs.repeated_fallback_count as f64),
            count: Some(security_inputs.repeated_fallback_count as u32),
        });
    }

    if let Some(summary) = control_plane
        && !matches!(summary.anomaly_verdict.severity, AnomalySeverity::Normal)
    {
        signals.push(ThreatSignal {
            kind: ThreatSignalKind::RuntimeAnomaly,
            severity: match summary.anomaly_verdict.severity {
                AnomalySeverity::Notice => ThreatSeverity::Moderate,
                AnomalySeverity::Warning => ThreatSeverity::High,
                AnomalySeverity::Critical => ThreatSeverity::Critical,
                AnomalySeverity::Normal => ThreatSeverity::Low,
            },
            source: "control-plane".to_string(),
            message: summary.anomaly_verdict.reason.clone(),
            stage_key: None,
            observed_value: summary.anomaly_verdict.duration_ratio,
            count: None,
        });
    }

    if let Some(summary) = control_plane {
        if !summary.decision.features.metal_available
            && (report.gpu_nodes > 0 || report.gpu_stage_busy_ratio() > 0.0)
        {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::TelemetryIntegrityMismatch,
                severity: ThreatSeverity::High,
                source: "runtime".to_string(),
                message:
                    "runtime reported GPU activity while control-plane marked Metal unavailable"
                        .to_string(),
                stage_key: None,
                observed_value: Some(report.gpu_stage_busy_ratio()),
                count: None,
            });
        }
        if report.gpu_nodes == 0
            && report.delegated_nodes == 0
            && !summary.realized_gpu_capable_stages.is_empty()
        {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::TelemetryIntegrityMismatch,
                severity: ThreatSeverity::Moderate,
                source: "runtime".to_string(),
                message:
                    "runtime marked GPU-capable stages as realized without recording any GPU nodes"
                        .to_string(),
                stage_key: None,
                observed_value: Some(summary.realized_gpu_capable_stages.len() as f64),
                count: Some(summary.realized_gpu_capable_stages.len() as u32),
            });
        }
    }

    for failure in &model_integrity.integrity_failures {
        signals.push(ThreatSignal {
            kind: ThreatSignalKind::ModelIntegrityFailure,
            severity: ThreatSeverity::ModelIntegrityCritical,
            source: "model-integrity".to_string(),
            message: failure.clone(),
            stage_key: None,
            observed_value: None,
            count: None,
        });
    }
    for notice in &model_integrity.freshness_notices {
        signals.push(ThreatSignal {
            kind: ThreatSignalKind::ModelFreshnessDrift,
            severity: ThreatSeverity::Moderate,
            source: "model-integrity".to_string(),
            message: notice.clone(),
            stage_key: None,
            observed_value: None,
            count: None,
        });
    }
    for lane in &model_integrity.quarantined_lanes {
        signals.push(ThreatSignal {
            kind: ThreatSignalKind::ModelQuarantined,
            severity: ThreatSeverity::ModelIntegrityCritical,
            source: "model-integrity".to_string(),
            message: format!("lane '{lane}' is quarantined"),
            stage_key: None,
            observed_value: None,
            count: None,
        });
    }

    if let Some(context) = runtime_context {
        if context.rate_limit_violation_count > 0 {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::RateLimitViolation,
                severity: ThreatSeverity::High,
                source: "api".to_string(),
                message: format!(
                    "caller exceeded rate limits {} time(s)",
                    context.rate_limit_violation_count
                ),
                stage_key: None,
                observed_value: Some(context.rate_limit_violation_count as f64),
                count: Some(context.rate_limit_violation_count),
            });
        }
        if context.auth_failure_count > 0 {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::AuthFailure,
                severity: ThreatSeverity::High,
                source: "api".to_string(),
                message: format!(
                    "caller accumulated {} auth failure(s)",
                    context.auth_failure_count
                ),
                stage_key: None,
                observed_value: Some(context.auth_failure_count as f64),
                count: Some(context.auth_failure_count),
            });
        }
        if context.malformed_request_count > 0 {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::MalformedRequestBurst,
                severity: ThreatSeverity::High,
                source: "api".to_string(),
                message: format!(
                    "caller submitted {} malformed request(s)",
                    context.malformed_request_count
                ),
                stage_key: None,
                observed_value: Some(context.malformed_request_count as f64),
                count: Some(context.malformed_request_count),
            });
        }
        if context.backend_incompatibility_attempt_count > 0 {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::BackendIncompatibilityAttempt,
                severity: ThreatSeverity::Moderate,
                source: "api".to_string(),
                message: format!(
                    "caller attempted {} incompatible backend selection(s)",
                    context.backend_incompatibility_attempt_count
                ),
                stage_key: None,
                observed_value: Some(context.backend_incompatibility_attempt_count as f64),
                count: Some(context.backend_incompatibility_attempt_count),
            });
        }
        if context.telemetry_replay_detected {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::TelemetryReplayIndicator,
                severity: ThreatSeverity::High,
                source: "telemetry".to_string(),
                message: "telemetry replay or duplicate sequence id detected".to_string(),
                stage_key: None,
                observed_value: None,
                count: None,
            });
        }
        if context.integrity_mismatch_detected {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::TelemetryIntegrityMismatch,
                severity: ThreatSeverity::High,
                source: "telemetry".to_string(),
                message: "telemetry integrity mismatch detected".to_string(),
                stage_key: None,
                observed_value: None,
                count: None,
            });
        }
        if context.anonymous_burst {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::AnonymousBurst,
                severity: ThreatSeverity::Moderate,
                source: "api".to_string(),
                message: "anonymous or single-identity burst behavior detected".to_string(),
                stage_key: None,
                observed_value: None,
                count: None,
            });
        }
    }

    if let Some(swarm) = swarm_verdict {
        if swarm.threat_digest_count > 0 {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::SwarmThreatDigest,
                severity: match swarm.activation_level {
                    ActivationLevel::Dormant => ThreatSeverity::Low,
                    ActivationLevel::Alert => ThreatSeverity::Moderate,
                    ActivationLevel::Active => ThreatSeverity::High,
                    ActivationLevel::Emergency => ThreatSeverity::Critical,
                },
                source: "swarm".to_string(),
                message: format!(
                    "swarm observed {} threat digest(s) at {} activation",
                    swarm.threat_digest_count,
                    swarm.activation_level.as_str()
                ),
                stage_key: None,
                observed_value: Some(swarm.threat_digest_count as f64),
                count: Some(swarm.threat_digest_count),
            });
        }
        if swarm.consensus_confirmed {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::SwarmConsensusAlert,
                severity: if swarm.activation_level >= ActivationLevel::Active {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Moderate
                },
                source: "swarm".to_string(),
                message: format!(
                    "swarm consensus confirmed an elevated threat at {} activation",
                    swarm.activation_level.as_str()
                ),
                stage_key: None,
                observed_value: Some(swarm.activation_level as u8 as f64),
                count: Some(1),
            });
        }
        if !swarm.low_reputation_peers.is_empty() {
            signals.push(ThreatSignal {
                kind: ThreatSignalKind::SwarmReputationDrop,
                severity: ThreatSeverity::Moderate,
                source: "swarm".to_string(),
                message: format!(
                    "swarm marked {} peer(s) as low reputation",
                    swarm.low_reputation_peers.len()
                ),
                stage_key: None,
                observed_value: Some(swarm.low_reputation_peers.len() as f64),
                count: Some(swarm.low_reputation_peers.len() as u32),
            });
        }
    }

    signals.sort_by_key(|signal| signal.severity);
    signals
}

fn security_model_score(
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_inputs: &SecurityFeatureInputs,
) -> Option<f64> {
    let control_plane = control_plane?;
    let descriptor = control_plane.decision.model_catalog.security.as_ref()?;
    if descriptor.quarantined {
        return None;
    }
    let shape = descriptor
        .input_shape
        .unwrap_or_else(|| descriptor.lane.supported_input_shapes()[0]);
    let feature_vector = build_security_feature_vector(
        shape,
        &control_plane.decision.features,
        Some(control_plane.decision.dispatch_plan.candidate),
        Some(control_plane.decision.backend_recommendation.selected),
        Some(control_plane.decision.backend_recommendation.objective),
        security_inputs,
    );
    predict_numeric(descriptor, &feature_vector)
        .ok()
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 1.0))
}

fn determine_risk_level(
    signals: &[ThreatSignal],
    risk_score: Option<f64>,
    model_integrity: &RuntimeModelIntegrity,
) -> SecurityRiskLevel {
    if !model_integrity.integrity_failures.is_empty()
        || !model_integrity.quarantined_lanes.is_empty()
    {
        return SecurityRiskLevel::ModelIntegrityCritical;
    }

    let strongest_signal = signals
        .iter()
        .map(|signal| signal.severity)
        .max()
        .unwrap_or(ThreatSeverity::Low);
    match strongest_signal {
        ThreatSeverity::ModelIntegrityCritical => SecurityRiskLevel::ModelIntegrityCritical,
        ThreatSeverity::Critical => SecurityRiskLevel::Critical,
        ThreatSeverity::High => {
            if risk_score.unwrap_or_default() >= 0.90 {
                SecurityRiskLevel::Critical
            } else {
                SecurityRiskLevel::High
            }
        }
        ThreatSeverity::Moderate => {
            if risk_score.unwrap_or_default() >= 0.70 {
                SecurityRiskLevel::High
            } else {
                SecurityRiskLevel::Moderate
            }
        }
        ThreatSeverity::Low => {
            let score = risk_score.unwrap_or_default();
            if score >= 0.90 {
                SecurityRiskLevel::Critical
            } else if score >= 0.70 {
                SecurityRiskLevel::High
            } else if score >= 0.40 {
                SecurityRiskLevel::Moderate
            } else {
                SecurityRiskLevel::Low
            }
        }
    }
}

fn actions_for_risk_level(
    risk_level: SecurityRiskLevel,
    signals: &[ThreatSignal],
    swarm_verdict: Option<&SwarmVerdict>,
) -> Vec<SecurityAction> {
    let gpu_related = signals.iter().any(|signal| {
        matches!(
            signal.kind,
            ThreatSignalKind::WatchdogTimingAnomaly
                | ThreatSignalKind::WatchdogThermalThrottle
                | ThreatSignalKind::WatchdogMemoryPressure
                | ThreatSignalKind::WatchdogGpuCircuitBreaker
                | ThreatSignalKind::RepeatedFallback
        )
    });
    match risk_level {
        SecurityRiskLevel::Low => vec![SecurityAction::Continue],
        SecurityRiskLevel::Moderate => {
            let mut actions = vec![SecurityAction::ReduceParallelism];
            if gpu_related {
                actions.push(SecurityAction::ForceCpuOnly);
            }
            actions
        }
        SecurityRiskLevel::High => {
            let mut actions = vec![
                SecurityAction::RequireStrictCryptographicLane,
                SecurityAction::DisableHeuristicShortcuts,
            ];
            if gpu_related {
                actions.push(SecurityAction::ForceCpuOnly);
            }
            if swarm_verdict
                .map(|verdict| verdict.activation_level >= ActivationLevel::Active)
                .unwrap_or(false)
            {
                actions.push(SecurityAction::RedundantExecution);
            }
            actions
        }
        SecurityRiskLevel::Critical => {
            let mut actions = vec![SecurityAction::RejectJob];
            if swarm_verdict
                .map(|verdict| verdict.activation_level >= ActivationLevel::Alert)
                .unwrap_or(false)
            {
                actions.push(SecurityAction::QuorumVerify);
            }
            actions
        }
        SecurityRiskLevel::ModelIntegrityCritical => vec![
            SecurityAction::QuarantineModelBundle,
            SecurityAction::FallbackToHeuristics,
            SecurityAction::IsolateNode,
        ],
    }
}

fn verdict_reason(
    risk_level: SecurityRiskLevel,
    signals: &[ThreatSignal],
    model_integrity: &RuntimeModelIntegrity,
) -> String {
    if let Some(first) = signals.last() {
        return format!("{}: {}", risk_level.as_str(), first.message);
    }
    if !model_integrity.freshness_notices.is_empty() {
        return format!(
            "{}: {}",
            risk_level.as_str(),
            model_integrity.freshness_notices[0]
        );
    }
    match risk_level {
        SecurityRiskLevel::Low => "low: no security-relevant anomalies detected".to_string(),
        SecurityRiskLevel::Moderate => {
            "moderate: deterministic supervisor observed recoverable runtime risk".to_string()
        }
        SecurityRiskLevel::High => {
            "high: deterministic supervisor recommends stricter cryptographic execution".to_string()
        }
        SecurityRiskLevel::Critical => {
            "critical: deterministic supervisor would reject this workload under enforcement".to_string()
        }
        SecurityRiskLevel::ModelIntegrityCritical => {
            "model-integrity-critical: production model trust chain failed; quarantine and fallback required".to_string()
        }
    }
}

fn persist_security_side_effects(
    verdict: &SecurityVerdict,
    model_integrity: &RuntimeModelIntegrity,
) {
    if matches!(
        verdict.risk_level,
        SecurityRiskLevel::High
            | SecurityRiskLevel::Critical
            | SecurityRiskLevel::ModelIntegrityCritical
    ) {
        let _ = write_security_event(verdict, model_integrity);
    }
    if matches!(
        verdict.risk_level,
        SecurityRiskLevel::ModelIntegrityCritical
    ) {
        for (lane, fingerprint) in &model_integrity.lane_fingerprints {
            if model_integrity
                .integrity_failures
                .iter()
                .any(|failure| failure.starts_with(&format!("{lane}:")))
            {
                let _ = write_quarantine_marker(lane, fingerprint, model_integrity);
            }
        }
    }
    let _ = builder::record_security_event(verdict, model_integrity);
}

fn write_security_event(
    verdict: &SecurityVerdict,
    model_integrity: &RuntimeModelIntegrity,
) -> Result<(), String> {
    let Some(dir) = security_events_dir() else {
        return Ok(());
    };
    fs::create_dir_all(&dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    let file_name = format!(
        "{}-{}.json",
        unix_time_now_ms(),
        verdict.risk_level.as_str()
    );
    let payload = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "zkf-runtime-security-event-v1",
        "timestamp_unix_ms": unix_time_now_ms(),
        "verdict": verdict,
        "model_integrity": model_integrity,
    }))
    .map_err(|err| format!("serialize security event: {err}"))?;
    fs::write(dir.join(file_name), payload)
        .map_err(|err| format!("write security event {}: {err}", dir.display()))
}

fn write_quarantine_marker(
    lane: &str,
    fingerprint: &str,
    model_integrity: &RuntimeModelIntegrity,
) -> Result<(), String> {
    let Some(dir) = security_quarantine_dir() else {
        return Ok(());
    };
    fs::create_dir_all(&dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "zkf-model-quarantine-v1",
        "timestamp_unix_ms": unix_time_now_ms(),
        "lane": lane,
        "fingerprint": fingerprint,
        "policy_mode": model_integrity.policy_mode.as_str(),
        "reason": "model integrity trust chain failed",
    }))
    .map_err(|err| format!("serialize quarantine marker: {err}"))?;
    fs::write(dir.join(format!("{fingerprint}.json")), payload)
        .map_err(|err| format!("write quarantine marker {}: {err}", dir.display()))
}

fn security_events_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".zkf").join("security").join("events"))
}

fn security_quarantine_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".zkf").join("security").join("quarantine"))
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{
        AnomalyVerdict, BackendRecommendation, BoundSource, CircuitFeatureProfile,
        ControlPlaneDecision, ControlPlaneFeatures, DispatchCandidate, DispatchCandidateScore,
        DispatchPlan, DurationEstimate, EtaSemantics, ExecutionRegime, JobKind,
    };
    use crate::telemetry::NodeTrace;
    use crate::trust::TrustModel;
    use crate::watchdog::{WatchdogAlert, WatchdogRecommendation};
    use std::time::Duration;
    use zkf_core::artifact::BackendKind;

    fn sample_control_plane_summary() -> ControlPlaneExecutionSummary {
        ControlPlaneExecutionSummary {
            decision: ControlPlaneDecision {
                job_kind: JobKind::Prove,
                features: ControlPlaneFeatures {
                    feature_schema: "zkf-neural-control-plane-v2".to_string(),
                    job_kind: JobKind::Prove,
                    objective: crate::control_plane::OptimizationObjective::FastestProve,
                    circuit: CircuitFeatureProfile {
                        constraint_count: 1024,
                        signal_count: 256,
                        blackbox_op_distribution: BTreeMap::new(),
                        max_constraint_degree: 2,
                        witness_size: 128,
                    },
                    stage_node_counts: BTreeMap::new(),
                    gpu_capable_stage_counts: BTreeMap::new(),
                    hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
                    chip_family: "m4".to_string(),
                    form_factor: "desktop".to_string(),
                    gpu_core_count: Some(40),
                    ane_tops: Some(38.0),
                    metal_available: true,
                    unified_memory: true,
                    ram_utilization: 0.2,
                    memory_pressure_ratio: 0.1,
                    battery_present: false,
                    on_external_power: true,
                    low_power_mode: false,
                    power_mode: "ac".to_string(),
                    thermal_pressure: Some(0.1),
                    thermal_state_celsius: Some(42.0),
                    cpu_speed_limit: Some(1.0),
                    core_frequency_mhz: Some(4050),
                    requested_backend: Some("arkworks-groth16".to_string()),
                    backend_route: Some("native-auto".to_string()),
                    program_digest_bucket: None,
                    requested_jobs: 1,
                    total_jobs: 1,
                },
                dispatch_plan: DispatchPlan::from_candidate(DispatchCandidate::Balanced),
                candidate_rankings: vec![DispatchCandidateScore {
                    candidate: DispatchCandidate::Balanced,
                    predicted_duration_ms: 120.0,
                    source: "heuristic".to_string(),
                }],
                backend_recommendation: BackendRecommendation {
                    selected: BackendKind::ArkworksGroth16,
                    objective: crate::control_plane::OptimizationObjective::FastestProve,
                    source: "heuristic".to_string(),
                    rankings: vec![],
                    notes: vec![],
                },
                duration_estimate: DurationEstimate {
                    estimate_ms: 120.0,
                    upper_bound_ms: Some(190.0),
                    predicted_wall_time_ms: 120.0,
                    source: "heuristic".to_string(),
                    execution_regime: ExecutionRegime::GpuCapable,
                    eta_semantics: EtaSemantics::HeuristicBound,
                    bound_source: BoundSource::HeuristicEnvelope,
                    countdown_safe: true,
                    note: None,
                    backend: Some(BackendKind::ArkworksGroth16),
                    dispatch_candidate: Some(DispatchCandidate::Balanced),
                },
                anomaly_baseline: AnomalyVerdict {
                    severity: AnomalySeverity::Normal,
                    source: "heuristic".to_string(),
                    reason: "baseline".to_string(),
                    predicted_anomaly_score: None,
                    advisory_estimate_ms: Some(120.0),
                    conservative_upper_bound_ms: Some(190.0),
                    execution_regime: Some(ExecutionRegime::GpuCapable),
                    eta_semantics: Some(EtaSemantics::HeuristicBound),
                    bound_source: Some(BoundSource::HeuristicEnvelope),
                    duration_interpretation: None,
                    expected_duration_ms: Some(120.0),
                    expected_duration_ratio_limit: Some(1.5),
                    observed_duration_ms: None,
                    duration_ratio: None,
                    expected_proof_size_bytes: Some(128),
                    expected_proof_size_ratio_limit: Some(2.0),
                    observed_proof_size_bytes: None,
                    proof_size_ratio: None,
                },
                model_catalog: ModelCatalog::default(),
                model_executions: vec![],
                notes: vec![],
            },
            anomaly_verdict: AnomalyVerdict {
                severity: AnomalySeverity::Warning,
                source: "heuristic".to_string(),
                reason: "timing drift".to_string(),
                predicted_anomaly_score: None,
                advisory_estimate_ms: Some(120.0),
                conservative_upper_bound_ms: Some(190.0),
                execution_regime: Some(ExecutionRegime::GpuCapable),
                eta_semantics: Some(EtaSemantics::HeuristicBound),
                bound_source: Some(BoundSource::HeuristicEnvelope),
                duration_interpretation: Some("slower-than-advisory-estimate".to_string()),
                expected_duration_ms: Some(120.0),
                expected_duration_ratio_limit: Some(1.5),
                observed_duration_ms: Some(220.0),
                duration_ratio: Some(1.83),
                expected_proof_size_bytes: Some(128),
                expected_proof_size_ratio_limit: Some(2.0),
                observed_proof_size_bytes: Some(128),
                proof_size_ratio: Some(1.0),
            },
            realized_gpu_capable_stages: vec!["msm".to_string()],
            proof_size_bytes: Some(128),
        }
    }

    fn sample_report() -> GraphExecutionReport {
        GraphExecutionReport {
            node_traces: vec![NodeTrace {
                node_id: crate::memory::NodeId::new(),
                op_name: "Msm",
                stage_key: "msm".to_string(),
                placement: crate::graph::DevicePlacement::Gpu,
                trust_model: TrustModel::Cryptographic,
                wall_time: Duration::from_millis(120),
                problem_size: Some(1),
                input_bytes: 64,
                output_bytes: 32,
                predicted_cpu_ms: Some(240.0),
                predicted_gpu_ms: Some(100.0),
                prediction_confidence: Some(0.95),
                prediction_observation_count: Some(64),
                input_digest: [0; 8],
                output_digest: [0; 8],
                allocated_bytes_after: 1024,
                accelerator_name: Some("metal-bn254-msm".to_string()),
                fell_back: false,
                buffer_residency: Some("shared".to_string()),
                delegated: false,
                delegated_backend: None,
            }],
            total_wall_time: Duration::from_millis(220),
            peak_memory_bytes: 1024,
            gpu_nodes: 1,
            cpu_nodes: 0,
            delegated_nodes: 0,
            final_trust_model: TrustModel::Cryptographic,
            fallback_nodes: 0,
            watchdog_alerts: vec![WatchdogAlert {
                kind: WatchdogAlertKind::TimingAnomaly,
                severity: WatchdogAlertSeverity::Warning,
                recommendation: WatchdogRecommendation::AdjustDispatch,
                message: "stage timing exceeded budget".to_string(),
                stage_key: Some("msm".to_string()),
                observed_duration_ms: Some(220.0),
                predicted_duration_ms: Some(120.0),
                timestamp_unix_ms: unix_time_now_ms(),
            }],
        }
    }

    #[test]
    fn security_supervisor_maps_runtime_signals_to_deterministic_actions() {
        let evaluation = SecuritySupervisor::evaluate(
            &sample_report(),
            Some(&sample_control_plane_summary()),
            None,
            None,
        );
        assert_eq!(evaluation.verdict.risk_level, SecurityRiskLevel::High);
        assert!(
            evaluation
                .verdict
                .actions
                .contains(&SecurityAction::RequireStrictCryptographicLane)
        );
    }

    #[test]
    fn security_supervisor_falls_back_without_security_model() {
        let evaluation = SecuritySupervisor::evaluate(
            &sample_report(),
            Some(&sample_control_plane_summary()),
            None,
            None,
        );
        assert_eq!(evaluation.verdict.policy_source, "deterministic-only");
        assert!(evaluation.verdict.risk_score.is_none());
    }

    #[test]
    fn model_integrity_failures_quarantine_and_fallback() {
        let mut summary = sample_control_plane_summary();
        summary
            .decision
            .model_catalog
            .failures
            .insert("scheduler".to_string(), "sidecar hash mismatch".to_string());
        let evaluation = SecuritySupervisor::evaluate(&sample_report(), Some(&summary), None, None);
        assert_eq!(
            evaluation.verdict.risk_level,
            SecurityRiskLevel::ModelIntegrityCritical
        );
        assert!(
            evaluation
                .verdict
                .actions
                .contains(&SecurityAction::FallbackToHeuristics)
        );
    }
}
