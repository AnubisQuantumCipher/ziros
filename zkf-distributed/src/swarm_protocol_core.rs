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

use crate::protocol::ThreatDigestMsg;
use zkf_runtime::security::{ThreatSeverity, ThreatSignalKind};
use zkf_runtime::swarm::ThreatDigest;

pub(crate) fn encode_threat_digest(digest: &ThreatDigest) -> ThreatDigestMsg {
    ThreatDigestMsg {
        source_peer: digest.source_peer,
        source_peer_id: digest.source_peer_id.clone(),
        timestamp_unix_ms: digest.timestamp_unix_ms,
        stage_key_hash: digest.stage_key_hash,
        stage_key: digest.stage_key.clone(),
        severity: severity_to_string(digest.severity),
        kind: threat_kind_to_string(digest.kind),
        z_score: digest.z_score,
        observation_count: digest.observation_count,
        signature: digest.signature.clone(),
        #[cfg(feature = "full")]
        signature_bundle: digest.signature_bundle.clone(),
        baseline_commitment: digest.baseline_commitment.clone(),
        execution_fingerprint: digest.execution_fingerprint.clone(),
        detail: digest.detail.clone(),
    }
}

pub(crate) fn decode_threat_digest(digest: &ThreatDigestMsg) -> ThreatDigest {
    ThreatDigest {
        source_peer: digest.source_peer,
        source_peer_id: digest.source_peer_id.clone(),
        timestamp_unix_ms: digest.timestamp_unix_ms,
        stage_key_hash: digest.stage_key_hash,
        stage_key: digest.stage_key.clone(),
        severity: severity_from_string(&digest.severity),
        kind: threat_kind_from_string(&digest.kind),
        z_score: digest.z_score,
        observation_count: digest.observation_count,
        signature: digest.signature.clone(),
        #[cfg(feature = "full")]
        signature_bundle: digest.signature_bundle.clone(),
        #[cfg(not(feature = "full"))]
        signature_bundle: None,
        baseline_commitment: digest.baseline_commitment.clone(),
        execution_fingerprint: digest.execution_fingerprint.clone(),
        detail: digest.detail.clone(),
    }
}

pub(crate) fn severity_to_string(severity: ThreatSeverity) -> String {
    match severity {
        ThreatSeverity::Low => "low",
        ThreatSeverity::Moderate => "moderate",
        ThreatSeverity::High => "high",
        ThreatSeverity::Critical => "critical",
        ThreatSeverity::ModelIntegrityCritical => "model-integrity-critical",
    }
    .to_string()
}

pub(crate) fn severity_from_string(severity: &str) -> ThreatSeverity {
    match severity {
        "moderate" => ThreatSeverity::Moderate,
        "high" => ThreatSeverity::High,
        "critical" => ThreatSeverity::Critical,
        "model-integrity-critical" => ThreatSeverity::ModelIntegrityCritical,
        _ => ThreatSeverity::Low,
    }
}

pub(crate) fn threat_kind_to_string(kind: ThreatSignalKind) -> String {
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
    .to_string()
}

pub(crate) fn threat_kind_from_string(kind: &str) -> ThreatSignalKind {
    match kind {
        "watchdog-timing-anomaly" => ThreatSignalKind::WatchdogTimingAnomaly,
        "watchdog-thermal-throttle" => ThreatSignalKind::WatchdogThermalThrottle,
        "watchdog-memory-pressure" => ThreatSignalKind::WatchdogMemoryPressure,
        "watchdog-gpu-circuit-breaker" => ThreatSignalKind::WatchdogGpuCircuitBreaker,
        "repeated-fallback" => ThreatSignalKind::RepeatedFallback,
        "baseline-drift-detected" => ThreatSignalKind::BaselineDriftDetected,
        "execution-fingerprint-mismatch" => ThreatSignalKind::ExecutionFingerprintMismatch,
        "canary-failure" => ThreatSignalKind::CanaryFailure,
        "model-integrity-failure" => ThreatSignalKind::ModelIntegrityFailure,
        "model-freshness-drift" => ThreatSignalKind::ModelFreshnessDrift,
        "model-quarantined" => ThreatSignalKind::ModelQuarantined,
        "rate-limit-violation" => ThreatSignalKind::RateLimitViolation,
        "auth-failure" => ThreatSignalKind::AuthFailure,
        "malformed-request-burst" => ThreatSignalKind::MalformedRequestBurst,
        "backend-incompatibility-attempt" => ThreatSignalKind::BackendIncompatibilityAttempt,
        "telemetry-replay-indicator" => ThreatSignalKind::TelemetryReplayIndicator,
        "telemetry-integrity-mismatch" => ThreatSignalKind::TelemetryIntegrityMismatch,
        "anonymous-burst" => ThreatSignalKind::AnonymousBurst,
        "swarm-threat-digest" => ThreatSignalKind::SwarmThreatDigest,
        "swarm-consensus-alert" => ThreatSignalKind::SwarmConsensusAlert,
        "swarm-reputation-drop" => ThreatSignalKind::SwarmReputationDrop,
        "corroborated-threat" => ThreatSignalKind::CorroboratedThreat,
        "contradiction-report" => ThreatSignalKind::ContradictionReport,
        "attack-genome-prefix-match" => ThreatSignalKind::AttackGenomePrefixMatch,
        "honeypot-accepted" => ThreatSignalKind::HoneypotAccepted,
        _ => ThreatSignalKind::RuntimeAnomaly,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        severity_from_string, severity_to_string, threat_kind_from_string, threat_kind_to_string,
    };
    use zkf_runtime::security::{ThreatSeverity, ThreatSignalKind};

    #[test]
    fn severity_codec_round_trips() {
        assert_eq!(
            severity_from_string(&severity_to_string(ThreatSeverity::Critical)),
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn threat_kind_codec_round_trips() {
        assert_eq!(
            threat_kind_from_string(&threat_kind_to_string(
                ThreatSignalKind::ExecutionFingerprintMismatch
            )),
            ThreatSignalKind::ExecutionFingerprintMismatch
        );
    }
}
