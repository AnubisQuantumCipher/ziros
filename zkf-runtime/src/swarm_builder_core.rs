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

use crate::security::{SecurityAction, ThreatSignalKind};
use crate::swarm::builder::{AttackTaxonomy, DetectionRule, RuleState};

const MIN_SHADOW_OBSERVATIONS: u64 = 50;
const MAX_SHADOW_FALSE_POSITIVE_RATE_BPS: u32 = 50;
const MAX_LIVE_FALSE_POSITIVE_RATE_BPS: u32 = 100;

pub(crate) fn classify_taxonomy(signal_kinds: &[ThreatSignalKind]) -> AttackTaxonomy {
    if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::RateLimitViolation
                | ThreatSignalKind::MalformedRequestBurst
                | ThreatSignalKind::AnonymousBurst
        )
    }) {
        AttackTaxonomy::Reconnaissance
    } else if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::AuthFailure
                | ThreatSignalKind::BackendIncompatibilityAttempt
                | ThreatSignalKind::TelemetryReplayIndicator
                | ThreatSignalKind::TelemetryIntegrityMismatch
                | ThreatSignalKind::CanaryFailure
                | ThreatSignalKind::HoneypotAccepted
        )
    }) {
        AttackTaxonomy::Injection
    } else if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::WatchdogTimingAnomaly
                | ThreatSignalKind::ExecutionFingerprintMismatch
        )
    }) {
        AttackTaxonomy::SideChannel
    } else if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::WatchdogMemoryPressure
                | ThreatSignalKind::WatchdogGpuCircuitBreaker
                | ThreatSignalKind::WatchdogThermalThrottle
                | ThreatSignalKind::RepeatedFallback
        )
    }) {
        AttackTaxonomy::ResourceExhaustion
    } else if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::ModelIntegrityFailure
                | ThreatSignalKind::ModelFreshnessDrift
                | ThreatSignalKind::ModelQuarantined
                | ThreatSignalKind::BaselineDriftDetected
                | ThreatSignalKind::CorroboratedThreat
                | ThreatSignalKind::ContradictionReport
        )
    }) {
        AttackTaxonomy::IntegrityCompromise
    } else if signal_kinds.iter().any(|kind| {
        matches!(
            kind,
            ThreatSignalKind::SwarmThreatDigest
                | ThreatSignalKind::SwarmConsensusAlert
                | ThreatSignalKind::SwarmReputationDrop
        )
    }) {
        AttackTaxonomy::Coordination
    } else {
        AttackTaxonomy::Unknown
    }
}

pub(crate) fn auto_promotion_allowed(rule: &DetectionRule) -> bool {
    !matches!(
        rule.action,
        SecurityAction::RejectJob | SecurityAction::IsolateNode
    )
}

pub(crate) fn should_queue_retrain(
    previous_corpus_record_count: Option<u64>,
    current_record_count: u64,
) -> bool {
    let Some(previous_corpus_record_count) = previous_corpus_record_count else {
        return true;
    };
    if previous_corpus_record_count == 0 {
        return true;
    }
    current_record_count
        >= previous_corpus_record_count
            .saturating_add(previous_corpus_record_count / 10)
            .max(previous_corpus_record_count + 1)
}

pub(crate) fn next_rule_state_after_shadow_observation(
    current_state: RuleState,
    shadow_observation_count: u64,
    shadow_false_positive_rate_basis_points: u32,
    auto_promote: bool,
) -> RuleState {
    if current_state == RuleState::Shadow && shadow_observation_count >= MIN_SHADOW_OBSERVATIONS {
        if shadow_false_positive_rate_basis_points > MAX_SHADOW_FALSE_POSITIVE_RATE_BPS {
            RuleState::Revoked
        } else if auto_promote {
            RuleState::Live
        } else {
            RuleState::Shadow
        }
    } else if current_state == RuleState::Live
        && shadow_observation_count >= 100
        && shadow_false_positive_rate_basis_points > MAX_LIVE_FALSE_POSITIVE_RATE_BPS
    {
        RuleState::Revoked
    } else {
        current_state
    }
}

pub(crate) fn transition_allowed(current_state: RuleState, next_state: RuleState) -> bool {
    match next_state {
        RuleState::Shadow | RuleState::Live => current_state != RuleState::Candidate,
        RuleState::Candidate | RuleState::Validated | RuleState::Revoked => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_taxonomy, next_rule_state_after_shadow_observation, should_queue_retrain,
        transition_allowed,
    };
    use crate::security::ThreatSignalKind;
    use crate::swarm::builder::{AttackTaxonomy, RuleState};

    #[test]
    fn taxonomy_classification_is_fail_closed() {
        assert_eq!(
            classify_taxonomy(&[ThreatSignalKind::MalformedRequestBurst]),
            AttackTaxonomy::Reconnaissance
        );
        assert_eq!(classify_taxonomy(&[]), AttackTaxonomy::Unknown);
    }

    #[test]
    fn retrain_threshold_requires_growth() {
        assert!(should_queue_retrain(None, 10));
        assert!(!should_queue_retrain(Some(100), 109));
        assert!(should_queue_retrain(Some(100), 110));
    }

    #[test]
    fn shadow_observation_state_machine_is_monotone() {
        assert_eq!(
            next_rule_state_after_shadow_observation(RuleState::Shadow, 50, 10, true),
            RuleState::Live
        );
        assert_eq!(
            next_rule_state_after_shadow_observation(RuleState::Shadow, 50, 60, true),
            RuleState::Revoked
        );
        assert!(!transition_allowed(RuleState::Candidate, RuleState::Live));
    }
}
