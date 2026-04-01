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

use super::builder::AttackTaxonomy;
use super::queen::ActivationLevel;
use crate::swarm_warrior_core;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub min_voters: usize,
    pub agreement_threshold: f64,
    pub timeout_ms: u64,
    pub reconnaissance_extra_voters: usize,
    pub emergency_min_distinct_backends: usize,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            min_voters: 3,
            agreement_threshold: 2.0 / 3.0,
            timeout_ms: 30_000,
            reconnaissance_extra_voters: 1,
            emergency_min_distinct_backends: 2,
        }
    }
}

impl QuorumConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatAdaptiveQuorumPolicy {
    pub taxonomy: AttackTaxonomy,
    pub min_voters: usize,
    pub agreement_threshold: f64,
    pub randomized_execution_order: bool,
    pub require_backend_diversity: bool,
    pub honeypot_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendQuorumResult {
    pub peer_id: String,
    pub backend_id: String,
    pub digest: [u8; 8],
    #[serde(default)]
    pub honeypot_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoneypotVerdict {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing_peers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing_backends: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WarriorDecision {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub majority_digest: Option<[u8; 8]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agreeing_peers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disagreeing_peers: Vec<String>,
    #[serde(default)]
    pub randomized_execution_order: bool,
    #[serde(default)]
    pub backend_diversification_required: bool,
    #[serde(default)]
    pub honeypot_rejected: bool,
}

pub type QuorumOutcome = WarriorDecision;

pub fn requires_quorum(
    activation_level: ActivationLevel,
    peer_reputation: f64,
    stage_anomaly_streak: u32,
    backend_trust_tier: u8,
) -> bool {
    swarm_warrior_core::requires_quorum(
        activation_level,
        (peer_reputation.clamp(0.0, 1.0) * 1000.0).round() as u32,
        stage_anomaly_streak,
        backend_trust_tier,
    )
}

pub fn threat_adaptive_policy(
    activation_level: ActivationLevel,
    taxonomy: AttackTaxonomy,
    config: &QuorumConfig,
) -> ThreatAdaptiveQuorumPolicy {
    let (
        min_voters,
        agreement_threshold_basis_points,
        randomized_execution_order,
        require_backend_diversity,
        honeypot_required,
    ) = swarm_warrior_core::adaptive_policy_adjustments(
        activation_level,
        taxonomy,
        config.min_voters,
        config.reconnaissance_extra_voters,
    );

    ThreatAdaptiveQuorumPolicy {
        taxonomy,
        min_voters,
        agreement_threshold: agreement_threshold_basis_points as f64 / 1000.0,
        randomized_execution_order,
        require_backend_diversity,
        honeypot_required,
    }
}

pub fn evaluate_quorum(results: &[(String, [u8; 8])], config: &QuorumConfig) -> WarriorDecision {
    let normalized = results
        .iter()
        .map(|(peer_id, digest)| BackendQuorumResult {
            peer_id: peer_id.clone(),
            backend_id: "default".to_string(),
            digest: *digest,
            honeypot_accepted: false,
        })
        .collect::<Vec<_>>();
    evaluate_adaptive_quorum(
        &normalized,
        ActivationLevel::Dormant,
        AttackTaxonomy::Unknown,
        config,
    )
}

pub fn evaluate_adaptive_quorum(
    results: &[BackendQuorumResult],
    activation_level: ActivationLevel,
    taxonomy: AttackTaxonomy,
    config: &QuorumConfig,
) -> WarriorDecision {
    let policy = threat_adaptive_policy(activation_level, taxonomy, config);
    let honeypot_verdict = evaluate_honeypot_acceptance(results);
    if policy.honeypot_required && !honeypot_verdict.accepted {
        return WarriorDecision {
            accepted: false,
            majority_digest: None,
            agreeing_peers: Vec::new(),
            disagreeing_peers: honeypot_verdict.failing_peers,
            randomized_execution_order: policy.randomized_execution_order,
            backend_diversification_required: policy.require_backend_diversity,
            honeypot_rejected: true,
        };
    }

    if results.len() < policy.min_voters {
        return WarriorDecision {
            accepted: false,
            majority_digest: None,
            agreeing_peers: Vec::new(),
            disagreeing_peers: results
                .iter()
                .map(|result| result.peer_id.clone())
                .collect(),
            randomized_execution_order: policy.randomized_execution_order,
            backend_diversification_required: policy.require_backend_diversity,
            honeypot_rejected: false,
        };
    }

    let distinct_backends = results
        .iter()
        .map(|result| result.backend_id.clone())
        .collect::<BTreeSet<_>>();
    if policy.require_backend_diversity
        && distinct_backends.len() < config.emergency_min_distinct_backends
    {
        return WarriorDecision {
            accepted: false,
            majority_digest: None,
            agreeing_peers: Vec::new(),
            disagreeing_peers: results
                .iter()
                .map(|result| result.peer_id.clone())
                .collect(),
            randomized_execution_order: policy.randomized_execution_order,
            backend_diversification_required: true,
            honeypot_rejected: false,
        };
    }

    let mut counts = BTreeMap::<[u8; 8], Vec<&BackendQuorumResult>>::new();
    for result in results {
        counts.entry(result.digest).or_default().push(result);
    }
    let mut selected = None;
    for (digest, peers) in counts {
        if selected
            .as_ref()
            .map(|(_, best): &([u8; 8], Vec<&BackendQuorumResult>)| peers.len() > best.len())
            .unwrap_or(true)
        {
            selected = Some((digest, peers));
        }
    }

    let Some((majority_digest, agreeing_entries)) = selected else {
        return WarriorDecision {
            accepted: false,
            majority_digest: None,
            agreeing_peers: Vec::new(),
            disagreeing_peers: Vec::new(),
            randomized_execution_order: policy.randomized_execution_order,
            backend_diversification_required: policy.require_backend_diversity,
            honeypot_rejected: false,
        };
    };

    let agreeing_peers = agreeing_entries
        .iter()
        .map(|result| result.peer_id.clone())
        .collect::<Vec<_>>();
    let disagreeing_peers = results
        .iter()
        .filter_map(|result| (result.digest != majority_digest).then_some(result.peer_id.clone()))
        .collect::<Vec<_>>();
    let agreeing_backend_count = agreeing_entries
        .iter()
        .map(|result| result.backend_id.clone())
        .collect::<BTreeSet<_>>()
        .len();
    WarriorDecision {
        accepted: swarm_warrior_core::quorum_accepts(
            agreeing_peers.len(),
            results.len(),
            (policy.agreement_threshold * 1000.0).round() as u32,
        ) && (!policy.require_backend_diversity
            || agreeing_backend_count >= config.emergency_min_distinct_backends),
        majority_digest: Some(majority_digest),
        agreeing_peers,
        disagreeing_peers,
        randomized_execution_order: policy.randomized_execution_order,
        backend_diversification_required: policy.require_backend_diversity,
        honeypot_rejected: false,
    }
}

pub fn evaluate_honeypot_acceptance(results: &[BackendQuorumResult]) -> HoneypotVerdict {
    let failing = results
        .iter()
        .filter(|result| result.honeypot_accepted)
        .collect::<Vec<_>>();
    HoneypotVerdict {
        accepted: swarm_warrior_core::honeypot_accepts(failing.len()),
        failing_peers: failing
            .iter()
            .map(|result| result.peer_id.clone())
            .collect(),
        failing_backends: failing
            .iter()
            .map(|result| result.backend_id.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_accepts_unanimous_agreement() {
        let results = vec![
            ("a".to_string(), [1; 8]),
            ("b".to_string(), [1; 8]),
            ("c".to_string(), [1; 8]),
        ];
        let decision = evaluate_quorum(&results, &QuorumConfig::default());
        assert!(decision.accepted);
        assert_eq!(decision.disagreeing_peers.len(), 0);
    }

    #[test]
    fn quorum_rejects_without_threshold() {
        let results = vec![
            ("a".to_string(), [1; 8]),
            ("b".to_string(), [2; 8]),
            ("c".to_string(), [3; 8]),
        ];
        let decision = evaluate_quorum(&results, &QuorumConfig::default());
        assert!(!decision.accepted);
    }

    #[test]
    fn reconnaissance_policy_raises_voter_count() {
        let policy = threat_adaptive_policy(
            ActivationLevel::Active,
            AttackTaxonomy::Reconnaissance,
            &QuorumConfig::default(),
        );
        assert_eq!(policy.min_voters, QuorumConfig::default().min_voters + 1);
    }

    #[test]
    fn injection_policy_requires_unanimity() {
        let results = vec![
            BackendQuorumResult {
                peer_id: "a".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [7; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "b".to_string(),
                backend_id: "plonky3".to_string(),
                digest: [7; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "c".to_string(),
                backend_id: "sp1".to_string(),
                digest: [8; 8],
                honeypot_accepted: false,
            },
        ];
        let decision = evaluate_adaptive_quorum(
            &results,
            ActivationLevel::Active,
            AttackTaxonomy::Injection,
            &QuorumConfig::default(),
        );
        assert!(!decision.accepted);
    }

    #[test]
    fn side_channel_policy_randomizes_execution_order() {
        let results = vec![
            BackendQuorumResult {
                peer_id: "a".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [7; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "b".to_string(),
                backend_id: "plonky3".to_string(),
                digest: [7; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "c".to_string(),
                backend_id: "nova".to_string(),
                digest: [7; 8],
                honeypot_accepted: false,
            },
        ];
        let decision = evaluate_adaptive_quorum(
            &results,
            ActivationLevel::Active,
            AttackTaxonomy::SideChannel,
            &QuorumConfig::default(),
        );
        assert!(decision.accepted);
        assert!(decision.randomized_execution_order);
    }

    #[test]
    fn emergency_diversification_rejects_single_backend_false_positive() {
        let results = vec![
            BackendQuorumResult {
                peer_id: "a".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [9; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "b".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [9; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "c".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [9; 8],
                honeypot_accepted: false,
            },
        ];
        let decision = evaluate_adaptive_quorum(
            &results,
            ActivationLevel::Emergency,
            AttackTaxonomy::IntegrityCompromise,
            &QuorumConfig::default(),
        );
        assert!(!decision.accepted);
        assert!(decision.backend_diversification_required);
    }

    #[test]
    fn honeypot_acceptance_triggers_lane_shutdown() {
        let results = vec![
            BackendQuorumResult {
                peer_id: "a".to_string(),
                backend_id: "arkworks".to_string(),
                digest: [9; 8],
                honeypot_accepted: false,
            },
            BackendQuorumResult {
                peer_id: "b".to_string(),
                backend_id: "plonky3".to_string(),
                digest: [9; 8],
                honeypot_accepted: true,
            },
            BackendQuorumResult {
                peer_id: "c".to_string(),
                backend_id: "nova".to_string(),
                digest: [9; 8],
                honeypot_accepted: false,
            },
        ];
        let decision = evaluate_adaptive_quorum(
            &results,
            ActivationLevel::Emergency,
            AttackTaxonomy::Injection,
            &QuorumConfig::default(),
        );
        assert!(!decision.accepted);
        assert!(decision.honeypot_rejected);
        assert_eq!(decision.disagreeing_peers, vec!["b".to_string()]);
    }
}
