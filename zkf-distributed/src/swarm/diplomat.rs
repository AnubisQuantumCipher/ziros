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

use crate::identity::PeerId;
use crate::protocol::{ReputationSyncMsg, ThreatDigestMsg, ThreatGossipMsg};
use crate::swarm::epoch::ThreatIntelPayload;
use crate::swarm::identity::PublicKeyBundle;
use crate::swarm::{decode_threat_digest, encode_threat_digest, reputation::ReputationTracker};
use crate::swarm_diplomat_core;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_runtime::SwarmTelemetryDigest;
use zkf_runtime::swarm::ThreatDigest;

const SYNTHESIS_WINDOW_MS: u64 = 60_000;
const MAX_RECENT_DIGESTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorroboratedThreatReport {
    pub stage_key_hash: u64,
    pub kind: String,
    pub severity: String,
    pub generated_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_ids: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContradictionReport {
    pub stage_key_hash: u64,
    pub reporting_peer_id: String,
    pub generated_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradicting_peer_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ThreatIntelligenceState {
    pub merkle_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corroborated_reports: Vec<CorroboratedThreatReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradiction_reports: Vec<ContradictionReport>,
    #[serde(default)]
    pub generated_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiplomatIngestResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_digests: Vec<ThreatDigestMsg>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corroborated_reports: Vec<CorroboratedThreatReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradiction_reports: Vec<ContradictionReport>,
    #[serde(default)]
    pub intelligence_root: String,
}

#[derive(Debug, Clone)]
struct ObservedDigest {
    peer_id: String,
    digest: ThreatDigestMsg,
}

pub struct Diplomat {
    gossip_max: usize,
    pending_digests: VecDeque<ThreatDigestMsg>,
    recent_digests: VecDeque<ObservedDigest>,
    known_swarm_peers: BTreeSet<String>,
    corroborated_reports: Vec<CorroboratedThreatReport>,
    contradiction_reports: Vec<ContradictionReport>,
}

impl Diplomat {
    pub fn new(gossip_max: usize) -> Self {
        Self {
            gossip_max: gossip_max.max(1),
            pending_digests: VecDeque::new(),
            recent_digests: VecDeque::new(),
            known_swarm_peers: BTreeSet::new(),
            corroborated_reports: Vec::new(),
            contradiction_reports: Vec::new(),
        }
    }

    pub fn enqueue_runtime_digests(&mut self, digests: &[ThreatDigest]) {
        for digest in digests {
            self.pending_digests.push_back(encode_threat_digest(digest));
        }
    }

    pub fn drain_heartbeat_digests(&mut self) -> Vec<ThreatDigestMsg> {
        let mut digests = Vec::new();
        for _ in 0..bounded_gossip_count(self.pending_digests.len(), self.gossip_max) {
            let Some(digest) = self.pending_digests.pop_front() else {
                break;
            };
            digests.push(digest);
        }
        digests
    }

    pub fn threat_gossip_message(
        &mut self,
        activation_level: Option<u8>,
        swarm_telemetry: Option<&SwarmTelemetryDigest>,
    ) -> ThreatGossipMsg {
        let payload = self.drain_threat_payload(activation_level, swarm_telemetry);
        ThreatGossipMsg {
            digests: payload.digests,
            activation_level: payload.activation_level,
            intelligence_root: payload.intelligence_root,
            local_pressure: payload.local_pressure,
            network_pressure: payload.network_pressure,
            encrypted_threat_payload: None,
        }
    }

    pub fn drain_threat_payload(
        &mut self,
        activation_level: Option<u8>,
        swarm_telemetry: Option<&SwarmTelemetryDigest>,
    ) -> ThreatIntelPayload {
        ThreatIntelPayload {
            digests: self.drain_heartbeat_digests(),
            activation_level,
            intelligence_root: Some(self.intelligence_state().merkle_root),
            local_pressure: swarm_telemetry.map(|telemetry| telemetry.local_threat_pressure),
            network_pressure: swarm_telemetry.map(|telemetry| telemetry.network_threat_pressure),
        }
    }

    pub fn ingest_heartbeat(
        &mut self,
        peer_id: &PeerId,
        digests: &[ThreatDigestMsg],
        activation_level: Option<u8>,
    ) -> usize {
        if !digests.is_empty() || activation_level.is_some() {
            self.known_swarm_peers.insert(peer_id.0.clone());
        }
        self.ingest_verified(peer_id, digests, activation_level)
            .accepted_digests
            .len()
    }

    pub fn ingest_verified_heartbeat(
        &mut self,
        peer_id: &PeerId,
        legacy_public_key: &[u8],
        public_key_bundle: Option<&PublicKeyBundle>,
        digests: &[ThreatDigestMsg],
        activation_level: Option<u8>,
    ) -> DiplomatIngestResult {
        let accepted = digests
            .iter()
            .filter(|digest| verify_threat_digest(legacy_public_key, public_key_bundle, digest))
            .cloned()
            .collect::<Vec<_>>();
        self.ingest_verified(peer_id, &accepted, activation_level)
    }

    pub fn ingest_threat_gossip(&mut self, peer_id: &PeerId, gossip: &ThreatGossipMsg) -> usize {
        self.ingest_verified(peer_id, &gossip.digests, gossip.activation_level)
            .accepted_digests
            .len()
    }

    pub fn ingest_verified_threat_gossip(
        &mut self,
        peer_id: &PeerId,
        legacy_public_key: &[u8],
        public_key_bundle: Option<&PublicKeyBundle>,
        gossip: &ThreatGossipMsg,
    ) -> DiplomatIngestResult {
        let accepted = gossip
            .digests
            .iter()
            .filter(|digest| verify_threat_digest(legacy_public_key, public_key_bundle, digest))
            .cloned()
            .collect::<Vec<_>>();
        self.ingest_verified(peer_id, &accepted, gossip.activation_level)
    }

    pub fn reputation_sync(&self, tracker: &ReputationTracker) -> ReputationSyncMsg {
        tracker.advisory_sync()
    }

    pub fn gossip_peer_count(&self) -> usize {
        self.known_swarm_peers.len()
    }

    pub fn intelligence_state(&self) -> ThreatIntelligenceState {
        ThreatIntelligenceState {
            merkle_root: intelligence_merkle_root(
                &self.corroborated_reports,
                &self.contradiction_reports,
            ),
            corroborated_reports: self.corroborated_reports.clone(),
            contradiction_reports: self.contradiction_reports.clone(),
            generated_unix_ms: unix_time_now_ms(),
        }
    }

    fn ingest_verified(
        &mut self,
        peer_id: &PeerId,
        digests: &[ThreatDigestMsg],
        activation_level: Option<u8>,
    ) -> DiplomatIngestResult {
        if !digests.is_empty() || activation_level.is_some() {
            self.known_swarm_peers.insert(peer_id.0.clone());
        }
        let mut corroborated_reports = Vec::new();
        let mut contradiction_reports = Vec::new();
        for digest in digests {
            self.record_observed_digest(peer_id, digest.clone());
            corroborated_reports.extend(self.synthesize_corroboration(digest));
            contradiction_reports.extend(self.synthesize_contradictions(peer_id, digest));
        }
        self.corroborated_reports
            .extend(corroborated_reports.iter().cloned());
        self.contradiction_reports
            .extend(contradiction_reports.iter().cloned());
        let intelligence_root =
            intelligence_merkle_root(&self.corroborated_reports, &self.contradiction_reports);
        DiplomatIngestResult {
            accepted_digests: digests.to_vec(),
            corroborated_reports,
            contradiction_reports,
            intelligence_root,
        }
    }

    fn record_observed_digest(&mut self, peer_id: &PeerId, digest: ThreatDigestMsg) {
        self.recent_digests.push_back(ObservedDigest {
            peer_id: peer_id.0.clone(),
            digest,
        });
        while self.recent_digests.len() > MAX_RECENT_DIGESTS {
            self.recent_digests.pop_front();
        }
        let cutoff = unix_time_now_ms().saturating_sub(u128::from(SYNTHESIS_WINDOW_MS));
        while let Some(front) = self.recent_digests.front() {
            if u128::from(front.digest.timestamp_unix_ms) >= cutoff {
                break;
            }
            self.recent_digests.pop_front();
        }
    }

    fn synthesize_corroboration(&self, digest: &ThreatDigestMsg) -> Vec<CorroboratedThreatReport> {
        let matching = self
            .recent_digests
            .iter()
            .filter(|observed| {
                observed.digest.stage_key_hash == digest.stage_key_hash
                    && observed.digest.kind == digest.kind
                    && digest
                        .timestamp_unix_ms
                        .saturating_sub(observed.digest.timestamp_unix_ms)
                        <= SYNTHESIS_WINDOW_MS
            })
            .collect::<Vec<_>>();
        let peer_ids = matching
            .iter()
            .map(|observed| observed.peer_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if peer_ids.len() < 2 {
            return Vec::new();
        }
        let report = CorroboratedThreatReport {
            stage_key_hash: digest.stage_key_hash,
            kind: digest.kind.clone(),
            severity: digest.severity.clone(),
            generated_unix_ms: unix_time_now_ms(),
            peer_ids,
            confidence: (matching.len() as f64 / 4.0).clamp(0.5, 1.0),
        };
        if self
            .corroborated_reports
            .iter()
            .rev()
            .take(8)
            .any(|existing| {
                existing.stage_key_hash == report.stage_key_hash
                    && existing.kind == report.kind
                    && existing.peer_ids == report.peer_ids
            })
        {
            Vec::new()
        } else {
            vec![report]
        }
    }

    fn synthesize_contradictions(
        &self,
        peer_id: &PeerId,
        digest: &ThreatDigestMsg,
    ) -> Vec<ContradictionReport> {
        let contradicting_peer_ids = self
            .recent_digests
            .iter()
            .filter(|observed| {
                observed.digest.stage_key_hash == digest.stage_key_hash
                    && observed.peer_id != peer_id.0
                    && digest
                        .timestamp_unix_ms
                        .saturating_sub(observed.digest.timestamp_unix_ms)
                        <= SYNTHESIS_WINDOW_MS
                    && (severity_rank(&observed.digest.severity)
                        .abs_diff(severity_rank(&digest.severity))
                        >= 2
                        || observed.digest.kind != digest.kind)
            })
            .map(|observed| observed.peer_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if contradicting_peer_ids.is_empty() {
            return Vec::new();
        }
        let report = ContradictionReport {
            stage_key_hash: digest.stage_key_hash,
            reporting_peer_id: peer_id.0.clone(),
            generated_unix_ms: unix_time_now_ms(),
            contradicting_peer_ids,
            reason: format!(
                "peer reports diverged on stage {} for kind {}",
                digest.stage_key_hash, digest.kind
            ),
        };
        if self
            .contradiction_reports
            .iter()
            .rev()
            .take(8)
            .any(|existing| {
                existing.stage_key_hash == report.stage_key_hash
                    && existing.reporting_peer_id == report.reporting_peer_id
                    && existing.contradicting_peer_ids == report.contradicting_peer_ids
            })
        {
            Vec::new()
        } else {
            vec![report]
        }
    }
}

pub(crate) fn bounded_gossip_count(pending_len: usize, gossip_max: usize) -> usize {
    swarm_diplomat_core::bounded_gossip_count(pending_len, gossip_max)
}

fn verify_threat_digest(
    legacy_public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
    digest: &ThreatDigestMsg,
) -> bool {
    let runtime_digest = decode_threat_digest(digest);
    let bytes = runtime_digest.signing_bytes();
    zkf_core::verify_signed_message(
        legacy_public_key,
        public_key_bundle,
        &bytes,
        &digest.signature,
        digest.signature_bundle.as_ref(),
        b"zkf-swarm",
    )
}

fn severity_rank(severity: &str) -> u8 {
    swarm_diplomat_core::severity_rank(severity)
}

fn intelligence_merkle_root(
    corroborated_reports: &[CorroboratedThreatReport],
    contradiction_reports: &[ContradictionReport],
) -> String {
    let mut leaves = Vec::new();
    for report in corroborated_reports {
        leaves.push(canonical_hash_leaf(report));
    }
    for report in contradiction_reports {
        leaves.push(canonical_hash_leaf(report));
    }
    swarm_diplomat_core::intelligence_merkle_root_from_leaves(leaves)
}

fn canonical_hash_leaf<T: Serialize>(value: &T) -> String {
    swarm_diplomat_core::canonical_hash_leaf(value)
}

#[allow(dead_code)]
fn canonical_json_string<T: Serialize>(value: &T) -> String {
    swarm_diplomat_core::canonical_json_string(value)
}

#[allow(dead_code)]
fn hash_bytes(bytes: &[u8]) -> String {
    swarm_diplomat_core::hash_bytes(bytes)
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
    use crate::swarm::identity::LocalPeerIdentity;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    use zkf_runtime::swarm::SwarmConfig;

    fn digest(index: u8, severity: &str, kind: &str) -> ThreatDigestMsg {
        ThreatDigestMsg {
            source_peer: [index; 32],
            source_peer_id: Some(format!("peer-{index}")),
            timestamp_unix_ms: unix_time_now_ms() as u64 + u64::from(index),
            stage_key_hash: 7,
            stage_key: Some("backend-prove".to_string()),
            severity: severity.to_string(),
            kind: kind.to_string(),
            z_score: 4.0,
            observation_count: 12,
            signature: vec![index; 64],
            signature_bundle: None,
            baseline_commitment: None,
            execution_fingerprint: None,
            detail: None,
        }
    }

    fn signed_digest(identity: &LocalPeerIdentity, index: u8, severity: &str) -> ThreatDigestMsg {
        let mut digest = digest(index, severity, "runtime-anomaly");
        let runtime_digest = decode_threat_digest(&digest);
        let signature_bundle = identity.sign_bundle(&runtime_digest.signing_bytes());
        digest.signature = signature_bundle.ed25519.clone();
        digest.signature_bundle = Some(signature_bundle);
        digest
    }

    fn with_swarm_home<T>(f: impl FnOnce(&SwarmConfig) -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_swarm = std::env::var_os("ZKF_SWARM");
        let old_backend = std::env::var_os("ZKF_SWARM_KEY_BACKEND");
        let old_policy = std::env::var_os("ZKF_SECURITY_POLICY_MODE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("ZKF_SWARM", "1");
            std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
            std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
        }
        let config = SwarmConfig::from_env();
        let result = f(&config);
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(old_swarm) = old_swarm {
                std::env::set_var("ZKF_SWARM", old_swarm);
            } else {
                std::env::remove_var("ZKF_SWARM");
            }
            if let Some(old_backend) = old_backend {
                std::env::set_var("ZKF_SWARM_KEY_BACKEND", old_backend);
            } else {
                std::env::remove_var("ZKF_SWARM_KEY_BACKEND");
            }
            if let Some(old_policy) = old_policy {
                std::env::set_var("ZKF_SECURITY_POLICY_MODE", old_policy);
            } else {
                std::env::remove_var("ZKF_SECURITY_POLICY_MODE");
            }
        }
        result
    }

    #[test]
    fn heartbeat_drain_respects_gossip_cap() {
        let mut diplomat = Diplomat::new(2);
        diplomat
            .pending_digests
            .push_back(digest(1, "high", "runtime-anomaly"));
        diplomat
            .pending_digests
            .push_back(digest(2, "high", "runtime-anomaly"));
        diplomat
            .pending_digests
            .push_back(digest(3, "high", "runtime-anomaly"));
        let drained = diplomat.drain_heartbeat_digests();
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn standalone_gossip_respects_gossip_cap() {
        let mut diplomat = Diplomat::new(1);
        diplomat
            .pending_digests
            .push_back(digest(1, "high", "runtime-anomaly"));
        diplomat
            .pending_digests
            .push_back(digest(2, "high", "runtime-anomaly"));
        let gossip = diplomat.threat_gossip_message(Some(1), None);
        assert_eq!(gossip.digests.len(), 1);
    }

    #[test]
    fn ingesting_gossip_tracks_swarm_peers() {
        let mut diplomat = Diplomat::new(2);
        let peer = PeerId("peer-a".to_string());
        diplomat.ingest_threat_gossip(
            &peer,
            &ThreatGossipMsg {
                digests: vec![digest(1, "high", "runtime-anomaly")],
                activation_level: Some(1),
                intelligence_root: None,
                local_pressure: None,
                network_pressure: None,
                encrypted_threat_payload: None,
            },
        );
        assert_eq!(diplomat.gossip_peer_count(), 1);
    }

    #[test]
    fn invalid_signature_is_rejected_by_verified_ingest() {
        with_swarm_home(|config| {
            let identity = LocalPeerIdentity::load_or_create(config, "peer-a").expect("identity");
            let mut diplomat = Diplomat::new(2);
            let peer = PeerId(identity.stable_peer_id().0);
            let result = diplomat.ingest_verified_heartbeat(
                &peer,
                &identity.public_key_bytes(),
                Some(&identity.public_key_bundle()),
                &[digest(1, "high", "runtime-anomaly")],
                Some(1),
            );
            assert!(result.accepted_digests.is_empty());
        });
    }

    #[test]
    fn valid_signature_is_accepted_by_verified_ingest() {
        with_swarm_home(|config| {
            let identity = LocalPeerIdentity::load_or_create(config, "peer-a").expect("identity");
            let mut diplomat = Diplomat::new(2);
            let peer = PeerId(identity.stable_peer_id().0);
            let result = diplomat.ingest_verified_heartbeat(
                &peer,
                &identity.public_key_bytes(),
                Some(&identity.public_key_bundle()),
                &[signed_digest(&identity, 1, "high")],
                Some(1),
            );
            assert_eq!(result.accepted_digests.len(), 1);
        });
    }

    #[test]
    fn corroborated_threat_report_is_generated_for_matching_peers() {
        with_swarm_home(|config| {
            let _identity_a =
                LocalPeerIdentity::load_or_create(config, "peer-a").expect("identity");
            let _identity_b =
                LocalPeerIdentity::load_or_create(config, "peer-b").expect("identity");
            let mut diplomat = Diplomat::new(4);

            let accepted_a = diplomat.ingest_heartbeat(
                &PeerId("peer-a".to_string()),
                &[digest(1, "high", "runtime-anomaly")],
                Some(1),
            );
            assert_eq!(accepted_a, 1);

            let accepted_b = diplomat.ingest_heartbeat(
                &PeerId("peer-b".to_string()),
                &[digest(1, "high", "runtime-anomaly")],
                Some(1),
            );
            assert_eq!(accepted_b, 1);
            let intelligence = diplomat.intelligence_state();
            assert_eq!(intelligence.corroborated_reports.len(), 1);
            assert_eq!(intelligence.corroborated_reports[0].peer_ids.len(), 2);
        });
    }

    #[test]
    fn contradiction_report_is_generated_for_divergent_peers() {
        with_swarm_home(|config| {
            let _identity_a =
                LocalPeerIdentity::load_or_create(config, "peer-a").expect("identity");
            let _identity_b =
                LocalPeerIdentity::load_or_create(config, "peer-b").expect("identity");
            let mut diplomat = Diplomat::new(4);

            let _ = diplomat.ingest_heartbeat(
                &PeerId("peer-a".to_string()),
                &[digest(1, "low", "runtime-anomaly")],
                Some(1),
            );

            let second = digest(1, "critical", "baseline-drift-detected");
            let result =
                diplomat.ingest_heartbeat(&PeerId("peer-b".to_string()), &[second], Some(1));
            assert_eq!(result, 1);
            let intelligence = diplomat.intelligence_state();
            assert_eq!(intelligence.contradiction_reports.len(), 1);
            assert_eq!(
                intelligence.contradiction_reports[0].reporting_peer_id,
                "peer-b".to_string()
            );
        });
    }

    #[test]
    fn intelligence_root_converges_under_canonical_ordering() {
        let corroborated_a = vec![
            CorroboratedThreatReport {
                stage_key_hash: 7,
                kind: "runtime-anomaly".to_string(),
                severity: "high".to_string(),
                generated_unix_ms: 1,
                peer_ids: vec!["peer-a".to_string(), "peer-b".to_string()],
                confidence: 0.75,
            },
            CorroboratedThreatReport {
                stage_key_hash: 9,
                kind: "baseline-drift-detected".to_string(),
                severity: "critical".to_string(),
                generated_unix_ms: 2,
                peer_ids: vec!["peer-c".to_string(), "peer-d".to_string()],
                confidence: 0.95,
            },
        ];
        let corroborated_b = corroborated_a.iter().rev().cloned().collect::<Vec<_>>();
        let contradictions_a = vec![ContradictionReport {
            stage_key_hash: 5,
            reporting_peer_id: "peer-z".to_string(),
            generated_unix_ms: 3,
            contradicting_peer_ids: vec!["peer-x".to_string(), "peer-y".to_string()],
            reason: "divergent".to_string(),
        }];
        let contradictions_b = contradictions_a.iter().rev().cloned().collect::<Vec<_>>();

        assert_eq!(
            intelligence_merkle_root(&corroborated_a, &contradictions_a),
            intelligence_merkle_root(&corroborated_b, &contradictions_b)
        );
    }
}
