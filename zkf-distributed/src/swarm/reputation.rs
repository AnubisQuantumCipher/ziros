use crate::error::DistributedError;
use crate::identity::PeerId;
use crate::protocol::{ReputationRecordMsg, ReputationSyncMsg};
use crate::swarm_reputation_core::{
    ReputationEvidenceKindCore, bounded_decay_score as bounded_decay_score_core,
    bounded_positive_reputation_delta as bounded_positive_reputation_delta_core,
    bounded_reputation_after_decayed_score as bounded_reputation_after_decayed_score_core,
    reputation_delta_basis_points, signed_basis_points_to_f64,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_runtime::swarm::SwarmConfig;

const MIN_REPUTATION: f64 = 0.0;
const MAX_REPUTATION: f64 = 1.0;
const NEUTRAL_REPUTATION: f64 = 0.25;
const ONE_HOUR_MS: u128 = 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReputationEvidenceKind {
    QuorumAgreement,
    QuorumDisagreement,
    AttestationValid,
    AttestationInvalid,
    HeartbeatTimeout,
    HeartbeatResumed,
    ThreatDigestCorroborated,
    ThreatDigestContradicted,
    ModelFreshnessMatch,
    ModelFreshnessMismatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReputationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_round_id: Option<String>,
    pub observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEvent {
    pub timestamp_unix_ms: u128,
    pub peer_id: String,
    pub event: ReputationEvidenceKind,
    pub evidence: ReputationEvidence,
    pub old_reputation: f64,
    pub new_reputation: f64,
    pub decay_applied: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerReputation {
    pub peer_id: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationVerificationReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    pub verified: bool,
    pub event_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct ReputationState {
    score: f64,
    last_updated_unix_ms: u128,
}

pub struct ReputationTracker {
    config: SwarmConfig,
    scores: BTreeMap<String, ReputationState>,
    positive_event_history: BTreeMap<String, Vec<(u128, f64)>>,
}

impl ReputationTracker {
    pub fn new(config: &SwarmConfig) -> Result<Self, DistributedError> {
        fs::create_dir_all(&config.reputation_log_path)?;
        let mut tracker = Self {
            config: config.clone(),
            scores: BTreeMap::new(),
            positive_event_history: BTreeMap::new(),
        };
        for event in load_events_from_dir(&tracker.config.reputation_log_path)? {
            tracker.scores.insert(
                event.peer_id.clone(),
                ReputationState {
                    score: event.new_reputation,
                    last_updated_unix_ms: event.timestamp_unix_ms,
                },
            );
            let raw_delta = event.new_reputation - event.old_reputation;
            if raw_delta > 0.0 {
                tracker
                    .positive_event_history
                    .entry(event.peer_id.clone())
                    .or_default()
                    .push((event.timestamp_unix_ms, raw_delta));
            }
        }
        Ok(tracker)
    }

    pub fn score_for(&self, peer_id: &PeerId) -> f64 {
        self.score_for_str(&peer_id.0)
    }

    pub fn score_for_str(&self, peer_id: &str) -> f64 {
        self.decayed_state_for(peer_id, unix_time_now_ms()).score
    }

    pub fn all_scores(&self) -> Vec<PeerReputation> {
        let now = unix_time_now_ms();
        self.scores
            .keys()
            .map(|peer_id| PeerReputation {
                peer_id: peer_id.clone(),
                score: self.decayed_state_for(peer_id, now).score,
            })
            .collect()
    }

    pub fn record_event(
        &mut self,
        peer_id: &PeerId,
        kind: ReputationEvidenceKind,
        evidence: ReputationEvidence,
    ) -> Result<ReputationEvent, DistributedError> {
        let now = evidence.observed_at_unix_ms.max(unix_time_now_ms());
        let prior = self.decayed_state_for(&peer_id.0, now);
        let delta = self.capped_delta_for(&peer_id.0, kind, now);
        let updated = (prior.score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        let raw_previous = self
            .scores
            .get(&peer_id.0)
            .copied()
            .unwrap_or(ReputationState {
                score: NEUTRAL_REPUTATION,
                last_updated_unix_ms: now,
            });
        let event = ReputationEvent {
            timestamp_unix_ms: now,
            peer_id: peer_id.0.clone(),
            event: kind,
            evidence,
            old_reputation: prior.score,
            new_reputation: updated,
            decay_applied: prior.score - raw_previous.score,
        };
        write_event(&self.config.reputation_log_path, &event)?;
        self.scores.insert(
            peer_id.0.clone(),
            ReputationState {
                score: updated,
                last_updated_unix_ms: now,
            },
        );
        if delta > 0.0 {
            self.positive_event_history
                .entry(peer_id.0.clone())
                .or_default()
                .push((now, delta));
        }
        Ok(event)
    }

    pub fn advisory_sync(&self) -> ReputationSyncMsg {
        ReputationSyncMsg {
            records: self
                .all_scores()
                .into_iter()
                .map(|entry| ReputationRecordMsg {
                    peer_id: entry.peer_id,
                    score: entry.score,
                    evidence: "advisory-snapshot".to_string(),
                    recorded_unix_ms: unix_time_now_ms(),
                })
                .collect(),
        }
    }

    pub fn apply_advisory_snapshot(
        &mut self,
        sync: &ReputationSyncMsg,
    ) -> Result<usize, DistributedError> {
        if sync.records.is_empty() {
            return Ok(0);
        }
        let path = self
            .config
            .reputation_log_path
            .join(format!("advisory-{}.json", unix_time_now_ms()));
        let bytes = serde_json::to_vec_pretty(sync)
            .map_err(|err| DistributedError::Serialization(err.to_string()))?;
        fs::write(path, bytes)?;
        Ok(sync.records.len())
    }

    fn decayed_state_for(&self, peer_id: &str, now_ms: u128) -> ReputationState {
        let Some(state) = self.scores.get(peer_id).copied() else {
            return ReputationState {
                score: NEUTRAL_REPUTATION,
                last_updated_unix_ms: now_ms,
            };
        };
        ReputationState {
            score: decay_score(
                state.score,
                state.last_updated_unix_ms,
                now_ms,
                self.config.reputation_decay_lambda,
            ),
            last_updated_unix_ms: now_ms,
        }
    }

    fn capped_delta_for(
        &mut self,
        peer_id: &str,
        kind: ReputationEvidenceKind,
        now_ms: u128,
    ) -> f64 {
        let requested = delta_for(kind);
        if requested <= 0.0 {
            return requested;
        }

        let history = self
            .positive_event_history
            .entry(peer_id.to_string())
            .or_default();
        history.retain(|(timestamp, _)| now_ms.saturating_sub(*timestamp) <= ONE_HOUR_MS);
        let earned_in_window = history.iter().map(|(_, delta)| *delta).sum::<f64>();
        bounded_positive_reputation_delta(
            requested,
            earned_in_window,
            self.config.reputation_hourly_cap,
        )
    }
}

pub fn load_reputation_scores() -> Result<Vec<PeerReputation>, DistributedError> {
    let config = SwarmConfig::from_env();
    Ok(ReputationTracker::new(&config)?.all_scores())
}

pub fn load_reputation_score_for(
    peer_id: &str,
) -> Result<Option<PeerReputation>, DistributedError> {
    Ok(load_reputation_scores()?
        .into_iter()
        .find(|entry| entry.peer_id == peer_id))
}

pub fn load_reputation_events() -> Result<Vec<ReputationEvent>, DistributedError> {
    let config = SwarmConfig::from_env();
    load_events_from_dir(&config.reputation_log_path)
}

pub fn load_reputation_events_for(peer_id: &str) -> Result<Vec<ReputationEvent>, DistributedError> {
    Ok(load_reputation_events()?
        .into_iter()
        .filter(|event| event.peer_id == peer_id)
        .collect())
}

pub fn verify_reputation_log() -> Result<(), DistributedError> {
    verify_reputation_log_report(None).map(|_| ())
}

pub fn verify_reputation_log_report(
    peer_id: Option<&str>,
) -> Result<ReputationVerificationReport, DistributedError> {
    let config = SwarmConfig::from_env();
    let events = load_events_from_dir(&config.reputation_log_path)?;
    let report_events = if let Some(peer_id) = peer_id {
        let filtered = events
            .iter()
            .filter(|event| event.peer_id == peer_id)
            .cloned()
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            return Err(DistributedError::Config(format!(
                "no reputation history for peer {peer_id}"
            )));
        }
        filtered
    } else {
        events
    };
    replay_and_verify_events(&report_events, &config)?;
    let score = if let Some(peer_id) = peer_id {
        Some(
            load_reputation_score_for(peer_id)?
                .map(|entry| entry.score)
                .unwrap_or(NEUTRAL_REPUTATION),
        )
    } else {
        None
    };
    Ok(ReputationVerificationReport {
        peer_id: peer_id.map(str::to_string),
        verified: true,
        event_count: report_events.len(),
        score,
    })
}

fn replay_and_verify_events(
    events: &[ReputationEvent],
    config: &SwarmConfig,
) -> Result<(), DistributedError> {
    let mut states = BTreeMap::<String, ReputationState>::new();
    for event in events {
        let previous = states
            .get(&event.peer_id)
            .copied()
            .unwrap_or(ReputationState {
                score: NEUTRAL_REPUTATION,
                last_updated_unix_ms: event.timestamp_unix_ms,
            });
        let decayed = decay_score(
            previous.score,
            previous.last_updated_unix_ms,
            event.timestamp_unix_ms,
            config.reputation_decay_lambda,
        );
        if (decayed - event.old_reputation).abs() > 0.001 {
            return Err(DistributedError::Config(format!(
                "reputation log mismatch for {} at {}: old={} expected={}",
                event.peer_id, event.timestamp_unix_ms, event.old_reputation, decayed
            )));
        }
        let expected = (decayed + delta_for(event.event)).clamp(MIN_REPUTATION, MAX_REPUTATION);
        if (expected - event.new_reputation).abs() > 0.001 {
            return Err(DistributedError::Config(format!(
                "reputation log mismatch for {} at {}: new={} expected={}",
                event.peer_id, event.timestamp_unix_ms, event.new_reputation, expected
            )));
        }
        states.insert(
            event.peer_id.clone(),
            ReputationState {
                score: event.new_reputation,
                last_updated_unix_ms: event.timestamp_unix_ms,
            },
        );
    }
    Ok(())
}

fn delta_for(kind: ReputationEvidenceKind) -> f64 {
    signed_basis_points_to_f64(reputation_delta_basis_points(proof_reputation_kind(kind)))
}

#[allow(dead_code)]
pub(crate) fn bounded_reputation_after_event(
    score: f64,
    last_updated_unix_ms: u128,
    now_unix_ms: u128,
    kind: ReputationEvidenceKind,
    lambda: f64,
) -> f64 {
    let decayed = decay_score(score, last_updated_unix_ms, now_unix_ms, lambda);
    bounded_reputation_after_decayed_score(decayed, kind)
}

#[allow(dead_code)]
pub(crate) fn bounded_reputation_after_decayed_score(
    decayed_score: f64,
    kind: ReputationEvidenceKind,
) -> f64 {
    bounded_reputation_after_decayed_score_core(decayed_score, proof_reputation_kind(kind))
}

pub(crate) fn bounded_decay_score(score: f64, decay_factor: f64) -> f64 {
    bounded_decay_score_core(score, decay_factor)
}

pub(crate) fn bounded_positive_reputation_delta(
    requested_delta: f64,
    earned_in_window: f64,
    hourly_cap: f64,
) -> f64 {
    if requested_delta <= 0.0 {
        return requested_delta;
    }
    bounded_positive_reputation_delta_core(requested_delta, earned_in_window, hourly_cap)
}

fn proof_reputation_kind(kind: ReputationEvidenceKind) -> ReputationEvidenceKindCore {
    match kind {
        ReputationEvidenceKind::QuorumAgreement => ReputationEvidenceKindCore::QuorumAgreement,
        ReputationEvidenceKind::QuorumDisagreement => {
            ReputationEvidenceKindCore::QuorumDisagreement
        }
        ReputationEvidenceKind::AttestationValid => ReputationEvidenceKindCore::AttestationValid,
        ReputationEvidenceKind::AttestationInvalid => {
            ReputationEvidenceKindCore::AttestationInvalid
        }
        ReputationEvidenceKind::HeartbeatTimeout => ReputationEvidenceKindCore::HeartbeatTimeout,
        ReputationEvidenceKind::HeartbeatResumed => ReputationEvidenceKindCore::HeartbeatResumed,
        ReputationEvidenceKind::ThreatDigestCorroborated => {
            ReputationEvidenceKindCore::ThreatDigestCorroborated
        }
        ReputationEvidenceKind::ThreatDigestContradicted => {
            ReputationEvidenceKindCore::ThreatDigestContradicted
        }
        ReputationEvidenceKind::ModelFreshnessMatch => {
            ReputationEvidenceKindCore::ModelFreshnessMatch
        }
        ReputationEvidenceKind::ModelFreshnessMismatch => {
            ReputationEvidenceKindCore::ModelFreshnessMismatch
        }
    }
}

fn decay_factor(last_updated_unix_ms: u128, now_unix_ms: u128, lambda: f64) -> f64 {
    if now_unix_ms <= last_updated_unix_ms {
        return 1.0;
    }
    let elapsed_seconds = (now_unix_ms.saturating_sub(last_updated_unix_ms)) as f64 / 1_000.0;
    (-lambda * elapsed_seconds).exp().clamp(0.0, 1.0)
}

pub(crate) fn decay_score(
    score: f64,
    last_updated_unix_ms: u128,
    now_unix_ms: u128,
    lambda: f64,
) -> f64 {
    if now_unix_ms <= last_updated_unix_ms {
        return score.clamp(MIN_REPUTATION, MAX_REPUTATION);
    }
    bounded_decay_score(
        score,
        decay_factor(last_updated_unix_ms, now_unix_ms, lambda),
    )
}

fn load_events_from_dir(dir: &Path) -> Result<Vec<ReputationEvent>, DistributedError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        if let Ok(event) = serde_json::from_slice::<ReputationEvent>(&bytes) {
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.timestamp_unix_ms);
    Ok(events)
}

fn write_event(dir: &Path, event: &ReputationEvent) -> Result<PathBuf, DistributedError> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "{}-{}.json",
        event.peer_id.replace(':', "_"),
        event.timestamp_unix_ms
    ));
    let bytes = serde_json::to_vec_pretty(event)
        .map_err(|err| DistributedError::Serialization(err.to_string()))?;
    fs::write(&path, bytes)?;
    Ok(path)
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
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
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

    #[test]
    fn reputation_decays_toward_neutral() {
        let decayed = decay_score(0.9, 0, 600_000, 0.001);
        assert!(decayed < 0.9);
        assert!(decayed > NEUTRAL_REPUTATION);
    }

    #[test]
    fn reputation_is_bounded() {
        let config = SwarmConfig::default();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        let peer = PeerId("peer-a".to_string());
        let event = ReputationEvidence {
            observed_at_unix_ms: unix_time_now_ms(),
            ..Default::default()
        };
        for _ in 0..20 {
            let _ = tracker
                .record_event(
                    &peer,
                    ReputationEvidenceKind::QuorumDisagreement,
                    event.clone(),
                )
                .unwrap();
        }
        assert!(tracker.score_for(&peer) >= 0.0);
        assert!(tracker.score_for(&peer) <= 1.0);
    }

    #[test]
    fn reputation_log_replay_verifies() {
        with_temp_home(|| {
            let config = SwarmConfig::from_env();
            let mut tracker = ReputationTracker::new(&config).unwrap();
            let peer = PeerId("peer-a".to_string());
            tracker
                .record_event(
                    &peer,
                    ReputationEvidenceKind::AttestationValid,
                    ReputationEvidence {
                        job_id: Some("job-1".to_string()),
                        partition_id: Some(0),
                        observed_at_unix_ms: unix_time_now_ms(),
                        ..Default::default()
                    },
                )
                .unwrap();
            verify_reputation_log().unwrap();
        });
    }

    #[test]
    fn advisory_snapshots_do_not_mutate_local_scores() {
        with_temp_home(|| {
            let config = SwarmConfig::from_env();
            let mut tracker = ReputationTracker::new(&config).unwrap();
            let before = tracker.score_for_str("peer-b");
            tracker
                .apply_advisory_snapshot(&ReputationSyncMsg {
                    records: vec![ReputationRecordMsg {
                        peer_id: "peer-b".to_string(),
                        score: 0.9,
                        evidence: "advisory".to_string(),
                        recorded_unix_ms: unix_time_now_ms(),
                    }],
                })
                .unwrap();
            assert_eq!(before, tracker.score_for_str("peer-b"));
        });
    }

    #[test]
    fn hourly_cap_saturates_positive_reputation_gain() {
        with_temp_home(|| {
            let config = SwarmConfig::from_env();
            let mut tracker = ReputationTracker::new(&config).unwrap();
            let peer = PeerId("peer-cap".to_string());
            for _ in 0..10 {
                tracker
                    .record_event(
                        &peer,
                        ReputationEvidenceKind::QuorumAgreement,
                        ReputationEvidence {
                            observed_at_unix_ms: 1,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            let earned = tracker.score_for(&peer);
            assert!((earned - 0.35).abs() < 0.001);
        });
    }

    #[test]
    fn negative_events_are_not_capped_by_hourly_limit() {
        with_temp_home(|| {
            let config = SwarmConfig::from_env();
            let mut tracker = ReputationTracker::new(&config).unwrap();
            let peer = PeerId("peer-negative".to_string());
            tracker
                .record_event(
                    &peer,
                    ReputationEvidenceKind::QuorumAgreement,
                    ReputationEvidence {
                        observed_at_unix_ms: 1,
                        ..Default::default()
                    },
                )
                .unwrap();
            let before = tracker.score_for(&peer);
            tracker
                .record_event(
                    &peer,
                    ReputationEvidenceKind::QuorumDisagreement,
                    ReputationEvidence {
                        observed_at_unix_ms: 2,
                        ..Default::default()
                    },
                )
                .unwrap();
            let after = tracker.score_for(&peer);
            assert!(
                after < before,
                "negative event should reduce score (before={before}, after={after})"
            );
        });
    }
}
