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

use crate::protocol::{ConsensusResultMsg, ConsensusVoteMsg};
use crate::swarm_consensus_core;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ConsensusCollector {
    timeout: Duration,
    votes: BTreeMap<(String, u32), Vec<ConsensusVoteMsg>>,
}

impl ConsensusCollector {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            votes: BTreeMap::new(),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn record_vote(
        &mut self,
        vote: ConsensusVoteMsg,
        min_voters: usize,
    ) -> Option<ConsensusResultMsg> {
        let key = (vote.job_id.clone(), vote.partition_id);
        let votes = self.votes.entry(key.clone()).or_default();
        votes.push(vote);
        (votes.len() >= min_voters).then(|| self.finalize_votes(&key))
    }

    pub fn finalize(
        &mut self,
        job_id: &str,
        partition_id: u32,
        min_voters: usize,
    ) -> Option<ConsensusResultMsg> {
        let key = (job_id.to_string(), partition_id);
        let votes = self.votes.get(&key)?;
        (votes.len() >= min_voters).then(|| self.finalize_votes(&key))
    }

    fn finalize_votes(&mut self, key: &(String, u32)) -> ConsensusResultMsg {
        let votes = self.votes.remove(key).unwrap_or_default();
        let accepted_count = votes.iter().filter(|vote| vote.accepted).count();
        let total = votes.len().max(1);
        let accepted = swarm_consensus_core::two_thirds_accepts(accepted_count, total);
        let severity = votes
            .iter()
            .max_by_key(|vote| swarm_consensus_core::severity_rank(&vote.severity))
            .map(|vote| vote.severity.clone())
            .unwrap_or_else(|| "low".to_string());
        ConsensusResultMsg {
            job_id: key.0.clone(),
            partition_id: key.1,
            accepted,
            severity,
            agreeing_peers: votes
                .iter()
                .filter_map(|vote| {
                    (vote.accepted == accepted).then_some(vote.voter_peer_id.clone())
                })
                .collect(),
            disagreeing_peers: votes
                .iter()
                .filter_map(|vote| {
                    (vote.accepted != accepted).then_some(vote.voter_peer_id.clone())
                })
                .collect(),
            decided_unix_ms: unix_time_now_ms(),
        }
    }
}

#[allow(dead_code)]
fn severity_rank(severity: &str) -> u8 {
    swarm_consensus_core::severity_rank(severity)
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
    fn majority_vote_is_accepted() {
        let mut collector = ConsensusCollector::new(1_000);
        let base = ConsensusVoteMsg {
            job_id: "job-1".to_string(),
            partition_id: 0,
            voter_peer_id: "a".to_string(),
            severity: "high".to_string(),
            accepted: true,
            output_digest: [1; 32],
            recorded_unix_ms: 1,
        };
        collector.record_vote(base.clone(), 3);
        collector.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: "b".to_string(),
                ..base.clone()
            },
            3,
        );
        let result = collector.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: "c".to_string(),
                accepted: false,
                ..base
            },
            3,
        );
        assert!(result.unwrap().accepted);
    }

    #[test]
    fn two_thirds_threshold_is_required() {
        let mut collector = ConsensusCollector::new(1_000);
        let base = ConsensusVoteMsg {
            job_id: "job-2".to_string(),
            partition_id: 0,
            voter_peer_id: "a".to_string(),
            severity: "high".to_string(),
            accepted: true,
            output_digest: [2; 32],
            recorded_unix_ms: 1,
        };
        collector.record_vote(base.clone(), 4);
        collector.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: "b".to_string(),
                ..base.clone()
            },
            4,
        );
        collector.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: "c".to_string(),
                accepted: false,
                ..base.clone()
            },
            4,
        );
        let result = collector.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: "d".to_string(),
                accepted: false,
                ..base
            },
            4,
        );
        assert!(!result.unwrap().accepted);
    }
}
