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

//! Health monitoring: heartbeat tracking and liveness detection.

use crate::identity::{PeerId, PeerState, PressureLevel};
use std::collections::HashMap;
use std::time::Duration;

/// Tracks peer health via heartbeats.
pub struct HealthMonitor {
    peers: HashMap<String, PeerState>,
    heartbeat_timeout: Duration,
}

impl HealthMonitor {
    pub fn new(heartbeat_timeout: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            heartbeat_timeout,
        }
    }

    /// Register or update a peer.
    pub fn update_peer(&mut self, peer: PeerState) {
        self.peers.insert(peer.capability.peer_id.0.clone(), peer);
    }

    /// Record a heartbeat from a peer.
    pub fn record_heartbeat(
        &mut self,
        peer_id: &PeerId,
        pressure: PressureLevel,
        active_subgraph_count: u32,
        current_buffer_bytes: u64,
        swarm_activation_level: Option<u8>,
    ) {
        if let Some(state) = self.peers.get_mut(&peer_id.0) {
            state.record_heartbeat(
                pressure,
                active_subgraph_count,
                current_buffer_bytes,
                swarm_activation_level,
            );
        }
    }

    /// Mark a peer as dead.
    pub fn mark_dead(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(&peer_id.0) {
            state.alive = false;
        }
    }

    /// Check all peers for timeouts and mark dead ones.
    pub fn check_liveness(&mut self) -> Vec<PeerId> {
        let mut dead = Vec::new();
        for state in self.peers.values_mut() {
            if state.alive && state.is_timed_out(self.heartbeat_timeout) {
                state.alive = false;
                dead.push(state.capability.peer_id.clone());
                log::warn!(
                    "peer {} timed out (no heartbeat for {:?})",
                    state.capability.peer_id,
                    self.heartbeat_timeout
                );
            }
        }
        dead
    }

    /// Get all currently alive peers.
    pub fn alive_peers(&self) -> Vec<&PeerState> {
        self.peers.values().filter(|p| p.alive).collect()
    }

    pub fn alive_swarm_activation_levels(&self) -> Vec<u8> {
        self.peers
            .values()
            .filter(|peer| peer.alive && peer.swarm_capable)
            .map(|peer| peer.swarm_activation_level)
            .collect()
    }

    /// Get a specific peer's state.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peers.get(&peer_id.0)
    }

    /// Number of alive peers.
    pub fn alive_count(&self) -> usize {
        self.peers.values().filter(|p| p.alive).count()
    }

    /// Remove a peer entirely.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(&peer_id.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeCapability;
    use std::net::SocketAddr;

    fn make_peer(id: &str) -> PeerState {
        let mut cap = NodeCapability::local();
        cap.peer_id = PeerId(id.into());
        let addr: SocketAddr = "127.0.0.1:9471".parse().unwrap();
        PeerState::new(cap, addr)
    }

    #[test]
    fn track_and_query_peers() {
        let mut monitor = HealthMonitor::new(Duration::from_secs(10));
        let peer = make_peer("test-peer-1");
        monitor.update_peer(peer);

        assert_eq!(monitor.alive_count(), 1);
        assert!(monitor.get_peer(&PeerId("test-peer-1".into())).is_some());
    }

    #[test]
    fn mark_dead_reduces_count() {
        let mut monitor = HealthMonitor::new(Duration::from_secs(10));
        let peer = make_peer("test-peer-2");
        monitor.update_peer(peer);

        assert_eq!(monitor.alive_count(), 1);
        monitor.mark_dead(&PeerId("test-peer-2".into()));
        assert_eq!(monitor.alive_count(), 0);
    }
}
