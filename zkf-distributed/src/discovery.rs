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

//! Peer discovery: mDNS, static list, and manual registration.

use crate::config::{ClusterConfig, DiscoveryMethod};
use crate::error::DistributedError;
use crate::identity::{NodeCapability, PeerState};
use std::net::SocketAddr;
#[cfg(feature = "mdns")]
use std::time::{Duration, Instant};

/// Trait for discovering cluster peers.
pub trait PeerDiscovery: Send {
    /// Discover peers. Returns the set of currently reachable peers.
    fn discover(&mut self) -> Result<Vec<PeerState>, DistributedError>;

    /// Name of this discovery backend.
    fn name(&self) -> &'static str;
}

/// Build a discovery backend from config.
pub fn create_discovery(
    config: &ClusterConfig,
) -> Result<Box<dyn PeerDiscovery>, DistributedError> {
    match config.discovery {
        DiscoveryMethod::Mdns => MdnsDiscovery::build(),
        DiscoveryMethod::Static => Ok(Box::new(StaticDiscovery::new(config.static_peers.clone()))),
        DiscoveryMethod::Manual => Ok(Box::new(ManualDiscovery::new())),
    }
}

// ─── mDNS Discovery ──────────────────────────────────────────────────────

/// mDNS-based discovery.
pub struct MdnsDiscovery {
    #[cfg(feature = "mdns")]
    daemon: mdns_sd::ServiceDaemon,
}

impl MdnsDiscovery {
    #[cfg(feature = "mdns")]
    fn new() -> Result<Self, DistributedError> {
        Ok(Self {
            daemon: mdns_sd::ServiceDaemon::new().map_err(|err| {
                DistributedError::Config(format!("failed to initialize mDNS discovery: {err}"))
            })?,
        })
    }

    #[cfg(not(feature = "mdns"))]
    fn new() -> Result<Self, DistributedError> {
        Err(DistributedError::Config(
            "mDNS discovery is not compiled in; use static or manual discovery".into(),
        ))
    }

    pub fn build() -> Result<Box<dyn PeerDiscovery>, DistributedError> {
        Ok(Box::new(Self::new()?))
    }
}

impl PeerDiscovery for MdnsDiscovery {
    fn discover(&mut self) -> Result<Vec<PeerState>, DistributedError> {
        #[cfg(feature = "mdns")]
        {
            let receiver = self
                .daemon
                .browse("_zkf-cluster._tcp.local.")
                .map_err(|err| {
                    DistributedError::Config(format!("failed to browse mDNS services: {err}"))
                })?;
            let deadline = Instant::now() + Duration::from_millis(750);
            let mut peers = Vec::new();
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(event) = receiver.recv_timeout(remaining) else {
                    break;
                };
                if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                    for addr in info.get_addresses() {
                        peers.push(PeerState::new(
                            NodeCapability::local(),
                            SocketAddr::new(*addr, info.get_port()),
                        ));
                    }
                }
            }
            peers.sort_by_key(|peer| peer.addr);
            peers.dedup_by_key(|peer| peer.addr);
            Ok(peers)
        }

        #[cfg(not(feature = "mdns"))]
        {
            Err(DistributedError::Config(
                "mDNS discovery is not compiled in; use static or manual discovery".into(),
            ))
        }
    }

    fn name(&self) -> &'static str {
        "mdns"
    }
}

// ─── Static Discovery ────────────────────────────────────────────────────

/// Static peer list from configuration.
pub struct StaticDiscovery {
    addrs: Vec<SocketAddr>,
}

impl StaticDiscovery {
    pub fn new(addrs: Vec<SocketAddr>) -> Self {
        Self { addrs }
    }
}

impl PeerDiscovery for StaticDiscovery {
    fn discover(&mut self) -> Result<Vec<PeerState>, DistributedError> {
        // Seed peers from configured addresses; the coordinator handshake will
        // refresh capabilities before any placement decision depends on them.
        let peers = self
            .addrs
            .iter()
            .map(|addr| {
                let cap = NodeCapability::local();
                PeerState::new(cap, *addr)
            })
            .collect();
        Ok(peers)
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

// ─── Manual Discovery ────────────────────────────────────────────────────

/// Manual peer registration (peers added at runtime via `register`).
pub struct ManualDiscovery {
    peers: Vec<PeerState>,
}

impl ManualDiscovery {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Register a peer manually.
    pub fn register(&mut self, addr: SocketAddr, capability: NodeCapability) {
        self.peers.push(PeerState::new(capability, addr));
    }
}

impl Default for ManualDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerDiscovery for ManualDiscovery {
    fn discover(&mut self) -> Result<Vec<PeerState>, DistributedError> {
        Ok(self.peers.clone())
    }

    fn name(&self) -> &'static str {
        "manual"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_discovery_returns_all_peers() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:9471".parse().unwrap(),
            "127.0.0.1:9472".parse().unwrap(),
        ];
        let mut disc = StaticDiscovery::new(addrs.clone());
        let peers = disc.discover().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].addr, addrs[0]);
        assert_eq!(peers[1].addr, addrs[1]);
    }

    #[test]
    fn manual_discovery_register_and_find() {
        let mut disc = ManualDiscovery::new();
        assert!(disc.discover().unwrap().is_empty());

        let addr: SocketAddr = "10.0.0.1:9471".parse().unwrap();
        disc.register(addr, NodeCapability::local());

        let peers = disc.discover().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, addr);
    }

    #[test]
    fn create_discovery_uses_static_by_default() {
        let config = ClusterConfig::default();
        let discovery = create_discovery(&config).unwrap();
        assert_eq!(discovery.name(), "static");
    }

    #[test]
    fn mdns_without_feature_fails_closed() {
        #[cfg(not(feature = "mdns"))]
        {
            use crate::config::DiscoveryMethod;

            let mut config = ClusterConfig::default();
            config.discovery = DiscoveryMethod::Mdns;
            let err = create_discovery(&config).err().expect("mdns should fail");
            assert!(
                err.to_string()
                    .contains("mDNS discovery is not compiled in")
            );
        }
    }
}
