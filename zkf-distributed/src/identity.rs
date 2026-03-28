//! Peer identity, capability advertisement, and state tracking.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_core::artifact::BackendKind;

#[cfg(feature = "full")]
use crate::swarm::{PublicKeyBundle, SignatureScheme};

/// Current protocol version for wire compatibility.
pub const PROTOCOL_VERSION: u32 = 1;
/// Current swarm overlay protocol version.
pub const SWARM_PROTOCOL_VERSION: u32 = 1;
static PEER_ID_NONCE: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for a cluster node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    /// Generate a new random peer ID from timestamp + random hex.
    pub fn generate() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce = u128::from(PEER_ID_NONCE.fetch_add(1, Ordering::Relaxed));
        // Use a simple hash of timestamp to avoid pulling in rand just for IDs.
        let hash = ts.wrapping_mul(0x517cc1b727220a95)
            ^ ts.rotate_left(17)
            ^ nonce.wrapping_mul(0x9e3779b97f4a7c15);
        PeerId(format!("{ts:016x}-{hash:016x}"))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Memory pressure level reported by a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PressureLevel {
    Normal,
    Warning,
    Critical,
}

/// Hardware profile of a peer (summary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub chip_name: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
}

/// Platform-level capability flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapability {
    pub os: String,
    pub arch: String,
}

/// System resource snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResources {
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
}

/// Advertised capabilities of a cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapability {
    pub peer_id: PeerId,
    pub hostname: String,
    pub hardware_profile: HardwareProfile,
    pub platform: PlatformCapability,
    pub resources: SystemResources,
    pub gpu_available: bool,
    pub gpu_cores: u32,
    pub crypto_extensions_available: bool,
    pub sme_available: bool,
    pub available_backends: Vec<BackendKind>,
    pub protocol_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ed25519_public_key: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<SignatureScheme>,
    #[cfg(feature = "full")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_bundle: Option<PublicKeyBundle>,
    pub max_buffer_memory_bytes: u64,
    pub pressure_level: PressureLevel,
}

impl NodeCapability {
    /// Build a local capability report for this machine.
    pub fn local() -> Self {
        let platform = zkf_core::PlatformCapability::detect();
        let resources = zkf_core::SystemResources::detect();
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into());

        Self {
            peer_id: PeerId::generate(),
            hostname,
            hardware_profile: HardwareProfile {
                chip_name: platform
                    .identity
                    .raw_chip_name
                    .clone()
                    .or(platform.identity.machine_name.clone())
                    .unwrap_or_else(|| platform.identity.chip_family.as_str().to_string()),
                cpu_cores: std::thread::available_parallelism()
                    .map(|p| p.get() as u32)
                    .unwrap_or(1),
                memory_bytes: resources.total_ram_bytes,
            },
            platform: PlatformCapability {
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
            },
            resources: SystemResources {
                total_memory_bytes: resources.total_ram_bytes,
                available_memory_bytes: resources.available_ram_bytes,
            },
            gpu_available: platform.identity.gpu.core_count.unwrap_or_default() > 0,
            gpu_cores: platform.identity.gpu.core_count.unwrap_or_default(),
            crypto_extensions_available: platform.identity.crypto_extensions.sha256
                || platform.identity.crypto_extensions.sha3
                || platform.identity.crypto_extensions.aes,
            sme_available: platform.identity.crypto_extensions.sme,
            available_backends: vec![
                BackendKind::ArkworksGroth16,
                BackendKind::Plonky3,
                BackendKind::Halo2,
                BackendKind::Halo2Bls12381,
                BackendKind::Nova,
                BackendKind::HyperNova,
                BackendKind::Sp1,
                BackendKind::RiscZero,
                BackendKind::MidnightCompact,
            ],
            protocol_version: PROTOCOL_VERSION,
            ed25519_public_key: Vec::new(),
            #[cfg(feature = "full")]
            signature_scheme: None,
            #[cfg(feature = "full")]
            public_key_bundle: None,
            max_buffer_memory_bytes: resources.available_ram_bytes,
            pressure_level: match resources.pressure.level {
                zkf_core::PressureLevel::Normal => PressureLevel::Normal,
                zkf_core::PressureLevel::Elevated => PressureLevel::Warning,
                zkf_core::PressureLevel::High | zkf_core::PressureLevel::Critical => {
                    PressureLevel::Critical
                }
            },
        }
    }

    /// Compute a placement score for a dominant device type.
    /// Higher is better for the given placement affinity.
    pub fn placement_score(&self, dominant_gpu: bool, reputation: Option<f64>) -> u64 {
        let mut score: u64 = 0;
        // Base: available memory in MiB
        score += self.resources.available_memory_bytes / (1024 * 1024);
        // GPU bonus
        if dominant_gpu && self.gpu_available {
            score += u64::from(self.gpu_cores) * 10;
        }
        // Crypto extensions bonus
        if self.crypto_extensions_available {
            score += 100;
        }
        // SME bonus for field-heavy work
        if self.sme_available {
            score += 200;
        }
        // Penalize pressure
        match self.pressure_level {
            PressureLevel::Normal => {}
            PressureLevel::Warning => score = score.saturating_sub(500),
            PressureLevel::Critical => score = score.saturating_sub(2000),
        }
        let reputation = reputation.unwrap_or(0.5).clamp(0.1, 1.0);
        let weighted = (score as f64 * reputation).round() as u64;
        weighted.max(32)
    }
}

/// Live state of a discovered peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub capability: NodeCapability,
    pub addr: SocketAddr,
    pub last_heartbeat_unix_ms: u128,
    pub active_subgraph_count: u32,
    pub current_buffer_bytes: u64,
    pub reputation: f64,
    pub swarm_activation_level: u8,
    pub swarm_capable: bool,
    pub alive: bool,
}

impl PeerState {
    pub fn new(capability: NodeCapability, addr: SocketAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            capability,
            addr,
            last_heartbeat_unix_ms: now,
            active_subgraph_count: 0,
            current_buffer_bytes: 0,
            reputation: 0.25,
            swarm_activation_level: 0,
            swarm_capable: false,
            alive: true,
        }
    }

    /// Update heartbeat timestamp and pressure level.
    pub fn record_heartbeat(
        &mut self,
        pressure: PressureLevel,
        active_subgraph_count: u32,
        current_buffer_bytes: u64,
        swarm_activation_level: Option<u8>,
    ) {
        self.last_heartbeat_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        self.capability.pressure_level = pressure;
        self.active_subgraph_count = active_subgraph_count;
        self.current_buffer_bytes = current_buffer_bytes;
        if let Some(level) = swarm_activation_level {
            self.swarm_activation_level = level;
            self.swarm_capable = true;
        }
        self.alive = true;
    }

    /// Check if peer has timed out given the heartbeat timeout.
    pub fn is_timed_out(&self, timeout: std::time::Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let elapsed_ms = now.saturating_sub(self.last_heartbeat_unix_ms);
        elapsed_ms > timeout.as_millis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_generation_is_unique() {
        let a = PeerId::generate();
        let b = PeerId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn placement_score_gpu_bonus() {
        let mut cap = NodeCapability::local();
        cap.gpu_available = true;
        cap.gpu_cores = 40;
        cap.resources.available_memory_bytes = 128 * 1024 * 1024 * 1024; // 128 GB
        let gpu_score = cap.placement_score(true, Some(1.0));

        cap.gpu_available = false;
        cap.gpu_cores = 0;
        let cpu_score = cap.placement_score(true, Some(1.0));

        assert!(gpu_score > cpu_score);
    }

    #[test]
    fn pressure_reduces_score() {
        let mut cap = NodeCapability::local();
        cap.resources.available_memory_bytes = 64 * 1024 * 1024 * 1024;
        cap.pressure_level = PressureLevel::Normal;
        let normal = cap.placement_score(false, Some(1.0));

        cap.pressure_level = PressureLevel::Critical;
        let critical = cap.placement_score(false, Some(1.0));

        assert!(normal > critical);
    }

    #[test]
    fn reputation_floor_preserves_nonzero_score() {
        let mut cap = NodeCapability::local();
        cap.resources.available_memory_bytes = 1024 * 1024;
        let score = cap.placement_score(false, Some(0.0));
        assert!(score > 0);
    }
}
