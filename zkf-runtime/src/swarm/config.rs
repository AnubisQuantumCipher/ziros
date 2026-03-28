use super::queen::QueenConfig;
use super::sentinel::SentinelConfig;
use super::warrior::QuorumConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwarmKeyBackend {
    File,
    Enclave,
}

impl SwarmKeyBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Enclave => "enclave",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmConfig {
    pub enabled: bool,
    pub sentinel: SentinelConfig,
    pub warrior: QuorumConfig,
    pub queen: QueenConfig,
    pub gossip_max_digests_per_heartbeat: usize,
    pub reputation_decay_lambda: f64,
    pub reputation_hourly_cap: f64,
    pub admission_pow_difficulty: u8,
    pub max_new_peers_per_hour_multiplier: usize,
    pub pattern_library_path: PathBuf,
    pub retrain_queue_path: PathBuf,
    pub rules_path: PathBuf,
    pub shadow_log_path: PathBuf,
    pub promotions_path: PathBuf,
    pub rollbacks_path: PathBuf,
    pub reputation_log_path: PathBuf,
    pub identity_path: PathBuf,
    pub key_backend: SwarmKeyBackend,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        let home = home_dir();
        let swarm_root = home.join(".zkf").join("swarm");
        Self {
            enabled: true,
            sentinel: SentinelConfig::default(),
            warrior: QuorumConfig::default(),
            queen: QueenConfig::default(),
            gossip_max_digests_per_heartbeat: 8,
            reputation_decay_lambda: 0.001,
            reputation_hourly_cap: 0.10,
            admission_pow_difficulty: 20,
            max_new_peers_per_hour_multiplier: 2,
            pattern_library_path: swarm_root.join("patterns"),
            retrain_queue_path: swarm_root.join("retrain-queue"),
            rules_path: swarm_root.join("rules"),
            shadow_log_path: swarm_root.join("shadow-log"),
            promotions_path: swarm_root.join("promotions"),
            rollbacks_path: swarm_root.join("rollbacks"),
            reputation_log_path: swarm_root.join("reputation-log"),
            identity_path: swarm_root.join("identity"),
            key_backend: default_key_backend(),
        }
    }
}

impl SwarmConfig {
    pub fn is_enabled() -> bool {
        Self::from_env().enabled
    }

    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("ZKF_SWARM") {
            config.enabled = value != "0";
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_Z_THRESHOLD")
            && let Ok(parsed) = value.parse::<f64>()
        {
            config.sentinel.z_threshold = parsed.max(0.0);
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_COOLDOWN_SECS")
            && let Ok(parsed) = value.parse::<u64>()
        {
            config.queen.cooldown_ms = u128::from(parsed) * 1_000;
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_QUORUM_SIZE")
            && let Ok(parsed) = value.parse::<usize>()
        {
            config.warrior.min_voters = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_GOSSIP_MAX")
            && let Ok(parsed) = value.parse::<usize>()
        {
            config.gossip_max_digests_per_heartbeat = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_REPUTATION_HOURLY_CAP")
            && let Ok(parsed) = value.parse::<f64>()
        {
            config.reputation_hourly_cap = parsed.clamp(0.0, 1.0);
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_ADMISSION_POW_DIFFICULTY")
            && let Ok(parsed) = value.parse::<u8>()
        {
            config.admission_pow_difficulty = parsed;
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_MAX_NEW_PEERS_PER_HOUR_MULTIPLIER")
            && let Ok(parsed) = value.parse::<usize>()
        {
            config.max_new_peers_per_hour_multiplier = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_JITTER_DETECTION") {
            config.sentinel.jitter_detection_enabled = value != "0";
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_CACHE_FLUSH_DETECTION") {
            config.sentinel.cache_flush_detection_enabled = value != "0";
        }
        if let Ok(value) = std::env::var("ZKF_SWARM_KEY_BACKEND") {
            config.key_backend = match value.trim().to_ascii_lowercase().as_str() {
                "file" => SwarmKeyBackend::File,
                "enclave" => SwarmKeyBackend::Enclave,
                _ => config.key_backend,
            };
        }
        config.sentinel.enabled = config.enabled;
        config
    }

    pub fn swarm_root(&self) -> PathBuf {
        self.pattern_library_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".zkf").join("swarm"))
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_key_backend() -> SwarmKeyBackend {
    #[cfg(target_os = "macos")]
    {
        SwarmKeyBackend::Enclave
    }
    #[cfg(not(target_os = "macos"))]
    {
        SwarmKeyBackend::File
    }
}
