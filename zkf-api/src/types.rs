use serde::{Deserialize, Serialize};
use zkf_backends::CapabilityReport;
use zkf_core::{FieldElement, IssuerSignedCredentialV1, ProofArtifact};
use zkf_lib::MerklePathNodeV1;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    /// ZKF program JSON (`ir-v2` by default, or `zir-v1` when `ir_family` requests it).
    pub program: serde_json::Value,
    /// Program family selector (`auto`, `zir-v1`, or `ir-v2`).
    pub ir_family: Option<String>,
    /// Witness inputs as key-value map.
    pub inputs: serde_json::Value,
    /// Backend to use (e.g., "arkworks-groth16", "plonky3").
    /// If omitted, auto-selects based on field.
    pub backend: Option<String>,
    /// Proving mode (e.g., "metal-first").
    pub mode: Option<String>,
    /// When true, emit a hybrid artifact with a Plonky3 STARK companion leg and Groth16 wrapped primary leg.
    pub hybrid: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WrapRequest {
    /// Source proof artifact JSON.
    pub proof: serde_json::Value,
    /// Source compiled program JSON.
    pub compiled: serde_json::Value,
    /// Target backend (default: "arkworks-groth16").
    pub target: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeployRequest {
    /// Proof artifact JSON.
    pub proof: serde_json::Value,
    /// Backend that produced the proof.
    pub backend: String,
    /// Solidity contract name (optional).
    pub contract_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkRequest {
    /// ZKF program JSON (`ir-v2` by default, or `zir-v1` when `ir_family` requests it).
    pub program: serde_json::Value,
    /// Program family selector (`auto`, `zir-v1`, or `ir-v2`).
    pub ir_family: Option<String>,
    /// Witness inputs.
    pub inputs: serde_json::Value,
    /// Backends to benchmark (comma-separated or array).
    pub backends: Option<Vec<String>>,
    /// Number of iterations per backend.
    pub iterations: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPolicySurfaceRequest {
    pub issuer_tree_root: FieldElement,
    pub active_tree_root: FieldElement,
    pub required_age: u8,
    pub required_status_mask: u32,
    pub current_epoch_day: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialProveRequest {
    pub signed_credential: IssuerSignedCredentialV1,
    pub subject_secret: String,
    pub subject_salt: String,
    pub issuer_path: Vec<MerklePathNodeV1>,
    pub active_path: Vec<MerklePathNodeV1>,
    pub surface: CredentialPolicySurfaceRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groth16_setup_blob: Option<String>,
    #[serde(default)]
    pub allow_dev_deterministic_groth16: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialVerifyRequest {
    pub artifact: ProofArtifact,
    pub surface: CredentialPolicySurfaceRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobResponse {
    pub id: String,
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct CapabilitiesResponse {
    pub version: String,
    pub backends: Vec<CapabilityReport>,
    pub frontends: Vec<String>,
    pub wrapping_paths: Vec<(String, String)>,
    pub gpu_available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// API key tier for metering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiTier {
    Free,
    Developer,
    Team,
    Enterprise,
}

impl ApiTier {
    pub fn proofs_per_month(self) -> u32 {
        match self {
            ApiTier::Free => 10,
            ApiTier::Developer => 500,
            ApiTier::Team => 5_000,
            ApiTier::Enterprise => u32::MAX,
        }
    }

    pub fn wraps_per_month(self) -> u32 {
        match self {
            ApiTier::Free => 0,
            ApiTier::Developer => 50,
            ApiTier::Team => 500,
            ApiTier::Enterprise => u32::MAX,
        }
    }

    pub fn deploys_per_month(self) -> u32 {
        match self {
            ApiTier::Free => 0,
            ApiTier::Developer => 20,
            ApiTier::Team => u32::MAX,
            ApiTier::Enterprise => u32::MAX,
        }
    }

    pub fn benchmarks_per_month(self) -> u32 {
        match self {
            ApiTier::Free => 5,
            ApiTier::Developer => 100,
            ApiTier::Team => u32::MAX,
            ApiTier::Enterprise => u32::MAX,
        }
    }

    pub fn concurrent_jobs(self) -> u32 {
        match self {
            ApiTier::Free => 1,
            ApiTier::Developer => 3,
            ApiTier::Team => 10,
            ApiTier::Enterprise => 50,
        }
    }

    pub fn gpu_enabled(self) -> bool {
        !matches!(self, ApiTier::Free)
    }
}
