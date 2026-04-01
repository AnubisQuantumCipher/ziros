//! Trust model types for the UMPG runtime.

use serde::{Deserialize, Serialize};
pub use zkf_core::SupportClass;
use zkf_core::{AppleChipFamily, PlatformCapability, PressureLevel, SystemResources};

/// Cryptographic trust guarantee for a node's output.
///
/// Taint propagates: if any dependency has a weaker trust model, the node
/// inherits the weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustModel {
    /// Output is proven in-circuit; verifier cannot forge.
    Cryptographic = 2,
    /// Output is verified by the host, not by a circuit.
    Attestation = 1,
    /// No cryptographic verification at all.
    MetadataOnly = 0,
}

impl TrustModel {
    /// The weaker of `self` and `other`.
    pub fn weaken(self, other: TrustModel) -> TrustModel {
        if (other as u8) < (self as u8) {
            other
        } else {
            self
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TrustModel::Cryptographic => "cryptographic",
            TrustModel::Attestation => "attestation",
            TrustModel::MetadataOnly => "metadata-only",
        }
    }

    pub fn trust_tier(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for TrustModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which trust lanes are allowed for this execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredTrustLane {
    /// Only cryptographic in-circuit proofs allowed.
    StrictCryptographic,
    /// Cryptographic proofs and host-validated attestations allowed.
    AllowAttestation,
    /// Any trust model including metadata-only markers.
    AllowMetadataOnly,
}

/// Execution hardware profile used for planning and production admission control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareProfile {
    M1,
    M2,
    M3,
    M4,
    A17Pro,
    A18,
    A18Pro,
    VisionPro,
    CpuOnly,
}

impl HardwareProfile {
    pub fn detect() -> Self {
        Self::from_platform(&PlatformCapability::detect())
    }

    pub fn from_resources(resources: &SystemResources) -> Self {
        let detected = Self::from_platform(&PlatformCapability::detect());
        if !matches!(detected, HardwareProfile::CpuOnly) {
            return detected;
        }
        if !resources.unified_memory {
            return HardwareProfile::CpuOnly;
        }
        let total_gib = resources.total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        if total_gib >= 48.0 {
            HardwareProfile::M4
        } else if total_gib >= 32.0 {
            HardwareProfile::M3
        } else if total_gib >= 16.0 {
            HardwareProfile::M2
        } else {
            HardwareProfile::M1
        }
    }

    pub fn from_platform(platform: &PlatformCapability) -> Self {
        match platform.identity.chip_family {
            AppleChipFamily::M1 => HardwareProfile::M1,
            AppleChipFamily::M2 | AppleChipFamily::UnknownApple => HardwareProfile::M2,
            AppleChipFamily::M3 => HardwareProfile::M3,
            AppleChipFamily::M4 => HardwareProfile::M4,
            AppleChipFamily::A17Pro => HardwareProfile::A17Pro,
            AppleChipFamily::A18 => HardwareProfile::A18,
            AppleChipFamily::A18Pro => HardwareProfile::A18Pro,
            AppleChipFamily::VisionPro => HardwareProfile::VisionPro,
            AppleChipFamily::NonApple => HardwareProfile::CpuOnly,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            HardwareProfile::M1 => "apple-silicon-m1",
            HardwareProfile::M2 => "apple-silicon-m2",
            HardwareProfile::M3 => "apple-silicon-m3",
            HardwareProfile::M4 => "apple-silicon-m4-max-48gb",
            HardwareProfile::A17Pro => "apple-a17-pro",
            HardwareProfile::A18 => "apple-a18",
            HardwareProfile::A18Pro => "apple-a18-pro",
            HardwareProfile::VisionPro => "vision-pro",
            HardwareProfile::CpuOnly => "cpu-only",
        }
    }

    pub fn supports_required(self, required: HardwareProfile) -> bool {
        self.rank() >= required.rank()
    }

    pub fn supports_strict_cryptographic_wrap(self, resources: &SystemResources) -> bool {
        matches!(self, HardwareProfile::M4)
            && !matches!(
                resources.pressure.level,
                PressureLevel::High | PressureLevel::Critical
            )
    }

    pub fn is_mobile(self) -> bool {
        matches!(
            self,
            HardwareProfile::A17Pro
                | HardwareProfile::A18
                | HardwareProfile::A18Pro
                | HardwareProfile::VisionPro
        )
    }

    pub fn is_apple(self) -> bool {
        !matches!(self, HardwareProfile::CpuOnly)
    }

    fn rank(self) -> u8 {
        match self {
            HardwareProfile::CpuOnly => 0,
            HardwareProfile::A17Pro => 1,
            HardwareProfile::A18 => 2,
            HardwareProfile::A18Pro => 3,
            HardwareProfile::VisionPro => 4,
            HardwareProfile::M1 => 5,
            HardwareProfile::M2 => 6,
            HardwareProfile::M3 => 7,
            HardwareProfile::M4 => 8,
        }
    }
}

impl std::fmt::Display for HardwareProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HardwareProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "apple-silicon-m1" | "m1" => Ok(HardwareProfile::M1),
            "apple-silicon-m2" | "apple-silicon-generic" | "apple-silicon" | "apple" | "m2" => {
                Ok(HardwareProfile::M2)
            }
            "apple-silicon-m3" | "m3" => Ok(HardwareProfile::M3),
            "apple-silicon-m4-max-48gb" | "m4-max-48gb" | "m4-max" | "apple-silicon-m4" | "m4" => {
                Ok(HardwareProfile::M4)
            }
            "apple-a17-pro" | "a17-pro" | "a17" => Ok(HardwareProfile::A17Pro),
            "apple-a18" | "a18" => Ok(HardwareProfile::A18),
            "apple-a18-pro" | "a18-pro" => Ok(HardwareProfile::A18Pro),
            "vision-pro" | "visionos" => Ok(HardwareProfile::VisionPro),
            "cpu-only" | "cpu" => Ok(HardwareProfile::CpuOnly),
            other => Err(format!("unknown hardware profile: {other}")),
        }
    }
}

/// Execution scheduling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Nodes run in strict topological order on CPU; reproducible.
    Deterministic,
    /// PlacementEngine decides per-node device; CPU+GPU overlap possible.
    Adaptive,
    /// Benchmark mode: collect detailed timing and resource metrics.
    Benchmark,
}

/// Device class for node execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceClass {
    Cpu,
    MetalGpu,
    External,
}

/// Summary of trust properties for a complete graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    pub trust_model: TrustModel,
    pub support_class: SupportClass,
    pub contains_delegated_nodes: bool,
    pub contains_attestation_nodes: bool,
}
