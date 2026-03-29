use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppleChipFamily {
    M1,
    M2,
    M3,
    M4,
    A17Pro,
    A18,
    A18Pro,
    VisionPro,
    UnknownApple,
    NonApple,
}

impl AppleChipFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::M1 => "m1",
            Self::M2 => "m2",
            Self::M3 => "m3",
            Self::M4 => "m4",
            Self::A17Pro => "a17-pro",
            Self::A18 => "a18",
            Self::A18Pro => "a18-pro",
            Self::VisionPro => "vision-pro",
            Self::UnknownApple => "unknown-apple",
            Self::NonApple => "non-apple",
        }
    }

    pub fn is_apple(self) -> bool {
        !matches!(self, Self::NonApple)
    }

    pub fn generation_score(self) -> f32 {
        match self {
            Self::M1 => 0.25,
            Self::M2 | Self::VisionPro => 0.50,
            Self::M3 => 0.75,
            Self::M4 => 1.00,
            Self::A17Pro => 0.90,
            Self::A18 => 0.95,
            Self::A18Pro => 1.00,
            Self::UnknownApple => 0.60,
            Self::NonApple => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceFormFactor {
    Desktop,
    Laptop,
    Mobile,
    Headset,
    Unknown,
}

impl DeviceFormFactor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Laptop => "laptop",
            Self::Mobile => "mobile",
            Self::Headset => "headset",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeuralEngineCapability {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tops: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_count: Option<u8>,
}

impl NeuralEngineCapability {
    fn from_chip_family(chip_family: AppleChipFamily) -> Self {
        let tops = match chip_family {
            AppleChipFamily::M1 => Some(11.0),
            AppleChipFamily::M2 | AppleChipFamily::VisionPro => Some(15.8),
            AppleChipFamily::M3 => Some(18.0),
            AppleChipFamily::M4 => Some(38.0),
            AppleChipFamily::A17Pro => Some(35.0),
            AppleChipFamily::A18 => Some(35.0),
            AppleChipFamily::A18Pro => Some(35.0),
            AppleChipFamily::UnknownApple => None,
            AppleChipFamily::NonApple => None,
        };
        Self {
            available: chip_family.is_apple(),
            tops,
            core_count: tops.map(|_| 16),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuCapability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
}

/// macOS power mode as reported by `pmset -g` → `powermode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PowerMode {
    /// System chooses based on workload and power source.
    #[default]
    Automatic,
    /// Battery saver — reduced clocks, fewer GPU dispatches.
    LowPower,
    /// Maximum clocks regardless of power source.
    HighPerformance,
}

impl PowerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::LowPower => "low-power",
            Self::HighPerformance => "high-performance",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ThermalEnvelope {
    pub battery_present: bool,
    pub on_external_power: bool,
    pub low_power_mode: bool,
    #[serde(default)]
    pub power_mode: PowerMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_state_celsius: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_speed_limit: Option<f64>,
}

/// ARM CPU cryptographic extension availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CryptoExtensions {
    /// FEAT_SHA256: hardware SHA-256 (SHA256H, SHA256H2, SHA256SU0, SHA256SU1)
    pub sha256: bool,
    /// FEAT_SHA3: hardware SHA-3/Keccak (EOR3, RAX1, XAR, BCAX)
    pub sha3: bool,
    /// FEAT_AES: hardware AES (AESE, AESD, AESMC, AESIMC)
    pub aes: bool,
    /// FEAT_PMULL: polynomial multiply (PMULL, PMULL2) for GF(2^128)
    pub pmull: bool,
    /// FEAT_SME: Scalable Matrix Extension (M4+)
    pub sme: bool,
}

impl CryptoExtensions {
    /// Detect available crypto extensions at runtime.
    pub fn detect() -> Self {
        #[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
        {
            Self {
                sha256: sysctl_bool("hw.optional.arm.FEAT_SHA256"),
                sha3: sysctl_bool("hw.optional.arm.FEAT_SHA3"),
                aes: sysctl_bool("hw.optional.arm.FEAT_AES"),
                pmull: sysctl_bool("hw.optional.arm.FEAT_PMULL"),
                sme: sysctl_bool("hw.optional.arm.FEAT_SME"),
            }
        }
        #[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
        {
            Self::default()
        }
    }

    /// Return true if any hardware crypto extension is available.
    pub fn any_available(&self) -> bool {
        self.sha256 || self.sha3 || self.aes || self.pmull || self.sme
    }

    /// Summary string for diagnostics.
    pub fn summary(&self) -> String {
        let mut features = Vec::new();
        if self.sha256 {
            features.push("SHA256");
        }
        if self.sha3 {
            features.push("SHA3");
        }
        if self.aes {
            features.push("AES");
        }
        if self.pmull {
            features.push("PMULL");
        }
        if self.sme {
            features.push("SME");
        }
        if features.is_empty() {
            "none".to_string()
        } else {
            features.join(", ")
        }
    }
}

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
fn sysctl_bool(name: &str) -> bool {
    use std::ffi::CString;
    let Ok(c_name) = CString::new(name) else {
        return false;
    };
    let mut value: i32 = 0;
    let mut size: libc::size_t = std::mem::size_of::<i32>();
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            &raw mut value as *mut libc::c_void,
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    ret == 0 && value != 0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformIdentity {
    pub chip_family: AppleChipFamily,
    pub form_factor: DeviceFormFactor,
    pub neural_engine: NeuralEngineCapability,
    pub gpu: GpuCapability,
    pub crypto_extensions: CryptoExtensions,
    pub unified_memory: bool,
    pub total_ram_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_chip_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformCapability {
    pub identity: PlatformIdentity,
    pub thermal_envelope: ThermalEnvelope,
}

impl PlatformCapability {
    pub fn detect() -> Self {
        Self {
            identity: platform_identity().clone(),
            thermal_envelope: detect_thermal_envelope(),
        }
    }

    pub fn platform_key(&self) -> String {
        let model = self
            .identity
            .model_identifier
            .as_deref()
            .unwrap_or("unknown-model")
            .replace(|ch: char| !ch.is_ascii_alphanumeric(), "-")
            .to_ascii_lowercase();
        format!(
            "{}-{}-gpu{}-{}",
            self.identity.chip_family.as_str(),
            self.identity.form_factor.as_str(),
            self.identity.gpu.core_count.unwrap_or_default(),
            model
        )
    }

    pub fn chip_generation_norm(&self) -> f32 {
        self.identity.chip_family.generation_score()
    }

    pub fn gpu_cores_norm(&self) -> f32 {
        (self.identity.gpu.core_count.unwrap_or_default() as f32 / 64.0).clamp(0.0, 1.0)
    }

    pub fn ane_tops_norm(&self) -> f32 {
        (self.identity.neural_engine.tops.unwrap_or_default() / 40.0).clamp(0.0, 1.0)
    }
}

static PLATFORM_IDENTITY: OnceCell<PlatformIdentity> = OnceCell::new();

pub fn platform_identity() -> &'static PlatformIdentity {
    PLATFORM_IDENTITY.get_or_init(detect_platform_identity)
}

fn detect_platform_identity() -> PlatformIdentity {
    let total_ram_bytes = detect_total_ram_bytes();
    let unified_memory = detect_unified_memory();

    #[cfg(target_os = "macos")]
    {
        let profiler = command_json(
            "system_profiler",
            &["SPHardwareDataType", "SPDisplaysDataType", "-json"],
        );
        let hardware = profiler
            .as_ref()
            .and_then(|value| value.get("SPHardwareDataType"))
            .and_then(|value| value.as_array())
            .and_then(|value| value.first());
        let display = profiler
            .as_ref()
            .and_then(|value| value.get("SPDisplaysDataType"))
            .and_then(|value| value.as_array())
            .and_then(|value| value.first());

        let raw_chip_name = hardware
            .and_then(|value| value.get("chip_type"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| sysctl_string("machdep.cpu.brand_string"));
        let machine_name = hardware
            .and_then(|value| value.get("machine_name"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let model_identifier = hardware
            .and_then(|value| value.get("machine_model"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| sysctl_string("hw.model"));
        let gpu_core_count = display
            .and_then(|value| value.get("sppci_cores"))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u32>().ok());
        let gpu_family = display
            .and_then(|value| value.get("spdisplays_mtlgpufamilysupport"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let chip_family =
            raw_chip_name
                .as_deref()
                .map(parse_chip_family)
                .unwrap_or(if unified_memory {
                    AppleChipFamily::UnknownApple
                } else {
                    AppleChipFamily::NonApple
                });
        let form_factor = machine_name
            .as_deref()
            .map(parse_machine_name_form_factor)
            .unwrap_or(DeviceFormFactor::Unknown);

        PlatformIdentity {
            chip_family,
            form_factor,
            neural_engine: NeuralEngineCapability::from_chip_family(chip_family),
            gpu: GpuCapability {
                core_count: gpu_core_count,
                family: gpu_family,
            },
            crypto_extensions: CryptoExtensions::detect(),
            unified_memory,
            total_ram_bytes,
            model_identifier,
            machine_name,
            raw_chip_name,
        }
    }

    #[cfg(target_os = "visionos")]
    {
        return generic_apple_identity(
            AppleChipFamily::VisionPro,
            DeviceFormFactor::Headset,
            total_ram_bytes,
            unified_memory,
        );
    }

    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    {
        let machine = sysctl_string("hw.machine");
        let chip_family = machine
            .as_deref()
            .map(parse_chip_family)
            .unwrap_or(AppleChipFamily::UnknownApple);
        return PlatformIdentity {
            chip_family,
            form_factor: DeviceFormFactor::Mobile,
            neural_engine: NeuralEngineCapability::from_chip_family(chip_family),
            gpu: GpuCapability {
                core_count: None,
                family: None,
            },
            crypto_extensions: CryptoExtensions::detect(),
            unified_memory,
            total_ram_bytes,
            model_identifier: machine.clone(),
            machine_name: None,
            raw_chip_name: machine,
        };
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos"
    )))]
    {
        PlatformIdentity {
            chip_family: AppleChipFamily::NonApple,
            form_factor: DeviceFormFactor::Unknown,
            neural_engine: NeuralEngineCapability::from_chip_family(AppleChipFamily::NonApple),
            gpu: GpuCapability {
                core_count: None,
                family: None,
            },
            crypto_extensions: CryptoExtensions::default(),
            unified_memory,
            total_ram_bytes,
            model_identifier: None,
            machine_name: None,
            raw_chip_name: None,
        }
    }
}

#[cfg(target_os = "visionos")]
fn generic_apple_identity(
    chip_family: AppleChipFamily,
    form_factor: DeviceFormFactor,
    total_ram_bytes: u64,
    unified_memory: bool,
) -> PlatformIdentity {
    PlatformIdentity {
        chip_family,
        form_factor,
        neural_engine: NeuralEngineCapability::from_chip_family(chip_family),
        gpu: GpuCapability {
            core_count: None,
            family: None,
        },
        crypto_extensions: CryptoExtensions::detect(),
        unified_memory,
        total_ram_bytes,
        model_identifier: sysctl_string("hw.model").or_else(|| sysctl_string("hw.machine")),
        machine_name: None,
        raw_chip_name: sysctl_string("hw.machine"),
    }
}

fn detect_thermal_envelope() -> ThermalEnvelope {
    #[cfg(target_os = "macos")]
    {
        detect_thermal_envelope_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        ThermalEnvelope::default()
    }
}

#[cfg(target_os = "macos")]
fn detect_thermal_envelope_macos() -> ThermalEnvelope {
    let mut envelope = ThermalEnvelope::default();

    if let Some(output) = command_string("pmset", &["-g", "batt"]) {
        envelope.on_external_power = output.contains("AC Power");
        envelope.battery_present =
            output.contains("InternalBattery") || output.contains("present: true");
    }

    if let Some(output) = command_string("pmset", &["-g", "therm"]) {
        for line in output.lines() {
            let line = line.trim();
            if let Some(value) = line
                .strip_prefix("CPU_Speed_Limit = ")
                .and_then(|raw| raw.trim().parse::<f64>().ok())
            {
                envelope.cpu_speed_limit = Some((value / 100.0).clamp(0.0, 1.0));
            }
            if let Some(value) = line
                .strip_prefix("ThermalLevel = ")
                .and_then(|raw| raw.trim().parse::<f64>().ok())
            {
                envelope.thermal_pressure = Some((value / 20.0).clamp(0.0, 1.0));
            }
        }
    }

    if let Some(raw) = command_string("defaults", &["read", "-g", "LowPowerMode"]) {
        let normalized = raw.trim();
        envelope.low_power_mode = matches!(normalized, "1" | "true" | "YES");
    }

    // Detect macOS power mode: 0 = Automatic, 1 = Low Power, 2 = High Performance.
    // `pmset -g` reports `powermode N` in the "Currently in use" block.
    if let Some(output) = command_string("pmset", &["-g"]) {
        for line in output.lines() {
            if let Some(value) = line
                .trim()
                .strip_prefix("powermode")
                .and_then(|raw| raw.trim().parse::<u8>().ok())
            {
                envelope.power_mode = match value {
                    1 => PowerMode::LowPower,
                    2 => PowerMode::HighPerformance,
                    _ => PowerMode::Automatic,
                };
                // Sync low_power_mode flag with powermode for consistency.
                if value == 1 {
                    envelope.low_power_mode = true;
                }
            }
        }
    }

    envelope
}

fn parse_machine_name_form_factor(value: &str) -> DeviceFormFactor {
    let value = value.to_ascii_lowercase();
    if value.contains("macbook") {
        DeviceFormFactor::Laptop
    } else if value.contains("vision") {
        DeviceFormFactor::Headset
    } else if value.contains("imac")
        || value.contains("mac mini")
        || value.contains("mac studio")
        || value.contains("mac pro")
    {
        DeviceFormFactor::Desktop
    } else {
        DeviceFormFactor::Unknown
    }
}

pub fn parse_chip_family(value: &str) -> AppleChipFamily {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("vision") {
        AppleChipFamily::VisionPro
    } else if normalized.contains("a18 pro") || normalized.contains("iphone17,") {
        AppleChipFamily::A18Pro
    } else if normalized.contains("a18") {
        AppleChipFamily::A18
    } else if normalized.contains("a17 pro") || normalized.contains("iphone16,") {
        AppleChipFamily::A17Pro
    } else if normalized.contains("m4") {
        AppleChipFamily::M4
    } else if normalized.contains("m3") {
        AppleChipFamily::M3
    } else if normalized.contains("m2") {
        AppleChipFamily::M2
    } else if normalized.contains("m1") {
        AppleChipFamily::M1
    } else if normalized.contains("apple")
        || normalized.contains("ipad")
        || normalized.contains("iphone")
    {
        AppleChipFamily::UnknownApple
    } else {
        AppleChipFamily::NonApple
    }
}

fn detect_total_ram_bytes() -> u64 {
    sysctl_string("hw.memsize")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default()
}

fn detect_unified_memory() -> bool {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos"
    ))]
    {
        true
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos"
    )))]
    {
        false
    }
}

fn sysctl_string(name: &str) -> Option<String> {
    command_string("sysctl", &["-n", name]).map(|value| value.trim().to_string())
}

fn command_string(binary: &str, args: &[&str]) -> Option<String> {
    Command::new(binary)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
}

fn command_json(binary: &str, args: &[&str]) -> Option<Value> {
    command_string(binary, args).and_then(|raw| serde_json::from_str(&raw).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chip_family_matches_mac_generations() {
        assert_eq!(parse_chip_family("Apple M1"), AppleChipFamily::M1);
        assert_eq!(parse_chip_family("Apple M2 Max"), AppleChipFamily::M2);
        assert_eq!(parse_chip_family("Apple M3 Pro"), AppleChipFamily::M3);
        assert_eq!(parse_chip_family("Apple M4 Max"), AppleChipFamily::M4);
    }

    #[test]
    fn parse_chip_family_matches_mobile_generations() {
        assert_eq!(parse_chip_family("A17 Pro"), AppleChipFamily::A17Pro);
        assert_eq!(parse_chip_family("A18"), AppleChipFamily::A18);
        assert_eq!(parse_chip_family("A18 Pro"), AppleChipFamily::A18Pro);
        assert_eq!(parse_chip_family("Vision Pro"), AppleChipFamily::VisionPro);
    }

    #[test]
    fn platform_norms_are_clamped() {
        let capability = PlatformCapability {
            identity: PlatformIdentity {
                chip_family: AppleChipFamily::M4,
                form_factor: DeviceFormFactor::Laptop,
                neural_engine: NeuralEngineCapability {
                    available: true,
                    tops: Some(38.0),
                    core_count: Some(16),
                },
                gpu: GpuCapability {
                    core_count: Some(40),
                    family: Some("metal4".to_string()),
                },
                crypto_extensions: CryptoExtensions::default(),
                unified_memory: true,
                total_ram_bytes: 48 * 1024 * 1024 * 1024,
                model_identifier: Some("Mac16,5".to_string()),
                machine_name: Some("MacBook Pro".to_string()),
                raw_chip_name: Some("Apple M4 Max".to_string()),
            },
            thermal_envelope: ThermalEnvelope::default(),
        };

        assert!(capability.chip_generation_norm() > 0.9);
        assert!(capability.gpu_cores_norm() > 0.5);
        assert!(capability.ane_tops_norm() > 0.9);
    }
}
