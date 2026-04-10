#![allow(unexpected_cfgs)]

mod cairo;
mod circom;
mod external;
pub mod halo2_export;
mod noir;
pub mod plonky3_air_export;
#[cfg(hax)]
mod proof_noir_recheck_spec;
mod translation;
mod zir;

use cairo::CairoFrontend;
use circom::CircomFrontend;
use external::{CompactFrontend, ZkvmFrontend};
use halo2_export::Halo2RustFrontend;
use noir::NoirAcirFrontend;
use plonky3_air_export::Plonky3AirFrontend;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
pub use translation::{DefaultFrontendTranslator, default_frontend_translator};
pub use translation::{
    FrontendTranslator, NoopFrontendTranslator, TranslationMeta, TranslationTarget,
    infer_noir_translation_meta,
};
use zir::ZirFrontend;
use zkf_core::{
    FieldId, Program, ToolRequirement, Witness, WitnessInputs, ZkfError, ZkfResult,
    program_v2_to_zir,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrontendKind {
    Zir,
    Noir,
    Circom,
    Cairo,
    Compact,
    Halo2Rust,
    Plonky3Air,
    Zkvm,
}

impl FrontendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FrontendKind::Zir => "zir",
            FrontendKind::Noir => "noir",
            FrontendKind::Circom => "circom",
            FrontendKind::Cairo => "cairo",
            FrontendKind::Compact => "compact",
            FrontendKind::Halo2Rust => "halo2-rust",
            FrontendKind::Plonky3Air => "plonky3-air",
            FrontendKind::Zkvm => "zkvm",
        }
    }
}

impl fmt::Display for FrontendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FrontendKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "zir" | "zir-source" | "native-zir" => Ok(Self::Zir),
            "noir" | "acir" => Ok(Self::Noir),
            "circom" | "r1cs" | "snarkjs-r1cs" => Ok(Self::Circom),
            "cairo" | "sierra" | "starknet" => Ok(Self::Cairo),
            "compact" | "midnight-compact" | "midnight" => Ok(Self::Compact),
            "halo2-rust" | "halo2" => Ok(Self::Halo2Rust),
            "plonky3-air" | "air" => Ok(Self::Plonky3Air),
            "zkvm" | "sp1" | "risc0" | "risc-zero" => Ok(Self::Zkvm),
            other => Err(format!("unknown frontend '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrontendCapabilities {
    pub frontend: FrontendKind,
    pub can_compile_to_ir: bool,
    pub can_execute: bool,
    pub input_formats: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IrFamilyPreference {
    #[default]
    Auto,
    ZirV1,
    IrV2,
}

impl IrFamilyPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ZirV1 => "zir-v1",
            Self::IrV2 => "ir-v2",
        }
    }
}

impl fmt::Display for IrFamilyPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IrFamilyPreference {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "zir-v1" | "zir" => Ok(Self::ZirV1),
            "ir-v2" | "ir" => Ok(Self::IrV2),
            other => Err(format!(
                "unknown ir family '{other}' (expected auto, zir-v1, or ir-v2)"
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FrontendProgram {
    IrV2(Program),
    ZirV1(zkf_core::zir_v1::Program),
}

impl FrontendProgram {
    pub fn ir_family(&self) -> &'static str {
        match self {
            Self::IrV2(_) => "ir-v2",
            Self::ZirV1(_) => "zir-v1",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::IrV2(program) => &program.name,
            Self::ZirV1(program) => &program.name,
        }
    }

    pub fn field(&self) -> FieldId {
        match self {
            Self::IrV2(program) => program.field,
            Self::ZirV1(program) => program.field,
        }
    }

    pub fn signal_count(&self) -> usize {
        match self {
            Self::IrV2(program) => program.signals.len(),
            Self::ZirV1(program) => program.signals.len(),
        }
    }

    pub fn constraint_count(&self) -> usize {
        match self {
            Self::IrV2(program) => program.constraints.len(),
            Self::ZirV1(program) => program.constraints.len(),
        }
    }

    pub fn digest_hex(&self) -> String {
        match self {
            Self::IrV2(program) => program.digest_hex(),
            Self::ZirV1(program) => program.digest_hex(),
        }
    }

    pub fn lower_to_ir_v2(&self) -> ZkfResult<Program> {
        match self {
            Self::IrV2(program) => Ok(program.clone()),
            Self::ZirV1(program) => zkf_core::program_zir_to_v2(program),
        }
    }

    pub fn promote_to_zir_v1(&self) -> zkf_core::zir_v1::Program {
        match self {
            Self::IrV2(program) => program_v2_to_zir(program),
            Self::ZirV1(program) => program.clone(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct FrontendProbe {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noir_version: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrontendInspection {
    pub frontend: FrontendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub functions: usize,
    pub unconstrained_functions: usize,
    #[serde(default)]
    pub opcode_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub blackbox_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub dropped_features: Vec<String>,
    pub requires_hints: bool,
}

#[derive(Clone, Default)]
pub struct FrontendImportOptions {
    pub program_name: Option<String>,
    pub field: Option<FieldId>,
    pub allow_unsupported_versions: bool,
    pub translator: Option<std::sync::Arc<dyn FrontendTranslator>>,
    pub ir_family: IrFamilyPreference,
    pub source_path: Option<std::path::PathBuf>,
}

pub trait FrontendEngine: Send + Sync {
    fn kind(&self) -> FrontendKind;
    fn capabilities(&self) -> FrontendCapabilities;
    fn probe(&self, value: &Value) -> FrontendProbe;

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program>;

    fn compile_to_program_family(
        &self,
        value: &Value,
        options: &FrontendImportOptions,
    ) -> ZkfResult<FrontendProgram> {
        self.compile_to_ir(value, options)
            .map(FrontendProgram::IrV2)
    }

    fn inspect(&self, _value: &Value) -> ZkfResult<FrontendInspection> {
        Err(ZkfError::UnsupportedBackend {
            backend: format!("frontend/{}/inspect", self.kind()),
            message: format!(
                "{} frontend does not support circuit inspection; \
                 use compile_to_ir to examine the constraint system",
                self.kind()
            ),
        })
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        Vec::new()
    }

    fn execute(&self, _value: &Value, _inputs: &WitnessInputs) -> ZkfResult<Witness> {
        Err(ZkfError::UnsupportedBackend {
            backend: format!("frontend/{}", self.kind()),
            message: format!(
                "{} frontend does not support direct execution; \
                 witness generation is handled by the backend after compile_to_ir",
                self.kind()
            ),
        })
    }
}

pub fn frontend_for(kind: FrontendKind) -> Box<dyn FrontendEngine> {
    match kind {
        FrontendKind::Zir => Box::new(ZirFrontend),
        FrontendKind::Noir => Box::new(NoirAcirFrontend),
        FrontendKind::Circom => Box::new(CircomFrontend),
        FrontendKind::Cairo => Box::new(CairoFrontend),
        FrontendKind::Compact => Box::new(CompactFrontend),
        FrontendKind::Halo2Rust => Box::new(Halo2RustFrontend),
        FrontendKind::Plonky3Air => Box::new(Plonky3AirFrontend),
        FrontendKind::Zkvm => Box::new(ZkvmFrontend),
    }
}

pub fn frontend_capabilities_matrix() -> Vec<FrontendCapabilities> {
    [
        FrontendKind::Zir,
        FrontendKind::Noir,
        FrontendKind::Circom,
        FrontendKind::Cairo,
        FrontendKind::Compact,
        FrontendKind::Halo2Rust,
        FrontendKind::Plonky3Air,
        FrontendKind::Zkvm,
    ]
    .iter()
    .map(|kind| frontend_for(*kind).capabilities())
    .collect()
}
